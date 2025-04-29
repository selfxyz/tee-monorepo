use crate::args::wallet::WalletArgs;
use crate::configs::global::{ARBITRUM_ONE_RPC_URL, RELAY_CONTRACT_ADDRESS, USDC_ADDRESS};
use crate::utils::conversion::{to_eth, to_usdc};
use crate::utils::provider::create_provider;
use crate::utils::usdc::approve_usdc;
use alloy::network::NetworkWallet;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};
use alloy::{hex, sol};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use inquire::Select;
use tokio::fs;
use tracing::{error, info};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Relay,
    "src/abis/Relay.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    USDC,
    "src/abis/Token.json"
);

#[derive(Args)]
pub struct JobArgs {
    #[command(subcommand)]
    command: JobCommands,
}

#[derive(Subcommand)]
pub enum JobCommands {
    /// Create a new job
    Create(CreateJobArgs),
    /// Fetch response for a job
    FetchResponse(FetchResponseArgs),
    /// Cancel a job
    Cancel(CancelArgs),
}

#[derive(Args)]
pub struct CreateJobArgs {
    #[command(flatten)]
    wallet: WalletArgs,

    /// Execution environment (defaults to 1)
    #[arg(long, default_value = "1")]
    env: u8,

    /// Code hash from deployed JS code (transaction hash)
    #[arg(long, required = true)]
    code_hash: String,

    /// Code inputs for the worker
    #[arg(long, required = true)]
    input_file: String,

    /// Maximum time allowed for executors to complete computation
    #[arg(long, required = true)]
    user_timeout: u64,

    /// Max gas price multiplier (e.g: 2, 3, 4)
    #[arg(long, default_value = "2")]
    max_gas_price: u64,

    /// Callback contract address
    #[arg(long, required = true)]
    callback_contract_address: String,

    /// Gas limit for callback function
    #[arg(long, required = true)]
    callback_gas_limit: u64,

    /// Address to receive compensation if job fails (defaults to sender's address)
    #[arg(long)]
    refund_account: Option<String>,
}

#[derive(Args)]
pub struct FetchResponseArgs {
    /// Job ID to fetch the response for
    #[arg(long, required = true)]
    job_transaction_hash: String,
}

#[derive(Args)]
pub struct CancelArgs {
    #[command(flatten)]
    wallet: WalletArgs,

    /// Job ID to cancel (transaction hash of job creation)
    #[arg(long, required = true)]
    job_transaction_hash: String,
}

pub async fn run_job(args: JobArgs) -> Result<()> {
    match args.command {
        JobCommands::Create(create_args) => create_job(create_args).await,
        JobCommands::FetchResponse(fetch_args) => fetch_response(fetch_args).await,
        JobCommands::Cancel(cancel_args) => cancel_job(cancel_args).await,
    }
}

async fn create_job(args: CreateJobArgs) -> Result<()> {
    // Load input file contents
    let code_inputs = fs::read(&args.input_file)
        .await
        .context("Failed to read input file")?;

    // Load wallet private key
    let wallet_private_key = &args.wallet.load_required()?;

    // Create provider with wallet
    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    // Get the signer's address
    let wallet = provider.wallet();
    let signer_address = wallet.default_signer_address();

    // Parse addresses
    let contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;
    let callback_contract: Address = args.callback_contract_address.parse()?;

    // Get refund account - either the provided one or the sender's address
    let refund_account: Address = match args.refund_account {
        Some(addr) => addr.parse()?,
        None => signer_address,
    };

    // Create contract instance
    let contract = Relay::new(contract_address, provider.clone());

    // Parse code hash from hex to bytes32
    let code_hash_str = args.code_hash.strip_prefix("0x").unwrap_or(&args.code_hash);
    let decoded = hex::decode(code_hash_str).context("Failed to decode code hash hex string")?;
    let code_hash: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("Code hash must be exactly 32 bytes"))?;
    let code_hash = FixedBytes::from(code_hash);

    // Convert numeric values to U256
    let user_timeout = U256::from(args.user_timeout);

    // Get current gas price and calculate max gas price
    let current_gas_price = U256::from(
        provider
            .get_gas_price()
            .await
            .context("Failed to get current gas price")?,
    );

    let max_gas_price = current_gas_price * U256::from(args.max_gas_price);

    let callback_gas_limit = U256::from(args.callback_gas_limit);

    // Get execution fee per ms for the environment
    let execution_fee_per_ms = contract
        .getJobExecutionFeePerMs(args.env)
        .call()
        .await
        .context("Failed to get execution fee per ms")?;

    let gateway_fee_per_job = contract
        .GATEWAY_FEE_PER_JOB()
        .call()
        .await
        .context("Failed to get gateway fee per job")?;

    let fixed_gas = contract
        .FIXED_GAS()
        .call()
        .await
        .context("Failed to get fixed gas")?;

    let callback_measure_gas = contract
        .CALLBACK_MEASURE_GAS()
        .call()
        .await
        .context("Failed to get callback measure gas")?;

    let callback_deposit =
        max_gas_price * (callback_gas_limit + fixed_gas._0 + callback_measure_gas._0);

    let wallet_eth_balance = provider
        .get_balance(signer_address)
        .await
        .context("Failed to get wallet balance")?;

    if wallet_eth_balance < callback_deposit {
        error!(
            "Insufficient ETH balance. Required: {} ETH, Available: {} ETH",
            callback_deposit, wallet_eth_balance
        );
        return Ok(());
    }

    let usdc_required = execution_fee_per_ms._0 * user_timeout + gateway_fee_per_job._0;

    let usdc_contract = USDC::new(USDC_ADDRESS.parse()?, &provider);

    let usdc_balace = usdc_contract.balanceOf(signer_address).call().await?._0;

    if usdc_balace < usdc_required {
        error!(
            "Insufficient USDC balance. Required: {} USDC, Available: {} USDC",
            usdc_required, usdc_balace
        );
        return Ok(());
    }

    info!(
        "Required deposits: {} USDC for the job and {} ETH for callback deposit",
        to_usdc(usdc_required)?,
        to_eth(callback_deposit)?
    );

    let options = vec!["Yes", "No"];
    let answer = Select::new("Do you want to continue?", options)
        .prompt()
        .context("Failed to get user confirmation")?;

    if answer == "No" {
        info!("Operation cancelled by user!");
        return Ok(());
    }

    //Approve USDC to the relay contract
    approve_usdc(usdc_required, provider)
        .await
        .context("Failed to approve required USDC")?;

    // Call relayJob with all parameters
    info!("Submitting job to relay contract...");
    let tx = contract
        .relayJob(
            args.env,
            code_hash,
            code_inputs.into(),
            user_timeout,
            max_gas_price,
            refund_account,
            callback_contract,
            callback_gas_limit,
        )
        .value(callback_deposit)
        .send()
        .await?;

    let receipt = tx.get_receipt().await?;

    let data = receipt.inner.logs()[1].log_decode::<Relay::JobRelayed>()?;
    let job_id = data.data().jobId;

    info!("Job ID: {:?}", job_id);

    info!(
        "Job submitted successfully in transaction: {:?}",
        receipt.transaction_hash
    );

    Ok(())
}

async fn fetch_response(args: FetchResponseArgs) -> Result<()> {
    // Create provider with no wallet (read-only)
    let rpc_url = ARBITRUM_ONE_RPC_URL
        .parse()
        .context("Failed to parse RPC URL")?;
    let provider = ProviderBuilder::new().on_http(rpc_url);

    //Fetch tx receipt
    let tx_receipt = provider
        .get_transaction_receipt(args.job_transaction_hash.parse()?)
        .await?
        .context("Failed to fetch transaction receipt")?;

    //Fetch job ID and tx block number from the transaction receipt
    let tx_block_number = tx_receipt
        .block_number
        .context("Transaction receipt does not have a block number")?;

    let data = tx_receipt.inner.logs()[1].log_decode::<Relay::JobRelayed>()?;
    let job_id = data.data().jobId;

    // Create contract instance
    let contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;
    let contract = Relay::new(contract_address, provider.clone());

    info!("Fetching job response for job ID: {:?}", job_id);

    // Get JobResponded events filtered by job ID
    info!("Searching for job response...");

    let log = contract
        .JobResponded_filter()
        .from_block(tx_block_number)
        .topic1(job_id);

    let events = log.query().await?;

    if events.is_empty() {
        error!("No response found for job ID: {:?}", job_id);
        return Ok(());
    }

    let job_output = &events[0].0.output;

    info!("Job response found!");

    let output_path = std::env::current_dir()?.join("output");
    fs::write(&output_path, job_output)
        .await
        .context("Failed to write response to output file")?;

    info!("Response saved to: {}", output_path.display());

    Ok(())
}

async fn cancel_job(args: CancelArgs) -> Result<()> {
    // Create provider with wallet
    let wallet_private_key = &args.wallet.load_required()?;
    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    // Get transaction receipt to extract job ID
    let tx_receipt = provider
        .get_transaction_receipt(args.job_transaction_hash.parse()?)
        .await?
        .context("Failed to fetch transaction receipt")?;

    // Extract job ID from the transaction receipt logs
    let data = tx_receipt.inner.logs()[1].log_decode::<Relay::JobRelayed>()?;
    let job_id = data.data().jobId;

    // Create contract instance
    let contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;
    let contract = Relay::new(contract_address, provider.clone());

    info!("Canceling job with ID: {:?}", job_id);

    // Call cancelJob on the contract
    let tx = contract
        .jobCancel(job_id)
        .send()
        .await
        .context("Failed to send cancel transaction")?;
    let receipt = tx.get_receipt().await?;

    info!(
        "Job canceled successfully in transaction: {:?}",
        receipt.transaction_hash
    );

    Ok(())
}
