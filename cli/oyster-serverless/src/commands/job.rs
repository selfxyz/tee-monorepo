use crate::args::wallet::WalletArgs;
use crate::configs::global::RELAY_CONTRACT_ADDRESS;
use crate::utils::conversion::{to_eth, to_usdc_units, to_wei};
use crate::utils::provider::create_provider;
use crate::utils::usdc::approve_usdc;
use alloy::network::NetworkWallet;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{Provider, WalletProvider};
use alloy::sol;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use tokio::fs;
use tracing::info;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Relay,
    "src/abis/Relay.json"
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

    /// Max gas price multiplier (e.g: 1.5, 2)
    #[arg(long, default_value = "2")]
    max_gas_price: u64,

    /// USDC amount to deposit
    #[arg(long, required = true)]
    usdc_for_job: f64,

    /// Callback contract address
    #[arg(long, required = true)]
    callback_contract_address: String,

    /// Gas limit for callback function
    #[arg(long, required = true)]
    callback_gas_limit: u64,

    /// Callback deposit amount
    #[arg(long, required = true)]
    callback_deposit: f64,

    /// Address to receive compensation if job fails (defaults to sender's address)
    #[arg(long)]
    refund_account: Option<String>,
}

pub async fn run_job(args: JobArgs) -> Result<()> {
    match args.command {
        JobCommands::Create(create_args) => create_job(create_args).await,
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
    let callback_deposit = to_wei(args.callback_deposit);
    let usdc_amount = to_usdc_units(args.usdc_for_job);

    //Approve USDC to the relay contract
    approve_usdc(usdc_amount, provider.clone())
        .await
        .context("Failed to approve required USDC")?;

    info!(
        "{} ETH provided for callback deposit",
        to_eth(callback_deposit)
    );

    info!("Preparing to call relayJob with parameters:");
    info!("1. env (uint8): {}", args.env);
    info!("2. code_hash (bytes32): {:?}", code_hash);
    info!("4. user_timeout (uint256): {}", user_timeout);
    info!("5. max_gas_price (uint256): {}", max_gas_price);
    info!("6. refund_account (address): {}", refund_account);
    info!("7. callback_contract (address): {}", callback_contract);
    info!("8. callback_gas_limit (uint256): {}", callback_gas_limit);
    info!("9. callback_deposit (value in wei): {}", callback_deposit);

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

    info!(
        "Job submitted successfully in transaction: {:?}",
        receipt.transaction_hash
    );

    info!("Job ID: {:?}", job_id);

    Ok(())
}
