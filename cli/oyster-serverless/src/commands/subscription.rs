use crate::args::wallet::WalletArgs;
use crate::configs::global::{
    ARBITRUM_ONE_RPC_URL, RELAY_CONTRACT_ADDRESS, RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS,
    USDC_ADDRESS,
};
use crate::utils::conversion::{to_eth, to_usdc};
use crate::utils::provider::create_provider;
use crate::utils::usdc::approve_usdc;
use alloy::network::NetworkWallet;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};
use alloy::sol;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use inquire::Select;
use tracing::{error, info};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    RelaySubscriptions,
    "src/abis/RelaySubscriptions.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    USDC,
    "src/abis/Token.json"
);

#[derive(Args)]
pub struct SubscriptionArgs {
    #[command(subcommand)]
    command: SubscriptionCommands,
}

#[derive(Subcommand)]
pub enum SubscriptionCommands {
    /// Create a new subscription
    Create(CreateSubscriptionArgs),
}

#[derive(Args)]
pub struct CreateSubscriptionArgs {
    #[command(flatten)]
    wallet: WalletArgs,

    /// Execution environment (defaults to 1)
    #[arg(long, default_value = "1")]
    env: u8,

    /// Start timestamp for the subscription
    #[arg(long, required = true)]
    start_timestamp: u64,

    /// Termination timestamp for the subscription
    #[arg(long, required = true)]
    termination_timestamp: u64,

    /// How often to run the serverless code
    #[arg(long, required = true)]
    periodic_gap: u64,

    /// Maximum time allowed for executors to complete computation
    #[arg(long, required = true)]
    user_timeout: u64,

    /// Max gas price multiplier (e.g: 1.5, 2, 2.5)
    #[arg(long, default_value = "1.5")]
    max_gas_price: f64,

    /// Callback contract address
    #[arg(long, required = true)]
    callback_contract_address: String,

    /// Gas limit for callback function
    #[arg(long, required = true)]
    callback_gas_limit: u64,

    /// Address to receive compensation if subscription fails (defaults to sender's address)
    #[arg(long)]
    refund_account: Option<String>,

    /// Code hash from deployed JS code (transaction hash)
    #[arg(long, required = true)]
    code_hash: String,

    /// Code inputs for the worker
    #[arg(long, required = true)]
    input_file: String,
}

pub async fn run_subscription(args: SubscriptionArgs) -> Result<()> {
    match args.command {
        SubscriptionCommands::Create(create_args) => create_subscription(create_args).await,
    }
}

async fn create_subscription(args: CreateSubscriptionArgs) -> Result<()> {
    // Load wallet private key
    let wallet_private_key = &args.wallet.load_required()?;

    // Create provider with wallet
    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    // Get the signer's address
    let wallet = provider.wallet();
    let signer_address = wallet.default_signer_address();

    let callback_contract: Address = args.callback_contract_address.parse()?;

    // Parse addresses
    let relay_subscription_contract_address = RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay subscriptions contract address")?;

    // Parse addresses
    let relay_contract_address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay contract address")?;

    // Get refund account - either the provided one or the sender's address
    let refund_account: Address = match args.refund_account {
        Some(addr) => addr.parse()?,
        None => signer_address,
    };

    // Create contract instances
    let relay_subscription_contract =
        RelaySubscriptions::new(relay_subscription_contract_address, provider.clone());
    let relay_contract = super::job::Relay::new(relay_contract_address, provider.clone());

    // Get current gas price and calculate max gas price
    let current_gas_price = U256::from(
        provider
            .get_gas_price()
            .await
            .context("Failed to get current gas price")?,
    );

    let max_gas_price = U256::from(
        (current_gas_price.to_string().parse::<f64>().unwrap() * args.max_gas_price).round() as u64,
    );

    let callback_gas_limit = U256::from(args.callback_gas_limit);

    // Get execution fee per ms for the environment
    let execution_fee_per_ms = relay_contract
        .getJobExecutionFeePerMs(args.env)
        .call()
        .await
        .context("Failed to get execution fee per ms")?;

    let gateway_fee_per_job = relay_contract
        .GATEWAY_FEE_PER_JOB()
        .call()
        .await
        .context("Failed to get gateway fee per job")?;

    // Get fixed gas values from the contract
    let fixed_gas = relay_contract
        .FIXED_GAS()
        .call()
        .await
        .context("Failed to get fixed gas")?;

    let callback_measure_gas = relay_contract
        .CALLBACK_MEASURE_GAS()
        .call()
        .await
        .context("Failed to get callback measure gas")?;

    let termination_timestamp = U256::from(args.termination_timestamp);
    let start_timestamp = U256::from(args.start_timestamp);
    let periodic_gap = U256::from(args.periodic_gap);
    let user_timeout = U256::from(args.user_timeout);

    //Total runs
    let total_runs = ((termination_timestamp - start_timestamp) / periodic_gap) + U256::from(1);

    // Calculate the callback deposit amount
    let callback_deposit =
        max_gas_price * (callback_gas_limit + fixed_gas._0 + callback_measure_gas._0) * total_runs;

    // Check ETH balance
    let wallet_eth_balance = provider
        .get_balance(signer_address)
        .await
        .context("Failed to get wallet balance")?;

    if wallet_eth_balance < callback_deposit {
        error!(
            "Insufficient ETH balance. Required: {} ETH, Available: {} ETH",
            to_eth(callback_deposit)?,
            to_eth(wallet_eth_balance)?
        );
        return Ok(());
    }

    // Check USDC balance
    let usdc_contract = USDC::new(USDC_ADDRESS.parse()?, &provider);
    let usdc_balance = usdc_contract.balanceOf(signer_address).call().await?._0;

    let usdc_required =
        (execution_fee_per_ms._0 * user_timeout + gateway_fee_per_job._0) * total_runs;

    if usdc_balance < usdc_required {
        error!(
            "Insufficient USDC balance. Required: {} USDC, Available: {} USDC",
            to_usdc(usdc_required)?,
            to_usdc(usdc_balance)?
        );
        return Ok(());
    }

    // Prompt user for confirmation
    let prompt_message = format!(
        "The required deposits are {} USDC for the job and {} ETH for the callback deposit. Would you like to continue?",
        to_usdc(usdc_required)?,
        to_eth(callback_deposit)?
    );

    let options = vec!["Yes", "No"];

    let answer = Select::new(&prompt_message, options)
        .prompt()
        .context("Failed to get user confirmation")?;

    if answer == "No" {
        info!("Operation cancelled by user!");
        return Ok(());
    }

    // // Approve USDC to the relay subscriptions contract
    // approve_usdc(max_payment, provider.clone())
    //     .await
    //     .context("Failed to approve required USDC")?;

    // // Call createSubscription with all parameters
    // info!("Creating subscription in relay subscriptions contract...");
    // let tx = contract
    //     .createSubscription(
    //         args.env,
    //         max_payment,
    //         duration,
    //         max_gas_price,
    //         refund_account,
    //         callback_contract,
    //         callback_gas_limit,
    //     )
    //     .value(callback_deposit)
    //     .send()
    //     .await?;

    // let receipt = tx.get_receipt().await?;

    // info!(
    //     "Subscription created successfully in transaction: {:?}",
    //     receipt.transaction_hash
    // );

    Ok(())
}
