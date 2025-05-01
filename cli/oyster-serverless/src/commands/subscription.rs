use crate::args::wallet::WalletArgs;
use crate::configs::global::{
    ARBITRUM_ONE_RPC_URL, RELAY_CONTRACT_ADDRESS, RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS,
    USDC_ADDRESS,
};
use crate::utils::conversion::{to_eth, to_usdc};
use crate::utils::provider::create_provider;
use crate::utils::usdc::approve_usdc;
use alloy::network::NetworkWallet;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder, WalletProvider};
use alloy::{hex, sol};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use inquire::{Select, Text};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tracing::{error, info};
use RelaySubscriptions::JobSubscriptionParams;

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
    /// Fetch response for a subscription
    FetchResponse(FetchResponseArgs),
}

#[derive(Args)]
pub struct CreateSubscriptionArgs {
    #[command(flatten)]
    wallet: WalletArgs,

    /// Execution environment (defaults to 1)
    #[arg(long, default_value = "1")]
    env: u8,

    /// Start timestamp for the subscription (epoch time in seconds)
    #[arg(long)]
    start_timestamp: Option<u64>,

    /// Termination timestamp for the subscription (epoch time in seconds)
    #[arg(long)]
    termination_timestamp: Option<u64>,

    /// How often to run the serverless code (in seconds)
    #[arg(long)]
    periodic_gap: Option<u64>,

    /// Maximum time allowed for executors to complete computation (in milliseconds)
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

#[derive(Args)]
pub struct FetchResponseArgs {
    /// Subscription ID to fetch the response for
    #[arg(long, required = true)]
    subscription_transaction_hash: String,
}

pub async fn run_subscription(args: SubscriptionArgs) -> Result<()> {
    match args.command {
        SubscriptionCommands::Create(create_args) => create_subscription(create_args).await,
        SubscriptionCommands::FetchResponse(fetch_args) => fetch_response(fetch_args).await,
    }
}

async fn create_subscription(args: CreateSubscriptionArgs) -> Result<()> {
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

    // Parse code hash from hex to bytes32
    let code_hash_str = args.code_hash.strip_prefix("0x").unwrap_or(&args.code_hash);
    let decoded = hex::decode(code_hash_str).context("Failed to decode code hash hex string")?;
    let code_hash: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("Code hash must be exactly 32 bytes"))?;
    let code_hash = FixedBytes::from(code_hash);

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

    // Get interactive input for start_timestamp if not provided
    let start_timestamp = get_start_timestamp(args.start_timestamp).await?;

    // Get interactive input for termination_timestamp if not provided
    let termination_timestamp =
        get_termination_timestamp(start_timestamp, args.termination_timestamp).await?;

    // Get interactive input for periodic_gap if not provided
    let periodic_gap = get_periodic_gap(args.periodic_gap).await?;

    let user_timeout = U256::from(args.user_timeout);

    // Calculate total runs based on provided or interactively gathered parameters
    let total_runs = ((termination_timestamp - start_timestamp) / periodic_gap) + U256::from(1);

    info!("Subscription start time: {}", start_timestamp);
    info!("Subscription end time: {}", termination_timestamp);
    info!("Subscription interval: {} seconds", periodic_gap);
    info!("Total subscription runs: {}", total_runs - U256::from(1));

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
        ((user_timeout * execution_fee_per_ms._0) + gateway_fee_per_job._0) * total_runs;

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
        "The required deposits are {} USDC for the subscription and {} ETH for the callback deposit. Would you like to continue?",
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

    //Approve USDC to the relay contract
    approve_usdc(usdc_required, provider, relay_subscription_contract_address)
        .await
        .context("Failed to approve required USDC")?;

    info!("Submitting subscription to relay subscription contract...");

    let job_subs_params = {
        JobSubscriptionParams {
            env: args.env,
            startTime: start_timestamp,
            maxGasPrice: max_gas_price,
            usdcDeposit: usdc_required,
            callbackGasLimit: callback_gas_limit,
            callbackContract: callback_contract,
            codehash: code_hash,
            codeInputs: code_inputs.into(),
            periodicGap: periodic_gap,
            terminationTimestamp: termination_timestamp,
            userTimeout: user_timeout,
            refundAccount: refund_account,
        }
    };

    let tx = relay_subscription_contract
        .startJobSubscription(job_subs_params)
        .value(callback_deposit)
        .send()
        .await?;

    let receipt = tx.get_receipt().await?;

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
        .get_transaction_receipt(args.subscription_transaction_hash.parse()?)
        .await?
        .context("Failed to fetch transaction receipt")?;

    //Fetch subscription ID and tx block number from the transaction receipt
    let tx_block_number = tx_receipt
        .block_number
        .context("Transaction receipt does not have a block number")?;

    let data =
        tx_receipt.inner.logs()[0].log_decode::<RelaySubscriptions::JobSubscriptionStarted>()?;
    let subscription_id = data.data().jobSubsId;
    let start_time = data.data().startTime;
    let periodic_gap = data.data().periodicGap;
    let termination_timestamp = data.data().terminationTimestamp;
    let total_runs = ((termination_timestamp - start_time) / periodic_gap) + U256::from(1);
    info!("Total Runs: {}", total_runs);

    info!(
        "Fetching subscription response for subscription ID: {:?}",
        subscription_id
    );

    // Create contract instance
    let contract_address = RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay subscriptions contract address")?;
    let contract = RelaySubscriptions::new(contract_address, provider.clone());

    // Get JobSubscriptionResponded events filtered by subscription ID
    info!("Searching for subscription response...");

    let log = contract
        .JobSubscriptionResponded_filter()
        .from_block(tx_block_number)
        .topic1(subscription_id);

    let events = log.query().await?;

    if events.is_empty() {
        error!(
            "No response found for subscription ID: {:?}",
            subscription_id
        );
        return Ok(());
    }

    info!(
        "Found {} responses out of {} total runs",
        events.len(),
        total_runs
    );

    // Handle completed subscriptions
    if events.len() as u128 == total_runs.to_string().parse::<u128>().unwrap() {
        info!("Subscription is complete. Saving all responses...");
        for event in events {
            let current_run = event.0.currentRuns;
            let output = event.0.output;
            info!("Saving response for run {}", current_run);
            let file_name = format!("output_{}", current_run);
            let output_path = std::env::current_dir()?.join(file_name);
            fs::write(&output_path, output)
                .await
                .context("Failed to write response to output file")?;

            info!("Response saved to: {}", output_path.display());
        }
    } else {
        // Handle in-progress subscriptions
        info!("Subscription is still in progress. Saving existing responses and watching for new ones...");

        // Save existing responses
        let mut seen_runs = std::collections::HashSet::new();
        let mut last_processed_block = tx_block_number;

        for event in events {
            let current_run = event.0.currentRuns;
            seen_runs.insert(current_run.to_string());
            let output = event.0.output;
            info!("Saving response for run {}", current_run);
            let file_name = format!("output_{}", current_run);
            let output_path = std::env::current_dir()?.join(file_name);
            fs::write(&output_path, output)
                .await
                .context("Failed to write response to output file")?;

            info!("Response saved to: {}", output_path.display());
        }

        // Poll for new events
        info!("Watching for new responses (Press Ctrl+C to stop)...");
        loop {
            let latest_block = provider.get_block_number().await?;

            // Don't query if no new blocks
            if latest_block <= last_processed_block {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            info!("From block: {}", last_processed_block + 1);
            info!("To block: {}", latest_block);
            let new_events = contract
                .JobSubscriptionResponded_filter()
                .from_block(last_processed_block + 1)
                .to_block(latest_block)
                .topic1(subscription_id)
                .query()
                .await?;

            for event in new_events {
                let current_run = event.0.currentRuns;

                // Skip if we've already seen this run
                if seen_runs.contains(&current_run.to_string()) {
                    continue;
                }

                seen_runs.insert(current_run.to_string());
                let output = event.0.output;
                info!("Received new response for run {}", current_run);
                let file_name = format!("output_{}", current_run);
                let output_path = std::env::current_dir()?.join(file_name);
                fs::write(&output_path, output)
                    .await
                    .context("Failed to write response to output file")?;

                info!("Response saved to: {}", output_path.display());

                // Check if this is the final run
                if current_run == total_runs - U256::from(1) {
                    info!("Received final run response. Subscription is complete.");
                    return Ok(());
                }
            }

            last_processed_block = latest_block;

            // Sleep for a shorter duration since we're tracking blocks explicitly
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }

    Ok(())
}

/// Get current Unix timestamp in seconds
fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

/// Get start timestamp from user input if not provided
async fn get_start_timestamp(provided_timestamp: Option<u64>) -> Result<U256> {
    if let Some(timestamp) = provided_timestamp {
        return Ok(U256::from(timestamp));
    }

    let options = vec!["Start subscription now", "Start with some delay"];
    let answer = Select::new("When should the subscription start?", options)
        .prompt()
        .context("Failed to get start time preference")?;

    let current_time = get_current_timestamp();

    match answer {
        "Start subscription now" => Ok(U256::from(current_time)),
        "Start with some delay" => {
            let delay_input = Text::new("Enter delay in seconds:")
                .prompt()
                .context("Failed to get delay input")?;

            let delay = delay_input
                .parse::<u64>()
                .context("Invalid delay format. Please enter a number.")?;

            Ok(U256::from(current_time + delay))
        }
        _ => Ok(U256::from(current_time)), // Default fallback
    }
}

/// Get termination timestamp from user input if not provided
async fn get_termination_timestamp(
    start_timestamp: U256,
    provided_timestamp: Option<u64>,
) -> Result<U256> {
    if let Some(timestamp) = provided_timestamp {
        return Ok(U256::from(timestamp));
    }

    let options = vec!["Predefined duration", "Custom termination timestamp"];
    let answer = Select::new("Select termination option:", options)
        .prompt()
        .context("Failed to get termination option")?;

    match answer {
        "Predefined duration" => {
            let durations = vec!["10 minutes", "1 hour", "6 hours", "1 day", "7 days"];

            let selected_duration = Select::new("Select duration:", durations)
                .prompt()
                .context("Failed to get predefined duration")?;

            let duration_seconds = match selected_duration {
                "10 minutes" => 10 * 60,
                "1 hour" => 60 * 60,
                "6 hours" => 6 * 60 * 60,
                "1 day" => 24 * 60 * 60,
                "7 days" => 7 * 24 * 60 * 60,
                _ => 60 * 60, // Default to 1 hour
            };

            Ok(start_timestamp + U256::from(duration_seconds))
        }
        "Custom termination timestamp" => {
            let timestamp_input =
                Text::new("Enter termination timestamp (in seconds since epoch):")
                    .prompt()
                    .context("Failed to get custom timestamp")?;

            let timestamp = timestamp_input
                .parse::<u64>()
                .context("Invalid timestamp format. Please enter a number.")?;

            let current_time = get_current_timestamp();
            if timestamp <= current_time {
                return Err(anyhow::anyhow!(
                    "Termination timestamp must be in the future"
                ));
            }

            Ok(U256::from(timestamp))
        }
        _ => Ok(start_timestamp + U256::from(60 * 60)), // Default to 1 hour
    }
}

/// Get periodic gap from user input if not provided
async fn get_periodic_gap(provided_gap: Option<u64>) -> Result<U256> {
    if let Some(gap) = provided_gap {
        return Ok(U256::from(gap));
    }

    let options = vec!["Predefined interval", "Custom periodic gap (sec)"];
    let answer = Select::new("Select periodic gap option:", options)
        .prompt()
        .context("Failed to get periodic gap option")?;

    match answer {
        "Predefined interval" => {
            let intervals = vec![
                "30 seconds",
                "60 seconds",
                "10 minutes",
                "1 hour",
                "3 hours",
            ];

            let selected_interval = Select::new("Select interval:", intervals)
                .prompt()
                .context("Failed to get predefined interval")?;

            let interval_seconds = match selected_interval {
                "30 seconds" => 30,
                "60 seconds" => 60,
                "10 minutes" => 10 * 60,
                "1 hour" => 60 * 60,
                "3 hours" => 3 * 60 * 60,
                _ => 60, // Default to 60 seconds
            };

            Ok(U256::from(interval_seconds))
        }
        "Custom periodic gap (sec)" => {
            let gap_input = Text::new("Enter periodic gap in seconds:")
                .prompt()
                .context("Failed to get custom gap")?;

            let gap = gap_input
                .parse::<u64>()
                .context("Invalid gap format. Please enter a number.")?;

            if gap == 0 {
                return Err(anyhow::anyhow!("Periodic gap must be greater than zero"));
            }

            Ok(U256::from(gap))
        }
        _ => Ok(U256::from(60)), // Default to 60 seconds
    }
}
