use crate::commands::subscription::types::{FetchResponseArgs, RelaySubscriptions};
use crate::configs::global::ARBITRUM_ONE_RPC_URL;
use crate::configs::global::RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS;
use alloy::primitives::U256;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result};
use tokio::fs;
use tracing::info;

/// Fetches responses for a subscription
pub async fn fetch_response(args: FetchResponseArgs) -> Result<()> {
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

    // Save existing responses
    let mut last_processed_block = tx_block_number;

    let mut outputs_found = 0;

    // Poll for new events
    loop {
        let latest_block = provider.get_block_number().await?;

        // Don't query if no new blocks
        if latest_block <= last_processed_block {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        let events = contract
            .JobSubscriptionResponded_filter()
            .from_block(last_processed_block + 1)
            .to_block(latest_block)
            .topic1(subscription_id)
            .query()
            .await?;

        for event in events {
            outputs_found += 1;
            let current_run = event.0.currentRuns;
            let output = event.0.output;
            info!("Received response for run {}", current_run);
            let file_name = format!("output_{}", current_run);
            let output_path = std::env::current_dir()?.join(file_name);
            fs::write(&output_path, output)
                .await
                .context("Failed to write response to output file")?;

            info!("Response saved to: {}", output_path.display());
            // Check if this is the final run
            if U256::from(outputs_found) == total_runs {
                info!("Received final run response. Subscription is complete.");
                return Ok(());
            }
        }

        last_processed_block = latest_block;

        // Sleep for a shorter duration since we're tracking blocks explicitly
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
