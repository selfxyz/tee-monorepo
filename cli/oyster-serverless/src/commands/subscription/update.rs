use crate::commands::subscription::types::{RelaySubscriptions, UpdateSubscriptionArgs};
use crate::configs::global::{ARBITRUM_ONE_RPC_URL, RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS};
use alloy::primitives::U256;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result};

/// Update an existing subscription
pub async fn update_subscription(args: UpdateSubscriptionArgs) -> Result<()> {
    let termination_timestamp = U256::from(args.termination_timestamp);
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

    // Create contract instances
    let realy_subscription_contract_address = RELAY_SUBSCRIPTIONS_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse relay subscriptions contract address")?;
    let realy_subscription_contract =
        RelaySubscriptions::new(realy_subscription_contract_address, provider.clone());


    Ok(())
}
