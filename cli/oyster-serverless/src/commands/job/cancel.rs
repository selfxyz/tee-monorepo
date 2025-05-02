use crate::commands::job::types::{CancelArgs, Relay};
use crate::configs::global::{RELAY_CONTRACT_ADDRESS, RELAY_OVERALL_TIMEOUT_NOT_OVER_SIGNATURE};
use crate::utils::provider::create_provider;
use alloy::providers::Provider;
use anyhow::{Context, Result};
use tracing::{error, info};

/// Cancels a job
pub async fn cancel_job(args: CancelArgs) -> Result<()> {
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
    let tx = match contract.jobCancel(job_id).send().await {
        Ok(tx) => tx,
        Err(e) => {
            // Check for RelayOverallTimeoutNotOver error signature
            if e.to_string()
                .contains(RELAY_OVERALL_TIMEOUT_NOT_OVER_SIGNATURE)
            {
                error!("Job cancellation is not allowed yet: The overall timeout period has not elapsed.");
                return Ok(());
            }
            error!("Failed to cancel job: {:?}", e);
            return Ok(());
        }
    };

    let receipt = tx.get_receipt().await?;

    info!(
        "Job canceled successfully in transaction: {:?}",
        receipt.transaction_hash
    );

    Ok(())
}
