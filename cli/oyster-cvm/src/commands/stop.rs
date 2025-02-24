use alloy::{
    network::EthereumWallet,
    primitives::{keccak256, Address, FixedBytes, B256},
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::local::PrivateKeySigner,
    sol,
};
use crate::configs::global::{ARBITRUM_ONE_RPC_URL, OYSTER_MARKET_ADDRESS};
use anyhow::{anyhow, Context, Result};
use tracing::info;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

pub async fn stop_oyster_instance(job_id: &str, wallet_private_key: &str) -> Result<()> {
    info!("Stopping oyster instance with:");
    info!("  Job ID: {}", job_id);

    // Setup wallet and provider with signer
    let private_key = FixedBytes::<32>::from_slice(&hex::decode(wallet_private_key)?);
    let signer = PrivateKeySigner::from_bytes(&private_key)?;
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(
            ARBITRUM_ONE_RPC_URL
                .parse()
                .context("Failed to parse RPC URL")?,
        );
    info!("Signer address: {:?}", provider.signer_addresses().next().ok_or_else(|| anyhow!("No signer address found"))?);

    // Create contract instance
    let market_address = OYSTER_MARKET_ADDRESS
        .parse()
        .context("Failed to parse market address")?;
    let market = OysterMarket::new(market_address, provider);

    // Parse job ID once
    let job_id_bytes = job_id.parse::<B256>().context("Failed to parse job ID")?;

    // Check if job exists
    let job = market
        .jobs(job_id_bytes)
        .call()
        .await
        .context("Failed to fetch job details")?;
    if job.owner == Address::ZERO {
        return Err(anyhow!("Job {} does not exist", job_id));
    }

    info!("Found job, initiating stop...");

    // Call jobClose function
    let tx_hash = market
        .jobClose(job_id_bytes)
        .send()
        .await
        .context("Failed to send stop transaction")?
        .watch()
        .await
        .context("Failed to get transaction hash")?;

    info!("Stop transaction sent: {:?}", tx_hash);

    // Verify transaction success
    let receipt = market
        .provider()
        .get_transaction_receipt(tx_hash)
        .await
        .context("Failed to get transaction receipt")?
        .ok_or_else(|| anyhow!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(anyhow!(
            "Stop transaction failed - check contract interaction"
        ));
    }

    // Calculate event signature hash
    let job_closed_signature = "JobClosed(bytes32)";
    let job_closed_topic = keccak256(job_closed_signature.as_bytes());

    // Look for JobClosed event
    for log in receipt.inner.logs().iter() {
        if log.topics()[0] == job_closed_topic {
            info!("Instance stopped successfully!");
            return Ok(());
        }
    }

    Err(anyhow!("JobClosed event not found in transaction receipt"))
}
