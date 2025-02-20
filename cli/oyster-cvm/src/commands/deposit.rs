use alloy::{
    network::EthereumWallet,
    primitives::{Address, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use crate::configs::global::{
    ARBITRUM_ONE_RPC_URL, OYSTER_MARKET_ADDRESS, MIN_DEPOSIT_AMOUNT
};
use crate::utils::usdc::{approve_usdc, format_usdc};
use anyhow::{anyhow, Context, Result};
use tracing::info;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

pub async fn deposit_to_job(job_id: &str, amount: u64, wallet_private_key: &str) -> Result<()> {
    info!("Starting deposit...");

    // Input validation
    if amount < MIN_DEPOSIT_AMOUNT {
        return Err(anyhow!(
            "Amount must be at least {} (0.000001 USDC)",
            MIN_DEPOSIT_AMOUNT
        ));
    }

    // Convert amount to U256 with 6 decimals (USDC has 6 decimals)
    let amount_u256 = U256::from(amount);

    // Setup wallet and provider with signer
    let private_key = FixedBytes::<32>::from_slice(
        &hex::decode(wallet_private_key).context("Failed to decode private key")?,
    );
    let signer = PrivateKeySigner::from_bytes(&private_key)
        .context("Failed to create signer from private key")?;
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(
            ARBITRUM_ONE_RPC_URL
                .parse()
                .context("Failed to parse RPC URL")?,
        );

    // Create contract instance
    let market = OysterMarket::new(
        OYSTER_MARKET_ADDRESS
            .parse()
            .context("Failed to parse market address")?,
        provider.clone(),
    );

    // Check if job exists and get current balance
    let job = market
        .jobs(job_id.parse().context("Failed to parse job ID")?)
        .call()
        .await
        .context("Failed to fetch job details")?;
    if job.owner == Address::ZERO {
        return Err(anyhow!("Job {} does not exist", job_id));
    }
    info!(
        "Depositing: {:.6} USDC",
        format_usdc(amount_u256)
    );

    // First approve USDC transfer
    approve_usdc(amount_u256, provider.clone()).await?;

    // Call jobDeposit function
    let tx_hash = market
        .jobDeposit(
            job_id.parse().context("Failed to parse job ID")?,
            amount_u256,
        )
        .send()
        .await
        .context("Failed to send deposit transaction")?
        .watch()
        .await
        .context("Failed to get transaction hash")?;

    info!("Deposit transaction hash: {:?}", tx_hash);

    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await
        .context("Failed to get transaction receipt")?
        .ok_or_else(|| anyhow!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(anyhow!(
            "Deposit transaction failed - check contract interaction"
        ));
    }

    info!("Deposit successful!");

    Ok(())
}
