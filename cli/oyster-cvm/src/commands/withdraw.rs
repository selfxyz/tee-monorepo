use alloy::{
    network::EthereumWallet,
    primitives::{Address, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use crate::configs::global::{
    ARBITRUM_ONE_RPC_URL, OYSTER_MARKET_ADDRESS,
    MIN_WITHDRAW_AMOUNT,
};
use crate::utils::usdc::format_usdc;
use anyhow::{anyhow, Context, Result};
use tracing::info;

// Withdrawal Settings
const BUFFER_MINUTES: u64 = 7; // Required buffer time in minutes
const SCALING_FACTOR: u128 = 1_000_000_000_000; // 1e12 scaling factor for contract values

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

pub async fn withdraw_from_job(
    job_id: &str,
    amount: Option<u64>,
    max: bool,
    wallet_private_key: &str,
) -> Result<()> {
    info!("Starting withdrawal process...");

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

    let job_id_bytes = job_id.parse().context("Failed to parse job ID")?;

    // Check if job exists and get current balance
    let job = market
        .jobs(job_id_bytes)
        .call()
        .await
        .context("Failed to fetch job details")?;
    if job.owner == Address::ZERO {
        return Err(anyhow!("Job {} does not exist", job_id));
    }

    // Check if balance is zero
    if job.balance == U256::ZERO {
        return Err(anyhow!("Cannot withdraw: job balance is 0 USDC"));
    }

    // Try to settle the job first
    info!("Attempting to settle job before withdrawal...");
    let pending_tx = market
        .jobSettle(job_id_bytes)
        .send()
        .await
        .context("Failed to settle job")?;
    let tx_hash = pending_tx
        .watch()
        .await
        .context("Failed to get transaction hash")?;
    info!("Job settlement successful. Transaction hash: {:?}", tx_hash);

    // Fetch updated job details after settlement attempt
    let job = market
        .jobs(job_id_bytes)
        .call()
        .await
        .context("Failed to fetch updated job details")?;

    // Check if balance is zero
    if job.balance == U256::ZERO {
        return Err(anyhow!("Cannot withdraw: job balance is 0 USDC"));
    }

    // Scale down rate by 1e12
    let scaled_rate = job
        .rate
        .checked_div(U256::from(SCALING_FACTOR))
        .ok_or_else(|| anyhow!("Failed to scale rate"))?;

    // Calculate required buffer balance (5 minutes worth of rate)
    let buffer_seconds = U256::from(BUFFER_MINUTES * 60);
    let buffer_balance = scaled_rate
        .checked_mul(buffer_seconds)
        .ok_or_else(|| anyhow!("Failed to calculate buffer balance"))?;

    // Balance is already in USDC 6 decimals format
    let balance = job.balance;

    info!(
        "Current balance: {:.6} USDC, Required buffer: {:.6} USDC",
        format_usdc(balance),
        format_usdc(buffer_balance)
    );

    // Calculate maximum withdrawable amount (in USDC with 6 decimals)
    let max_withdrawable = if balance > buffer_balance {
        balance
            .checked_sub(buffer_balance)
            .ok_or_else(|| anyhow!("Failed to calculate withdrawable amount"))?
    } else {
        return Err(anyhow!(
            "Cannot withdraw: current balance ({:.6} USDC) is less than required buffer ({:.6} USDC)",
            format_usdc(balance),
            format_usdc(buffer_balance)
        ));
    };

    // First check amount if not using max
    if !max {
        let amount =
            amount.ok_or_else(|| anyhow!("Amount must be specified when not using --max"))?;
        if amount < MIN_WITHDRAW_AMOUNT {
            return Err(anyhow!(
                "Amount must be at least {} (0.000001 USDC)",
                MIN_WITHDRAW_AMOUNT
            ));
        }
    }

    // Determine withdrawal amount (in USDC with 6 decimals)
    let amount_u256 = if max {
        info!("Maximum withdrawal requested");
        max_withdrawable
    } else {
        let amount_u256 = U256::from(amount.unwrap()); // Safe to unwrap as we checked above
        if amount_u256 > max_withdrawable {
            return Err(anyhow!(
                "Cannot withdraw {:.6} USDC: maximum withdrawable amount is {:.6} USDC (need to maintain {:.6} USDC buffer)",
                format_usdc(amount_u256),
                format_usdc(max_withdrawable),
                format_usdc(buffer_balance)
            ));
        }
        amount_u256
    };

    info!(
        "Initiating withdrawal of {:.6} USDC",
        format_usdc(amount_u256)
    );

    // Call jobWithdraw function with amount in USDC 6 decimals
    let tx_hash = market
        .jobWithdraw(job_id_bytes, amount_u256)
        .send()
        .await
        .map_err(|e| {
            info!("Transaction failed with error: {:?}", e);
            anyhow!("Failed to send withdraw transaction: {}", e)
        })?
        .watch()
        .await
        .context("Failed to get transaction hash")?;

    info!(
        "Withdrawal transaction sent. Transaction hash: {:?}",
        tx_hash
    );

    // Verify transaction success
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await
        .context("Failed to get transaction receipt")?
        .ok_or_else(|| anyhow!("Transaction receipt not found"))?;

    if !receipt.status() {
        return Err(anyhow!(
            "Withdraw transaction failed - check contract interaction"
        ));
    }

    info!("Withdrawal successful!");
    Ok(())
}
