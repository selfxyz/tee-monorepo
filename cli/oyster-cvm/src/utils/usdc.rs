use crate::configs::global::{OYSTER_MARKET_ADDRESS, USDC_ADDRESS};
use alloy::{
    network::Ethereum,
    primitives::{Address, U256},
    providers::Provider,
    sol,
    transports::http::Http,
};
use anyhow::{Context, Result};
use reqwest::Client;
use tracing::info;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    USDC,
    "src/abis/token_abi.json"
);

/// Approves USDC transfer to the Oyster Market contract
pub async fn approve_usdc(
    amount: U256,
    provider: impl Provider<Http<Client>, Ethereum>,
) -> Result<()> {
    let usdc_address: Address = USDC_ADDRESS
        .parse()
        .context("Failed to parse USDC address")?;
    let market_address: Address = OYSTER_MARKET_ADDRESS
        .parse()
        .context("Failed to parse market address")?;

    let usdc = USDC::new(usdc_address, provider);
    let tx_hash = usdc
        .approve(market_address, amount)
        .send()
        .await
        .context("Failed to send USDC approval transaction")?
        .watch()
        .await
        .context("Failed to get USDC approval transaction hash")?;

    info!("USDC approval transaction: {:?}", tx_hash);
    Ok(())
}

/// Formats a U256 value as USDC with 6 decimal places
pub fn format_usdc(value: U256) -> f64 {
    value.to::<u128>() as f64 / 1e6
}
