use crate::configs::global::{RELAY_CONTRACT_ADDRESS, USDC_ADDRESS};
use alloy::{
    network::Ethereum,
    primitives::{Address, U256},
    providers::{Provider, WalletProvider},
    sol,
    transports::http::Http,
};
use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use tracing::info;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    USDC,
    "src/abis/Token.json"
);

/// Approves USDC transfer to the Oyster Market contract if the current allowance is insufficient
pub async fn approve_usdc(
    amount: U256,
    provider: impl Provider<Http<Client>, Ethereum> + WalletProvider,
) -> Result<()> {
    let usdc_address: Address = USDC_ADDRESS
        .parse()
        .context("Failed to parse USDC address")?;
    let relay_contract_address: Address = RELAY_CONTRACT_ADDRESS
        .parse()
        .context("Failed to parse market address")?;
    let signer_address = provider
        .signer_addresses()
        .next()
        .ok_or_else(|| anyhow!("No signer address found"))?;
    let usdc = USDC::new(usdc_address, provider);

    // Get the current allowance
    let current_allowance_result = usdc
        .allowance(signer_address, relay_contract_address)
        .call()
        .await
        .context("Failed to get current USDC allowance")?;

    // Extract numeric allowance value
    let current_allowance: U256 = current_allowance_result._0;

    // Only approve if the current allowance is less than the required amount
    if current_allowance < amount {
        info!(
            "Current allowance {} USDC is less than required amount {} USDC, approving USDC transfer...",
            current_allowance, amount
        );
        let tx_hash = usdc
            .increaseAllowance(relay_contract_address, amount)
            .send()
            .await
            .context("Failed to send USDC approval transaction")?
            .watch()
            .await
            .context("Failed to get USDC approval transaction hash")?;

        info!("USDC approval transaction: {:?}", tx_hash);
    } else {
        info!(
            "Current allowance {} USDC is sufficient for the required amount {} USDC, skipping approval",
            current_allowance, amount
        );
    }
    Ok(())
}
