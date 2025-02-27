use crate::configs::global::OYSTER_MARKET_ADDRESS;
use crate::utils::provider::create_provider;
use alloy::sol;
use anyhow::{Context, Result};
use tracing::info;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    OysterMarket,
    "src/abis/oyster_market_abi.json"
);

pub async fn update_job(
    job_id: &str,
    wallet_private_key: &str,
    image_url: Option<&str>,
    debug: Option<bool>,
) -> Result<()> {
    let provider = create_provider(wallet_private_key)
        .await
        .context("Failed to create provider")?;

    let market = OysterMarket::new(OYSTER_MARKET_ADDRESS.parse()?, provider);

    let mut metadata = serde_json::from_str::<serde_json::Value>(
        &market.jobs(job_id.parse()?).call().await?.metadata,
    )?;
    info!(
        "Original metadata: {}",
        serde_json::to_string_pretty(&metadata)?
    );

    if let Some(debug) = debug {
        metadata["debug"] = serde_json::Value::Bool(debug);
    }

    if let Some(image_url) = image_url {
        metadata["url"] = serde_json::Value::String(image_url.into());
    }

    info!(
        "Updated metadata: {}",
        serde_json::to_string_pretty(&metadata)?
    );

    let tx_hash = market
        .jobMetadataUpdate(job_id.parse()?, serde_json::to_string(&metadata)?)
        .send()
        .await?
        .watch()
        .await?;

    info!("Metadata update transaction: {:?}", tx_hash);

    Ok(())
}
