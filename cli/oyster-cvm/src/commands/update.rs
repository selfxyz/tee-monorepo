use alloy::{
    network::EthereumWallet, primitives::FixedBytes, providers::ProviderBuilder,
    signers::local::PrivateKeySigner, sol,
};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

const ARBITRUM_ONE_RPC_URL: &str = "https://arb1.arbitrum.io/rpc";
const OYSTER_MARKET_ADDRESS: &str = "0x9d95D61eA056721E358BC49fE995caBF3B86A34B"; // Mainnet Contract Address

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
    let private_key = FixedBytes::<32>::from_slice(&hex::decode(wallet_private_key)?);
    let signer = PrivateKeySigner::from_bytes(&private_key)?;
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_http(ARBITRUM_ONE_RPC_URL.parse()?);
    let market = OysterMarket::new(OYSTER_MARKET_ADDRESS.parse()?, provider);

    let mut metadata =
        serde_json::from_str::<Metadata>(&market.jobs(job_id.parse()?).call().await?.metadata)?;

    if let Some(debug) = debug {
        metadata.debug = debug;
    }

    if let Some(image_url) = image_url {
        metadata.url = image_url.into();
    }

    let tx_hash = market
        .jobMetadataUpdate(job_id.parse()?, serde_json::to_string(&metadata)?)
        .send()
        .await?
        .watch()
        .await?;

    info!("Metadata update transaction: {:?}", tx_hash);

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    instance: String,
    region: String,
    memory: u32,
    vcpu: u32,
    url: String,
    name: String,
    debug: bool,
}
