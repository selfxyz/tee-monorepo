mod common_chain_interaction;
mod common_chain_util;
mod config;

use anyhow::Context;
use ethers::prelude::*;
use ethers::providers::Provider;
use log::info;
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::RwLock;

use clap::Parser;

use crate::common_chain_interaction::update_block_data;
use crate::common_chain_util::{pub_key_to_address, BlockData};
use crate::config::ConfigManager;
use common_chain_interaction::CommonChainClient;

type HttpProvider = NonceManagerMiddleware<SignerMiddleware<Provider<Http>, LocalWallet>>;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(
        long,
        value_parser,
        default_value = "./oyster_serverless_gateway_config.json"
    )]
    config_file: String,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    // Load the configuration file
    let args = Cli::parse();
    let config_manager = ConfigManager::new(&args.config_file);
    let config = config_manager.load_config().unwrap();

    let operator_address = pub_key_to_address(config.pub_key.as_bytes())
        .await
        .context("Failed to get address from pub key")
        .unwrap();

    // Connect to provider
    let chain_ws_client = Provider::<Ws>::connect_with_reconnects(config.com_chain_ws_url, 5)
        .await
        .context(
            "Failed to connect to the chain websocket provider. Please check the chain url.",
        )?;
    let chain_http_provider = Provider::<Http>::connect(&config.com_chain_http_url).await;

    info!("Connected to the chain provider.");

    // Start the block data updater
    let recent_blocks: Arc<RwLock<BTreeMap<u64, BlockData>>> =
        Arc::new(RwLock::new(BTreeMap::new()));
    let recent_blocks_clone = Arc::clone(&recent_blocks);
    let chain_http_provider_clone = chain_http_provider.clone();
    tokio::spawn(async move {
        update_block_data(chain_http_provider_clone, &recent_blocks_clone).await;
    });

    // Start contract event listner
    let contract_client = Arc::new(
        CommonChainClient::new(
            operator_address,
            config.key,
            chain_ws_client,
            chain_http_provider,
            &config.gateway_contract_addr,
            &config.com_chain_contract_addr,
            config.start_block,
            &recent_blocks,
            config.com_chain_id,
        )
        .await,
    );

    // Listen for new jobs and handles them.
    info!("Starting the contract event listener.");
    contract_client.run().await?;

    Ok(())
}
