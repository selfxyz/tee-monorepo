mod api_impl;
mod common_chain_interaction;
mod common_chain_util;
mod config;
mod constant;
mod model;

use actix_web::web::Data;
use actix_web::{App, HttpServer};
use anyhow::Context;
use clap::Parser;
use ethers::prelude::*;
use ethers::providers::Provider;
use k256::ecdsa::SigningKey;
use log::info;
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;

use crate::api_impl::{deregister_enclave, index, inject_key, register_enclave};
use crate::common_chain_interaction::update_block_data;
use crate::common_chain_util::BlockData;
use crate::config::ConfigManager;
use crate::model::AppState;

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
    #[clap(long, value_parser, default_value = "6001")]
    port: u16,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    // Load the configuration file
    let args = Cli::parse();
    let config_manager = ConfigManager::new(&args.config_file);
    let config = config_manager.load_config().unwrap();

    // let operator_address = pub_key_to_address(config.pub_key.as_bytes())
    //     .await
    //     .context("Failed to get address from pub key")
    //     .unwrap();

    // Connect to provider
    // let chain_ws_client = Provider::<Ws>::connect_with_reconnects(config.com_chain_ws_url, 5)
    //     .await
    //     .context(
    //         "Failed to connect to the chain websocket provider. Please check the chain url.",
    //     )?;
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

    let enclave_pub_key = fs::read(config.enclave_public_key)
        .await
        .context("Failed to read the enclave signer key")?;

    let enclave_signer_key = SigningKey::from_slice(
        fs::read(config.enclave_secret_key)
            .await
            .context("Failed to read the enclave signer key")?
            .as_slice(),
    )
    .context("Invalid enclave signer key")?;

    // Create a Appstate
    let app_data = Data::new(AppState {
        enclave_signer_key: enclave_signer_key,
        wallet: None.into(),
        common_chain_id: config.com_chain_id,
        common_chain_http_url: config.com_chain_http_url,
        common_chain_ws_url: config.com_chain_ws_url,
        gateway_contract_addr: config.gateway_contract_addr,
        job_contract_addr: config.job_contract_addr,
        chain_list: vec![].into(),
        registered: false.into(),
        enclave_pub_key: enclave_pub_key.into(),
        recent_blocks: recent_blocks.clone(),
        start_block: config.start_block,
    });
    // Start a http server
    let server = HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .service(index)
            .service(inject_key)
            .service(register_enclave)
            .service(deregister_enclave)
    })
    .bind(("0.0.0.0", args.port))
    .context(format!("could not bind to port {}", args.port))?
    .run();

    println!("Node server started on port {}", args.port);

    server.await?;

    // // Start contract event listner
    // let contract_client = Arc::new(
    //     CommonChainClient::new(
    //         operator_address,
    //         config.key,
    //         chain_ws_client,
    //         chain_http_provider,
    //         &config.gateway_contract_addr,
    //         &config.com_chain_contract_addr,
    //         config.start_block,
    //         &recent_blocks,
    //         config.com_chain_id,
    //     )
    //     .await,
    // );

    // // Listen for new jobs and handles them.
    // info!("Starting the contract event listener.");
    // contract_client.run().await?;

    Ok(())
}
