mod api_impl;
mod common_chain_gateway_state;
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
use crate::common_chain_gateway_state::{gateway_epoch_state_service, GatewayData};
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

    // Start the gateway epoch state service
    let gateway_epoch_state: &Arc<RwLock<BTreeMap<u64, BTreeMap<Bytes, GatewayData>>>> =
        &Arc::new(RwLock::new(BTreeMap::new()));
    let gateway_epoch_state_clone = Arc::clone(&gateway_epoch_state);
    let chain_http_provider_clone = chain_http_provider.clone();
    tokio::spawn(async move {
        gateway_epoch_state_service(
            config.gateway_contract_addr,
            &chain_http_provider_clone,
            &gateway_epoch_state_clone,
            config.epoch,
            config.time_interval,
        )
        .await;
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
        enclave_signer_key,
        wallet: None.into(),
        common_chain_id: config.com_chain_id,
        common_chain_http_url: config.com_chain_http_url,
        common_chain_ws_url: config.com_chain_ws_url,
        gateway_contract_addr: config.gateway_contract_addr,
        job_contract_addr: config.job_contract_addr,
        chain_list: vec![].into(),
        registered: false.into(),
        enclave_pub_key: enclave_pub_key.into(),
        gateway_epoch_state: gateway_epoch_state.clone(),
        start_block: config.start_block,
        epoch: config.epoch,
        time_interval: config.time_interval,
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
