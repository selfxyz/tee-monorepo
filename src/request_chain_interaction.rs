use std::sync::Arc;

use anyhow::{Context, Result};
use ethers::prelude::*;
use ethers::providers::Provider;
use ethers::utils::keccak256;
use log::{error, info};
use tokio::task;

use crate::HttpProvider;

abigen!(RequestChainContract, "./RequestChainContract.json",);

#[derive(Debug, Clone)]
pub struct RequestChainData {
    pub chain_id: U256,
    pub contract_address: Address,
    pub rpc_url: String,
}

pub struct RequestChainClient {
    pub chain_id: U256,
    pub contract_address: Address,
    pub rpc_url: String,
    pub chain_ws_client: Provider<Ws>,
    pub contract: RequestChainContract<HttpProvider>,
}

pub async fn handle_all_req_chain_events(
    mut req_chain_data: Vec<RequestChainData>,
    signer_key: String,
) -> Result<()> {
    info!("Initializing Request Chain Clients for all request chains...");
    while let Some(request_chain) = req_chain_data.pop() {
        let signer = signer_key
            .parse::<LocalWallet>()?
            .with_chain_id(request_chain.chain_id.as_u64());
        let signer_address = signer.address();

        let req_chain_ws_client =
            Provider::<Ws>::connect_with_reconnects(request_chain.rpc_url.clone(), 5).await.context(
                "Failed to connect to the request chain websocket provider. Please check the chain url.",
            )?;
        let req_chain_http_client = Provider::<Http>::connect(&request_chain.rpc_url)
            .await
            .with_signer(signer)
            .nonce_manager(signer_address);
        let contract = RequestChainContract::new(
            request_chain.contract_address,
            Arc::new(req_chain_http_client),
        );

        let event_filter = Filter::new()
            .address(request_chain.contract_address)
            .select(0..)
            .topic0(vec![
                keccak256("JobPlace(bytes32,bytes,uint256,uint256,uint256,uint256)"),
                keccak256("JobCancel(bytes32)"),
            ]);

        info!(
            "Connected to the request chain provider for chain_id: {}",
            request_chain.chain_id.as_u64()
        );
        info!(
            "Subscribing to events for chain_id: {}",
            request_chain.chain_id.as_u64()
        );

        // Spawn a new task for each Request Chain Contract
        task::spawn(async move {
            // register subscription
            let mut stream = req_chain_ws_client
                .subscribe_logs(&event_filter)
                .await
                .context("failed to subscribe to new jobs")
                .unwrap();

            while let Some(log) = stream.next().await {
                let topics = log.topics.clone();

                if topics[0]
                    == keccak256("JobPlace(uint256,bytes32,bytes,uint256,uint256,uint256,uint256)")
                        .into()
                {
                    info!(
                        "Request Chain ID: {:?}, JobPlace jobID: {:?}",
                        request_chain.chain_id, log
                    );
                } else if topics[0] == keccak256("JobCancel(uint256)").into() {
                    info!(
                        "Request Chain ID: {:?}, JobCancel jobID: {:?}",
                        request_chain.chain_id, log
                    );
                } else {
                    error!(
                        "Request Chain ID: {:?}, Unknown event: {:?}",
                        request_chain.chain_id, log
                    );
                }
            }
        });
    }
    Ok(())
}
