use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use ethers::abi::ParamType;
use ethers::providers::Provider;
use ethers::utils::keccak256;
use ethers::{abi::decode, prelude::*};
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

#[derive(Debug, Clone)]
pub struct RequestChainClient {
    pub chain_id: U256,
    pub contract_address: Address,
    pub rpc_url: String,
    pub contract: RequestChainContract<HttpProvider>,
}

#[derive(Debug, Clone)]
pub struct JobRelayed {
    pub job_id: U256,
    pub tx_hash: H256,
    pub code_input: Bytes,
    pub user_timout: U256,
    pub starttime: U256,
    pub max_gas_price: U256,
    pub deposit: Address,
    pub callback_deposit: U256,
}

pub async fn handle_all_req_chain_events(
    mut req_chain_data: Vec<RequestChainData>,
    signer_key: String,
) -> Result<HashMap<String, Arc<RequestChainClient>>> {
    info!("Initializing Request Chain Clients for all request chains...");
    let mut request_chain_clients: HashMap<String, Arc<RequestChainClient>> = HashMap::new();
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
                keccak256(
                    "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,uint256)",
                ),
                keccak256("JobCancelled(bytes32)"),
            ]);

        info!(
            "Connected to the request chain provider for chain_id: {}",
            request_chain.chain_id.as_u64()
        );
        info!(
            "Subscribing to events for chain_id: {}",
            request_chain.chain_id.as_u64()
        );

        let req_chain_client = Arc::from(RequestChainClient {
            chain_id: request_chain.chain_id,
            contract_address: request_chain.contract_address,
            rpc_url: request_chain.rpc_url,
            contract,
        });

        let req_chain_client_clone = Arc::clone(&req_chain_client);

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
                    == keccak256(
                        "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,uint256)",
                    )
                    .into()
                {
                    info!(
                        "Request Chain ID: {:?}, JobPlace jobID: {:?}",
                        request_chain.chain_id, log.topics[1]
                    );
                    let req_chain_client = Arc::clone(&req_chain_client_clone);
                    task::spawn(async move {
                        job_placed_handler(req_chain_client, log).await;
                    });
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

        request_chain_clients.insert(request_chain.chain_id.to_string(), req_chain_client);
    }
    Ok(request_chain_clients)
}

async fn job_placed_handler(req_chain_client: Arc<RequestChainClient>, log: Log) {
    let types = vec![
        ParamType::Uint(256),
        ParamType::FixedBytes(32),
        ParamType::Bytes,
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::Uint(256),
    ];

    let decoded = decode(&types, &log.data.0).unwrap();

    let job_relayed = JobRelayed {
        job_id: decoded[0].clone().into_uint().unwrap(),
        tx_hash: TxHash::from_slice(&decoded[1].clone().into_bytes().unwrap()),
        code_input: decoded[2].clone().into_bytes().unwrap().into(),
        user_timout: decoded[3].clone().into_uint().unwrap(),
        starttime: decoded[4].clone().into_uint().unwrap(),
        max_gas_price: decoded[5].clone().into_uint().unwrap(),
        deposit: decoded[6].clone().into_address().unwrap(),
        callback_deposit: decoded[7].clone().into_uint().unwrap(),
    };
}
