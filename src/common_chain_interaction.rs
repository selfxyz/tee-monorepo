use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ethers::abi::{decode, Address, ParamType};
use ethers::prelude::*;
use ethers::providers::Provider;
use ethers::utils::keccak256;
use log::{error, info};
use tokio::sync::RwLock;
use tokio::{task, time};
// use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::common_chain_util::{prune_old_blocks, BlockData};
use crate::HttpProvider;

abigen!(CommonChainContract, "./CommonChainContract.json",);
abigen!(RequestChainContract, "./RequestChainContract.json",);

#[derive(Debug, Clone)]
pub struct GatewayData {
    pub operator: Address,
    pub request_chains: Vec<RequestChainData>,
    pub stake_amount: U256,
    pub status: bool,
}

#[derive(Debug, Clone)]
pub struct CommonChainClient {
    pub key: String,
    pub chain_ws_client: Provider<Ws>,
    pub contract_addr: H160,
    pub start_block: u64,
    pub contract: CommonChainContract<HttpProvider>,
    pub gateway_data: GatewayData,
    pub req_chain_clients: HashMap<String, Arc<RequestChainClient>>,
}

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
pub struct Job {
    pub job_id: U256,
    pub tx_hash: H256,
    pub code_input: Bytes,
    pub user_timout: U256,
    pub starttime: U256,
    pub max_gas_price: U256,
    pub deposit: Address,
    pub callback_deposit: U256,
}

impl CommonChainClient {
    pub async fn new(
        key: String,
        chain_ws_client: Provider<Ws>,
        chain_http_client: HttpProvider,
        contract_addr: &H160,
        start_block: u64,
    ) -> Self {
        info!("Initializing Common Chain Client...");
        let contract = CommonChainContract::new(contract_addr.clone(), Arc::new(chain_http_client));
        let gateway = contract
            .gateways(key.parse::<Address>().unwrap())
            .await
            .context("Failed to get gateway data")
            .unwrap();
        let gateway_data = GatewayData {
            operator: gateway.0,
            request_chains: gateway
                .1
                .into_iter()
                .map(|(chain_id, contract_address, rpc_url)| RequestChainData {
                    chain_id,
                    contract_address,
                    rpc_url,
                })
                .collect(),
            stake_amount: gateway.2,
            status: gateway.3,
        };
        info!("Gateway Data fetched. Common Chain Client Initialized");

        CommonChainClient {
            key,
            chain_ws_client,
            contract_addr: *contract_addr,
            start_block,
            contract,
            gateway_data,
            req_chain_clients: HashMap::new(),
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        self.handle_all_req_chain_events().await?;
        todo!()
        // let (tx, rx) = channel(100);
        // let self_ref = Arc::clone(&self);
        // tokio::spawn(async move {
        //     self_ref._send_txns(rx).await;
        // });
        // self._listen_jobs(tx).await?;
        // Ok(())
    }

    async fn handle_all_req_chain_events(self: Arc<Self>) -> Result<()> {
        info!("Initializing Request Chain Clients for all request chains...");
        let mut req_chain_data = self.gateway_data.request_chains.clone();
        let mut request_chain_clients: HashMap<String, Arc<RequestChainClient>> = HashMap::new();
        while let Some(request_chain) = req_chain_data.pop() {
            let signer = self
                .key
                .clone()
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
            let self_clone = Arc::clone(&self);

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
                    let self_clone = Arc::clone(&self_clone);
                    task::spawn(async move {
                        self_clone.job_placed_handler(req_chain_client, log).await;
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

        *Arc::make_mut(&mut Arc::from(self.req_chain_clients.clone())) = request_chain_clients;
        Ok(())
    }

    async fn job_placed_handler(
        self: Arc<Self>,
        req_chain_client: Arc<RequestChainClient>,
        log: Log,
    ) {
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

        let job = Job {
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

    // async fn _listen_jobs(&self, tx: Sender) -> Result<(), Box<dyn Error>> {
    //     // event filter

    //     let event_filter = Filter::new()
    //         .address(self.contract_addr)
    //         .select(self.start_block..)
    //         .topic0(vec![keccak256(
    //             "JobPlaced(uint256,address,string,address,bytes)",
    //         )]);

    //     let mut stream = self
    //         .chain_ws_client
    //         .subscribe_logs(&event_filter)
    //         .await
    //         .context("Failed to subscribe to new job placed events")?;

    //     info!("Listening for events...");
    //     while let Some(event) = stream.next().await {
    //         // If log is removed then skip
    //         if event.removed.unwrap_or(false) {
    //             continue;
    //         }

    //         // decode event data
    //         let Ok(event_tokens) = decode(
    //             &vec![ParamType::Uint(32), ParamType::String, ParamType::String],
    //             &event.data.to_vec(),
    //         ) else {
    //             Self::log_skipped_event(&event, "Failed to decode event data");
    //             continue;
    //         };

    //         // create job struct from event
    //         let job = Job {
    //             id: match event_tokens[0].clone().into_uint() {
    //                 Some(id) => id,
    //                 None => {
    //                     Self::log_skipped_event(&event, "Failed to parse job ID from token");
    //                     continue;
    //                 }
    //             },
    //             txhash: match event_tokens[1].clone().into_string() {
    //                 Some(txhash) => txhash,
    //                 None => {
    //                     Self::log_skipped_event(&event, "Failed to parse job txhash from token");
    //                     continue;
    //                 }
    //             },
    //             input: match event_tokens[2].clone().into_string() {
    //                 Some(input) => input,
    //                 None => {
    //                     Self::log_skipped_event(&event, "Failed to parse job input from token");
    //                     continue;
    //                 }
    //             },
    //         };

    //         // Create a async task for event handler
    //         let job_handler = Arc::clone(&self.job_handler);
    //         let _success = match job_handler.job_placed(job, tx.clone()) {
    //             Ok(res) => res,
    //             Err(err) => {
    //                 let msg = format!("Failed to place the job: {}", err);
    //                 Self::log_skipped_event(&event, msg.as_str());
    //             }
    //         };
    //     }
    //     Ok(())
    // }

    // async fn _send_txns(&self, mut rx: Receiver<JobResponse>) {
    //     while let Some(job_resp) = rx.recv().await {
    //         info!("creating a transaction for jobFinish");
    //         let call = self.contract.job_finish(
    //             job_resp.id,
    //             job_resp.resp,
    //             job_resp.err,
    //             job_resp.exec_time,
    //             job_resp.timestamp,
    //             job_resp.sig,
    //         );
    //         info!("transaction created");

    //         let pending_tx = match call.send().await {
    //             Ok(pending_tx) => pending_tx,
    //             Err(err) => {
    //                 error!(
    //                     "Failed to send transaction for job {}: {:?}",
    //                     job_resp.id, err
    //                 );
    //                 continue;
    //             }
    //         };

    //         // Checking for one block confirmation
    //         let tx_receipt = match pending_tx.await {
    //             Ok(Some(tx)) => tx,
    //             Ok(None) => {
    //                 error!(
    //                     "Transaction has been dropped from mempool for job: {}",
    //                     job_resp.id
    //                 );
    //                 continue;
    //             }
    //             Err(err) => {
    //                 error!(
    //                     "Failed to confirm transaction for Job: {}: {:?}",
    //                     job_resp.id, err
    //                 );
    //                 continue;
    //             }
    //         };

    //         info!(
    //             "Transaction confirmed for Job: {}, Block: {}, TxHash: {}",
    //             job_resp.id,
    //             tx_receipt.block_number.unwrap_or(0.into()),
    //             tx_receipt.transaction_hash
    //         );
    //     }
    // }
}

pub async fn update_block_data(
    provider: Provider<Http>,
    recent_blocks: &Arc<RwLock<BTreeMap<u64, BlockData>>>,
) {
    let mut interval = time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        let latest_block = provider
            .get_block_number()
            .await
            .context("Failed to get the latest block number. Please check the chain url.")
            .unwrap()
            .as_u64();
        let latest_block_info = provider
            .get_block(latest_block)
            .await
            .context("Failed to get the latest block information. Please check the chain url.")
            .unwrap();

        if latest_block_info.is_none() {
            continue;
        }

        let timestamp = latest_block_info.unwrap().timestamp.as_u64();

        // Update the 'recent_blocks' map
        recent_blocks.write().await.insert(
            timestamp,
            BlockData {
                number: latest_block,
                timestamp,
            },
        );

        // Prune old entries (more on this below)
        prune_old_blocks(&recent_blocks).await;
    }
}
