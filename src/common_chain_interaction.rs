use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ethers::abi::Address;
use ethers::prelude::*;
use ethers::providers::Provider;
use log::info;
use tokio::sync::RwLock;
use tokio::time;
// use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::common_chain_util::{prune_old_blocks, BlockData};
use crate::request_chain_interaction::{
    handle_all_req_chain_events, RequestChainClient, RequestChainData,
};
use crate::HttpProvider;

abigen!(CommonChainContract, "./CommonChainContract.json",);

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

        let req_chain_clients =
            handle_all_req_chain_events(gateway_data.request_chains.clone(), key.clone())
                .await
                .unwrap();
        info!("Request Chain Clients Initialized");

        CommonChainClient {
            key,
            chain_ws_client,
            contract_addr: *contract_addr,
            start_block,
            contract,
            gateway_data,
            req_chain_clients,
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        todo!()
        // let (tx, rx) = channel(100);
        // let self_ref = Arc::clone(&self);
        // tokio::spawn(async move {
        //     self_ref._send_txns(rx).await;
        // });
        // self._listen_jobs(tx).await?;
        // Ok(())
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
