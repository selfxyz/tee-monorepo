use anyhow::{Context, Result};
use async_recursion::async_recursion;
use ethers::abi::{decode, Address, ParamType};
use ethers::prelude::*;
use ethers::providers::Provider;
use ethers::utils::keccak256;
use k256::ecdsa::SigningKey;
use log::{error, info};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::{task, time};

use crate::chain_util::{
    get_key_for_job_id, pub_key_to_address, sign_job_response_response,
    sign_reassign_gateway_relay_response, sign_relay_job_response,
};
use crate::constant::{
    MAX_GATEWAY_RETRIES, OFFEST_FOR_GATEWAY_EPOCH_STATE_CYCLE, REQUEST_RELAY_TIMEOUT,
};
use crate::contract_abi::{
    CommonChainGatewayContract, CommonChainJobsContract, RequestChainContract,
};
use crate::model::{
    ComChainJobType, CommonChainClient, GatewayData, Job, JobResponse, ReqChainJobType,
    RequestChainClient, RequestChainData,
};
use crate::HttpProvider;

impl CommonChainClient {
    pub async fn new(
        enclave_signer_key: SigningKey,
        enclave_pub_key: Bytes,
        signer: LocalWallet,
        com_chain_ws_url: &String,
        chain_http_provider: Arc<HttpProvider>,
        gateway_contract_addr: &H160,
        contract_addr: &H160,
        gateway_epoch_state: Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
        request_chain_list: Vec<RequestChainData>,
        epoch: u64,
        time_interval: u64,
    ) -> Self {
        info!("Initializing Common Chain Client...");
        let gateway_contract = CommonChainGatewayContract::new(
            gateway_contract_addr.clone(),
            chain_http_provider.clone(),
        );

        let com_chain_jobs_contract =
            CommonChainJobsContract::new(contract_addr.clone(), chain_http_provider.clone());

        info!("Gateway Data fetched. Common Chain Client Initialized");

        let chain_ws_client = Provider::<Ws>::connect_with_reconnects(com_chain_ws_url, 5)
            .await
            .context(
                "Failed to connect to the chain websocket provider. Please check the chain url.",
            )
            .unwrap();

        CommonChainClient {
            signer,
            enclave_signer_key,
            address: pub_key_to_address(&enclave_pub_key).unwrap(),
            chain_ws_client,
            contract_addr: *contract_addr,
            gateway_contract_addr: *gateway_contract_addr,
            gateway_contract,
            com_chain_jobs_contract,
            req_chain_clients: HashMap::new(),
            gateway_epoch_state,
            request_chain_list,
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            epoch,
            time_interval,
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        // setup for the listening events on Request Chain and calling Common Chain functions
        let (req_chain_tx, com_chain_rx) = channel::<(Job, Arc<CommonChainClient>)>(100);
        let self_clone = Arc::clone(&self);
        self_clone.txns_to_common_chain(com_chain_rx).await?;
        let self_clone = Arc::clone(&self);
        self_clone.handle_all_req_chain_events(req_chain_tx).await?;

        // setup for the listening events on Common Chain and calling Request Chain functions
        let (com_chain_tx, req_chain_rx) = channel::<(JobResponse, Arc<CommonChainClient>)>(100);
        let self_clone = Arc::clone(&self);
        self_clone.txns_to_request_chain(req_chain_rx).await?;
        self.handle_all_com_chain_events(com_chain_tx).await?;
        Ok(())
    }

    async fn handle_all_req_chain_events(
        self: Arc<Self>,
        tx: Sender<(Job, Arc<CommonChainClient>)>,
    ) -> Result<()> {
        info!("Initializing Request Chain Clients for all request chains...");
        let mut req_chain_data = self.request_chain_list.clone();
        let mut request_chain_clients: HashMap<String, Arc<RequestChainClient>> = HashMap::new();
        for request_chain in req_chain_data.clone() {
            let signer = self.signer.clone().with_chain_id(request_chain.chain_id);
            let signer_address = signer.address();

            let req_chain_http_client = Provider::<Http>::connect(&request_chain.rpc_url)
                .await
                .with_signer(signer)
                .nonce_manager(signer_address);
            info!(
                "Connected to the request chain provider for chain_id: {}",
                request_chain.chain_id
            );
            let contract = RequestChainContract::new(
                request_chain.contract_address,
                Arc::new(req_chain_http_client),
            );
            let req_chain_client = Arc::from(RequestChainClient {
                chain_id: request_chain.chain_id,
                contract_address: request_chain.contract_address,
                rpc_url: request_chain.rpc_url,
                contract,
            });
            request_chain_clients.insert(request_chain.chain_id.to_string(), req_chain_client);
        }
        *Arc::make_mut(&mut Arc::from(self.req_chain_clients.clone())) = request_chain_clients;

        while let Some(request_chain) = req_chain_data.pop() {
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
                "Subscribing to events for chain_id: {}",
                request_chain.chain_id
            );

            let self_clone = Arc::clone(&self);
            let tx_clone = tx.clone();
            let req_chain_ws_client =
                Provider::<Ws>::connect_with_reconnects(request_chain.rpc_url.clone(), 5).await.context(
                    "Failed to connect to the request chain websocket provider. Please check the chain url.",
                )?;
            // Spawn a new task for each Request Chain Contract
            task::spawn(async move {
                // register subscription
                let mut stream = req_chain_ws_client
                    .subscribe_logs(&event_filter)
                    .await
                    .context(format!(
                        "failed to subscribe to events on Request Chain: {}",
                        request_chain.chain_id
                    ))
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
                    let self_clone = Arc::clone(&self_clone);
                    let tx = tx_clone.clone();
                    task::spawn(async move {
                        let job = self_clone.clone()
                            .get_job_from_job_relay_event(
                                log,
                                 1 as u8,
                                  &request_chain.chain_id.to_string()
                            )
                            .await
                            .context("Failed to decode event")
                            .unwrap();
                        self_clone.job_placed_handler(
                                &request_chain.chain_id.to_string(),
                                job,
                                tx.clone(),
                            )
                            .await;
                    });
                } else if topics[0] == keccak256("JobCancelled(uint256)").into() {
                    info!(
                        "Request Chain ID: {:?}, JobCancelled jobID: {:?}",
                        request_chain.chain_id, log.topics[1]
                    );
                    let self_clone = Arc::clone(&self_clone);
                    task::spawn(async move {
                        self_clone.cancel_job_with_job_id(
                            log.topics[1].into_uint(),
                            request_chain.chain_id
                        ).await;
                    });
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

    async fn get_job_from_job_relay_event(
        self: Arc<Self>,
        log: Log,
        sequence_number: u8,
        req_chain_id: &String,
    ) -> Result<Job> {
        let types = vec![
            ParamType::FixedBytes(32),
            ParamType::Bytes,
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
        ];

        let decoded = decode(&types, &log.data.0).unwrap();

        let req_chain_client = self.req_chain_clients[req_chain_id].clone();
        let job_id = log.topics[1].into_uint();

        Ok(Job {
            job_id,
            req_chain_id: req_chain_client.chain_id.clone(),
            job_key: get_key_for_job_id(job_id, req_chain_client.chain_id.clone()).await,
            tx_hash: decoded[0].clone().into_bytes().unwrap(),
            code_input: decoded[1].clone().into_bytes().unwrap().into(),
            user_timeout: decoded[2].clone().into_uint().unwrap(),
            starttime: decoded[3].clone().into_uint().unwrap(),
            max_gas_price: decoded[4].clone().into_uint().unwrap(),
            deposit: decoded[5].clone().into_address().unwrap(),
            callback_deposit: decoded[6].clone().into_uint().unwrap(),
            job_owner: log.address,
            job_type: ComChainJobType::JobRelay,
            sequence_number,
            gateway_address: None,
        })
    }

    async fn job_placed_handler(
        self: Arc<Self>,
        req_chain_id: &String,
        job: Job,
        tx: Sender<(Job, Arc<CommonChainClient>)>,
    ) {
        let mut job: Job = job.clone();
        let req_chain_client = self.req_chain_clients[req_chain_id].clone();

        let gateway_address: Address;

        gateway_address = self
            .select_gateway_for_job_id(
                job.job_id.clone(),
                job.starttime.as_u64(),
                job.sequence_number,
                req_chain_client,
            )
            .await
            .context("Failed to select a gateway for the job")
            .unwrap();

        job.gateway_address = Some(gateway_address);

        if gateway_address == self.address {
            // scope for the write lock
            {
                self.active_jobs
                    .write()
                    .await
                    .insert(job.job_key, job.clone());
            }
            tx.send((job, self.clone())).await.unwrap();
        } else {
            self.job_relayed_slash_timer(job.clone(), tx.clone())
                .await
                .unwrap();
        }
    }

    #[async_recursion]
    async fn job_relayed_slash_timer(
        self: Arc<Self>,
        mut job: Job,
        tx: Sender<(Job, Arc<CommonChainClient>)>,
    ) -> Result<()> {
        time::sleep(Duration::from_secs(REQUEST_RELAY_TIMEOUT)).await;

        // TODO: Issue with event logs -
        // get_logs might not provide the latest logs for the latest block
        // SOLUTION 1 - Wait for the next block.
        //          Problem: Extra time spent here waiting.
        let job_relayed_event_filter = Filter::new()
            .address(self.contract_addr)
            .topic0(vec![keccak256(
                "JobRelayed(uint256,uint256,bytes32,bytes,uint256,address,address,address[])",
            )])
            .topic1(job.job_id)
            .topic2(U256::from(job.req_chain_id));

        let logs = self
            .chain_ws_client
            .get_logs(&job_relayed_event_filter)
            .await
            .unwrap();

        for log in logs {
            let topics = log.topics.clone();
            if topics[0]
                == keccak256(
                    "JobRelayed(uint256,uint256,bytes32,bytes,uint256,address,address,address[])",
                )
                .into()
            {
                let decoded = decode(
                    &vec![
                        ParamType::FixedBytes(32),
                        ParamType::Bytes,
                        ParamType::Uint(256),
                        ParamType::Address,
                        ParamType::Address,
                        ParamType::Array(Box::new(ParamType::Address)),
                    ],
                    &log.data.0,
                )
                .unwrap();

                let job_id = log.topics[1].into_uint();
                let req_chain_id = log.topics[2].into_uint().low_u64();
                let tx_hash = decoded[0].clone().into_bytes().unwrap();
                let code_input: Vec<u8> = decoded[1].clone().into_bytes().unwrap().into();
                let user_timeout = decoded[2].clone().into_uint().unwrap();
                let job_owner = decoded[3].clone().into_address().unwrap();
                let gateway_operator = decoded[4].clone().into_address().unwrap();

                if job_id == job.job_id
                    && req_chain_id == job.req_chain_id
                    && tx_hash == job.tx_hash
                    && code_input == job.code_input
                    && user_timeout == job.user_timeout
                    && job_owner == job.job_owner
                    && gateway_operator != Address::zero()
                {
                    info!(
                        "Job ID: {:?}, JobRelayed event triggered for job ID: {:?}",
                        job.job_id, job_id
                    );
                    return Ok(());
                }
            }
        }

        info!("Job ID: {:?}, JobRelayed event not triggered", job.job_id);

        // slash the previous gateway
        {
            let self_clone = self.clone();
            let mut job_clone = job.clone();
            job_clone.job_type = ComChainJobType::SlashGatewayJob;
            let tx_clone = tx.clone();
            tx_clone.send((job_clone, self_clone)).await.unwrap();
        }

        job.sequence_number += 1;
        if job.sequence_number > MAX_GATEWAY_RETRIES {
            info!("Job ID: {:?}, Max retries reached", job.job_id);
            return Ok(());
        }
        job.gateway_address = None;

        self.job_placed_handler(&job.req_chain_id.to_string(), job, tx)
            .await;

        Ok(())
    }

    async fn select_gateway_for_job_id(
        &self,
        job_id: U256,
        seed: u64,
        skips: u8,
        req_chain_client: Arc<RequestChainClient>,
    ) -> Result<Address> {
        let current_cycle = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - self.epoch
            - OFFEST_FOR_GATEWAY_EPOCH_STATE_CYCLE)
            / self.time_interval;

        let all_gateways_data: Vec<GatewayData>;
        loop {
            let gateway_epoch_state_guard = self.gateway_epoch_state.read().await;
            if let Some(gateway_epoch_state) = gateway_epoch_state_guard.get(&current_cycle) {
                all_gateways_data = gateway_epoch_state.values().cloned().collect();
                break;
            }
            drop(gateway_epoch_state_guard);

            // wait for cycle to be created
            time::sleep(Duration::from_secs(60)).await;
        }

        // create a weighted probability distribution for gateways based on stake amount
        // For example, if there are 3 gateways with stake amounts 100, 200, 300
        // then the distribution arrat will be [100, 300, 600]
        let mut stake_distribution: Vec<u64> = vec![];
        let mut total_stake: u64 = 0;
        let mut gateway_data_of_req_chain: Vec<GatewayData> = vec![];
        for gateway_data in all_gateways_data.iter() {
            if gateway_data
                .req_chain_ids
                .contains(&U256::from(req_chain_client.chain_id))
            {
                gateway_data_of_req_chain.push(gateway_data.clone());
                total_stake += gateway_data.stake_amount.as_u64();
                stake_distribution.push(total_stake);
            }
        }

        // random number between 1 to total_stake from the eed for the weighted random selection.
        // use this seed in std_rng to generate a random number between 1 to total_stake
        // skipping skips numbers from the random number generated
        let mut rng = StdRng::seed_from_u64(seed);
        for _ in 0..skips - 1 {
            let _ = rng.gen_range(1..=total_stake);
        }
        let random_number = rng.gen_range(1..=total_stake);

        // select the gateway based on the random number
        let res = stake_distribution.binary_search_by(|&probe| {
            if probe < random_number {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        let index = match res {
            Ok(index) => index,
            Err(index) => index,
        };
        let selected_gateway = &gateway_data_of_req_chain[index];

        info!(
            "Job ID: {:?}, Gateway Address: {:?}",
            job_id, selected_gateway.address
        );

        Ok(selected_gateway.address)
    }

    async fn cancel_job_with_job_id(self: Arc<Self>, job_id: U256, req_chain_id: u64) {
        info!("Remove the job from the active jobs list");
        let job_key = get_key_for_job_id(job_id, req_chain_id).await;

        // scope for the write lock
        {
            self.active_jobs.write().await.remove(&job_key);
        }
    }

    async fn txns_to_common_chain(
        self: Arc<Self>,
        mut rx: Receiver<(Job, Arc<CommonChainClient>)>,
    ) -> Result<()> {
        while let Some((job, com_chain_client)) = rx.recv().await {
            match job.job_type {
                ComChainJobType::JobRelay => {
                    com_chain_client.relay_job_txn(job).await;
                }
                ComChainJobType::SlashGatewayJob => {
                    com_chain_client.reassign_gateway_relay_txn(job).await;
                }
            }
        }
        Ok(())
    }

    async fn relay_job_txn(self: Arc<Self>, job: Job) {
        info!("Creating a transaction for relayJob");
        let signature = sign_relay_job_response(
            &self.enclave_signer_key,
            job.job_id,
            job.req_chain_id.into(),
            &job.tx_hash,
            &job.code_input,
            job.user_timeout.as_u64(),
            &job.job_owner,
            job.sequence_number,
        )
        .await
        .unwrap();
        let signature = types::Bytes::from(signature.into_bytes());
        let tx_hash: [u8; 32] = job.tx_hash[..].try_into().unwrap();

        let txn = self.com_chain_jobs_contract.relay_job(
            signature,
            job.job_id,
            job.req_chain_id.into(),
            tx_hash,
            job.code_input,
            job.user_timeout,
            job.starttime,
            job.sequence_number,
            job.job_owner,
        );

        let pending_txn = txn.send().await;
        let Ok(pending_txn) = pending_txn else {
            error!(
                "Failed to confirm transaction {} for job relay to CommonChain",
                pending_txn.unwrap_err()
            );
            return;
        };

        let txn_hash = pending_txn.tx_hash();
        let Ok(Some(_)) = pending_txn.confirmations(1).await else {
            error!(
                "Failed to confirm transaction {} for job relay to CommonChain",
                txn_hash
            );
            return;
        };

        info!(
            "Transaction {} confirmed for job relay to CommonChain",
            txn_hash
        );
    }

    async fn reassign_gateway_relay_txn(self: Arc<Self>, job: Job) {
        info!("Creating a transaction for reassignGatewayRelay");
        let signature = sign_reassign_gateway_relay_response(
            &self.enclave_signer_key,
            job.job_id,
            job.gateway_address.as_ref().unwrap(),
        )
        .await
        .unwrap();
        let signature = types::Bytes::from(signature.into_bytes());

        let txn = self.com_chain_jobs_contract.reassign_gateway_relay(
            job.gateway_address.unwrap(),
            job.job_id,
            U256::from(job.req_chain_id),
            signature,
            job.sequence_number,
        );

        let pending_txn = txn.send().await;
        let Ok(pending_txn) = pending_txn else {
            error!(
                "Failed to confirm transaction {} for reassign gateway relay to CommonChain",
                pending_txn.unwrap_err()
            );
            return;
        };

        let txn_hash = pending_txn.tx_hash();
        let Ok(Some(_)) = pending_txn.confirmations(1).await else {
            error!(
                "Failed to confirm transaction {} for reassign gateway relay to CommonChain",
                txn_hash
            );
            return;
        };

        info!(
            "Transaction {} confirmed for reassign gateway relay to CommonChain",
            txn_hash
        );
    }

    async fn handle_all_com_chain_events(
        self: Arc<Self>,
        tx: Sender<(JobResponse, Arc<CommonChainClient>)>,
    ) -> Result<()> {
        info!("Subscribing to events for Common Chain");
        let event_filter = Filter::new()
            .address(self.contract_addr)
            .select(0..)
            .topic0(vec![
                keccak256("JobResponded(uint256,uint256,bytes,uint256,uint8,uint8)"),
                keccak256("JobResourceUnavailable(uint256,uint256,address)"),
                keccak256("GatewayReassigned(uint256,uint256,address,address,uint8)"),
            ]);

        let mut stream = self
            .chain_ws_client
            .subscribe_logs(&event_filter)
            .await
            .context("failed to subscribe to events on the Common Chain")
            .unwrap();

        while let Some(log) = stream.next().await {
            let topics = log.topics.clone();

            if topics[0]
                == keccak256("JobResponded(uint256,uint256,bytes,uint256,uint8,uint8)").into()
            {
                info!(
                    "JobResponded event triggered for job ID: {:?}, Request Chain ID: {:?}",
                    log.topics[1], log.topics[2]
                );
                let self_clone = Arc::clone(&self);
                let tx = tx.clone();
                task::spawn(async move {
                    let job_response = self_clone
                        .clone()
                        .get_job_from_job_responded_event(log)
                        .await
                        .context("Failed to decode event")
                        .unwrap();
                    self_clone.job_responded_handler(job_response, tx).await;
                });
            } else if topics[0]
                == keccak256("JobResourceUnavailable(uint256,uint256,address)").into()
            {
                info!("JobResourceUnavailable event triggered");
                let self_clone = Arc::clone(&self);
                task::spawn(async move {
                    self_clone.job_resource_unavailable_handler(log).await;
                });
            } else if topics[0]
                == keccak256("GatewayReassigned(uint256,uint256,address,address,uint8)").into()
            {
                info!(
                    "Request Chain ID: {:?}, GatewayReassigned jobID: {:?}",
                    log.topics[2], log.topics[1]
                );
                let self_clone = Arc::clone(&self);
                task::spawn(async move {
                    self_clone.gateway_reassigned_handler(log).await;
                });
            } else {
                error!("Unknown event: {:?}", log);
            }
        }

        Ok(())
    }

    async fn get_job_from_job_responded_event(self: Arc<Self>, log: Log) -> Result<JobResponse> {
        let types = vec![
            ParamType::Bytes,
            ParamType::Uint(256),
            ParamType::Uint(8),
            ParamType::Uint(8),
        ];

        let decoded = decode(&types, &log.data.0).unwrap();
        let job_id = log.topics[1].into_uint();
        let req_chain_id = log.topics[2].into_uint().low_u64();

        Ok(JobResponse {
            job_id,
            req_chain_id,
            job_key: get_key_for_job_id(job_id, req_chain_id).await,
            output: decoded[0].clone().into_bytes().unwrap().into(),
            total_time: decoded[1].clone().into_uint().unwrap(),
            error_code: decoded[2].clone().into_uint().unwrap().low_u64() as u8,
            output_count: decoded[3].clone().into_uint().unwrap().low_u64() as u8,
            job_type: ReqChainJobType::JobResponded,
            gateway_address: None,
            sequence_number: 0,
        })
    }

    async fn job_responded_handler(
        self: Arc<Self>,
        mut job_response: JobResponse,
        tx: Sender<(JobResponse, Arc<CommonChainClient>)>,
    ) {
        if job_response.output_count > 1 {
            info!(
                "Job ID: {:?}, Multiple outputs received. Ignoring the response.",
                job_response.job_id
            );
            return;
        }

        // let req_chain_client =
        //     self.req_chain_clients[&job_response.req_chain_id.to_string()].clone();

        let job: Option<Job>;
        // scope for the read lock
        {
            job = self
                .active_jobs
                .read()
                .await
                .get(&job_response.job_key)
                .cloned();
        }
        if job.is_some() {
            let job = job.unwrap();
            job_response.gateway_address = job.gateway_address;
            self.clone().remove_job(job).await;

            // Currently, slashing is not implemented for the JobResponded event
            // } else if job_response.sequence_number > 0 {
            //     let gateway_address: Address;
            //     // let seed be absolute difference between (job_id and req_chain_id) + total_time
            //     let seed = {
            //         let job_id_req_chain_id = match job_response
            //             .job_id
            //             .as_u64()
            //             .checked_sub(job_response.req_chain_id)
            //         {
            //             Some(val) => val,
            //             None => job_response.req_chain_id - job_response.job_id.as_u64(),
            //         };
            //         job_id_req_chain_id + job_response.total_time.as_u64()
            //     };
            //     gateway_address = self
            //         .select_gateway_for_job_id(
            //             job_response.job_id.clone(),
            //             seed,
            //             job_response.sequence_number,
            //             req_chain_client,
            //         )
            //         .await
            //         .context("Failed to select a gateway for the job")
            //         .unwrap();
            //     job_response.gateway_address = Some(gateway_address);
            // }
            // if job_response.gateway_address.unwrap() == self.address {
            tx.send((job_response, self.clone())).await.unwrap();
            // } else {
            //     self.job_responded_slash_timer(job_response.clone(), tx.clone())
            //         .await
            //         .unwrap();
        }
    }

    async fn remove_job(self: Arc<Self>, job: Job) {
        let mut active_jobs = self.active_jobs.write().await;
        // The retry number check is to make sure we are removing the correct job from the active jobs list
        // In a case where this txn took longer than the REQUEST_RELAY_TIMEOUT, the job might have been retried
        // and the active_jobs list might have the same job_id with a different retry number.
        if active_jobs.contains_key(&job.job_key)
            && active_jobs[&job.job_key].sequence_number == job.sequence_number
        {
            active_jobs.remove(&job.job_key);
        }
    }

    // TODO: Discuss with the team about the implementation of slashing for the JobResponded event
    // Currently, slashing is not implemented for the JobResponded event
    // #[async_recursion]
    // async fn job_responded_slash_timer(
    //     self: Arc<Self>,
    //     mut job_response: JobResponse,
    //     tx: Sender<(JobResponse, Arc<CommonChainClient>)>,
    // ) -> Result<()> {
    //     time::sleep(Duration::from_secs(RESPONSE_RELAY_TIMEOUT)).await;
    //     // get request chain client
    //     let req_chain_client =
    //         self.req_chain_clients[&job_response.req_chain_id.to_string()].clone();
    //     let onchain_job_response = req_chain_client
    //         .contract
    //         .jobs(job_response.job_id)
    //         .await
    //         .unwrap();
    //     let output_received: bool = onchain_job_response.8;
    //     let onchain_job_response: JobResponse = JobResponse {
    //         job_id: job_response.job_id,
    //         req_chain_id: job_response.req_chain_id,
    //         job_key: get_key_for_job_id(job_response.job_id, job_response.req_chain_id).await,
    //         output: Bytes::default().into(),
    //         total_time: U256::zero(),
    //         error_code: 0,
    //         output_count: 0,
    //         job_type: ReqChainJobType::JobResponded,
    //         gateway_address: Some(onchain_job_response.7),
    //         // depending on how the gateway is reassigned, the retry number might be different
    //         // can be added to event and a check below in the if condition
    //         // if retry number is added to the event,
    //         // remove_job_response needs to be updated accordingly
    //         sequence_number: 1,
    //     };
    //     if output_received && onchain_job_response.gateway_address.unwrap() != H160::zero() {
    //         info!(
    //             "Job ID: {:?}, JobResponded event triggered",
    //             job_response.job_id
    //         );
    //         return Ok(());
    //     }
    //     // TODO: how to slash the gateway now?
    //     // The same function used with the JobRelayed event won't work here.
    //     // For now, use the same function.
    //     {
    //         let self_clone = self.clone();
    //         let mut job_response_clone = job_response.clone();
    //         job_response_clone.job_type = ReqChainJobType::SlashGatewayResponse;
    //         let tx_clone = tx.clone();
    //         tx_clone
    //             .send((job_response_clone, self_clone))
    //             .await
    //             .unwrap();
    //     }
    //     job_response.sequence_number += 1;
    //     if job_response.sequence_number > MAX_GATEWAY_RETRIES {
    //         info!("Job ID: {:?}, Max retries reached", job_response.job_id);
    //         return Ok(());
    //     }
    //     // If gateway is already set, job_responded_handler will reassign the gateway
    //     job_response.gateway_address = onchain_job_response.gateway_address;
    //     self.job_responded_handler(job_response, tx).await;
    //     Ok(())
    // }

    async fn job_resource_unavailable_handler(self: Arc<Self>, log: Log) {
        let job_id = log.topics[1].into_uint();
        let req_chain_id = log.topics[2].into_uint().low_u64();

        let job_key = get_key_for_job_id(job_id, req_chain_id).await;
        let job: Job;
        // scope for the read lock
        {
            job = self.active_jobs.read().await.get(&job_key).unwrap().clone();
        }

        if job.gateway_address.unwrap() != self.address {
            return;
        }

        // scope for the write lock
        {
            self.active_jobs.write().await.remove(&job_key);
        }
    }

    async fn gateway_reassigned_handler(self: Arc<Self>, log: Log) {
        let types = vec![ParamType::Address, ParamType::Address, ParamType::Uint(8)];

        let decoded = decode(&types, &log.data.0).unwrap();

        let job_id = log.topics[1].into_uint();
        let req_chain_id = log.topics[2].into_uint().low_u64();
        let old_gateway = decoded[0].clone().into_address().unwrap();
        let sequence_number = decoded[2].clone().into_uint().unwrap().low_u64() as u8;

        if old_gateway != self.address {
            return;
        }

        let job_key = get_key_for_job_id(job_id, req_chain_id).await;
        let job: Job;
        // scope for the read lock
        {
            job = self.active_jobs.read().await.get(&job_key).unwrap().clone();
        }

        if job.sequence_number != sequence_number {
            return;
        }

        // scope for the write lock
        {
            self.active_jobs.write().await.remove(&job_key);
        }
    }

    async fn txns_to_request_chain(
        self: Arc<Self>,
        mut rx: Receiver<(JobResponse, Arc<CommonChainClient>)>,
    ) -> Result<()> {
        while let Some((job_response, com_chain_client)) = rx.recv().await {
            match job_response.job_type {
                ReqChainJobType::JobResponded => {
                    let com_chain_client_clone = com_chain_client.clone();
                    let job_response_clone = job_response.clone();
                    com_chain_client_clone
                        .job_response_txn(job_response_clone)
                        .await;
                    com_chain_client
                        .remove_job_response(job_response.job_key)
                        .await;
                } // Currently, slashing is not implemented for the JobResponded event
                  // ReqChainJobType::SlashGatewayResponse => {
                  //     com_chain_client
                  //         .reassign_gateway_response_txn(job_response)
                  //         .await;
                  // }
            }
        }
        Ok(())
    }

    async fn job_response_txn(self: Arc<Self>, job_response: JobResponse) {
        info!("Creating a transaction for jobResponse");

        let req_chain_client =
            self.req_chain_clients[&job_response.req_chain_id.to_string()].clone();

        let signature = sign_job_response_response(
            &self.enclave_signer_key,
            job_response.job_id,
            job_response.output.clone(),
            job_response.total_time,
            job_response.error_code,
        )
        .await
        .unwrap();
        let signature = types::Bytes::from(signature.into_bytes());

        let txn = req_chain_client.contract.job_response(
            signature,
            job_response.job_id,
            job_response.output,
            job_response.total_time,
            job_response.error_code,
        );

        let pending_txn = txn.send().await;
        let Ok(pending_txn) = pending_txn else {
            error!(
                "Failed to confirm transaction {} for job response to RequestChain",
                pending_txn.unwrap_err()
            );
            return;
        };

        let txn_hash = pending_txn.tx_hash();
        let Ok(Some(_)) = pending_txn.confirmations(1).await else {
            error!(
                "Failed to confirm transaction {} for job response to RequestChain",
                txn_hash
            );
            return;
        };

        info!(
            "Transaction {} confirmed for job response to RequestChain",
            txn_hash
        );
    }

    async fn remove_job_response(self: Arc<Self>, job_key: U256) {
        let mut active_jobs = self.active_jobs.write().await;
        active_jobs.remove(&job_key);
    }
}
