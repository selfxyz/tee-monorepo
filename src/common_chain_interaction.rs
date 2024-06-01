use anyhow::{Context, Result};
use async_recursion::async_recursion;
use ethers::abi::{decode, Address, ParamType};
use ethers::prelude::*;
use ethers::providers::Provider;
use ethers::utils::keccak256;
use hex::FromHex;
use k256::ecdsa::SigningKey;
use log::{error, info};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::{task, time};

use crate::chain_util::{
    get_key_for_job_id, pub_key_to_address, sign_job_response_response,
    sign_reassign_gateway_relay_response, sign_relay_job_response, LogsProvider,
};
use crate::common_chain_gateway_state_service::gateway_epoch_state_service;
use crate::constant::{
    GATEWAY_BLOCK_STATES_TO_MAINTAIN, MAX_GATEWAY_RETRIES, MIN_GATEWAY_STAKE,
    OFFEST_FOR_GATEWAY_EPOCH_STATE_CYCLE, REQUEST_RELAY_TIMEOUT,
};
use crate::contract_abi::{CommonChainGatewayContract, CommonChainJobsContract};
use crate::model::{
    ComChainJobType, CommonChainClient, GatewayData, Job, JobResponse, ReqChainJobType,
    RequestChainClient,
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
        jobs_contract_addr: &H160,
        gateway_epoch_state: Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
        request_chain_list: Vec<u64>,
        epoch: u64,
        time_interval: u64,
        req_chain_clients: HashMap<u64, Arc<RequestChainClient>>,
        gateway_epoch_state_waitlist: Arc<RwLock<HashMap<u64, Vec<Job>>>>,
    ) -> Self {
        info!("Initializing Common Chain Client...");
        let gateway_contract = CommonChainGatewayContract::new(
            gateway_contract_addr.clone(),
            chain_http_provider.clone(),
        );

        let com_chain_jobs_contract =
            CommonChainJobsContract::new(jobs_contract_addr.clone(), chain_http_provider.clone());

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
            jobs_contract_addr: *jobs_contract_addr,
            gateway_contract_addr: *gateway_contract_addr,
            gateway_contract,
            com_chain_jobs_contract,
            req_chain_clients,
            gateway_epoch_state,
            request_chain_list,
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            epoch,
            time_interval,
            gateway_epoch_state_waitlist,
        }
    }

    pub async fn run(
        self: Arc<Self>,
        common_chain_http: Arc<HttpProvider>,
    ) -> Result<(), Box<dyn Error>> {
        // setup for the listening events on Request Chain and calling Common Chain functions
        let (req_chain_tx, com_chain_rx) = channel::<(Job, Arc<CommonChainClient>)>(100);
        let self_clone = Arc::clone(&self);
        // Start the gateway epoch state service
        {
            let service_start_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let contract_client_clone = self.clone();
            let tx_clone = req_chain_tx.clone();
            tokio::spawn(async move {
                gateway_epoch_state_service(
                    service_start_time,
                    &common_chain_http,
                    contract_client_clone,
                    tx_clone,
                )
                .await;
            });
        }
        tokio::spawn(async move {
            let _ = self_clone.txns_to_common_chain(com_chain_rx).await;
        });
        let self_clone = Arc::clone(&self);
        self_clone.handle_all_req_chain_events(req_chain_tx).await?;

        // setup for the listening events on Common Chain and calling Request Chain functions
        let (com_chain_tx, req_chain_rx) = channel::<(JobResponse, Arc<CommonChainClient>)>(100);
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            let _ = self_clone.txns_to_request_chain(req_chain_rx).await;
        });
        self.handle_all_com_chain_events(com_chain_tx).await?;
        Ok(())
    }

    async fn handle_all_req_chain_events(
        self: Arc<Self>,
        tx: Sender<(Job, Arc<CommonChainClient>)>,
    ) -> Result<()> {
        info!("Initializing Request Chain Clients for all request chains...");
        let mut req_chain_data = self.request_chain_list.clone();

        while let Some(chain_id) = req_chain_data.pop() {
            let self_clone = Arc::clone(&self);
            let tx_clone = tx.clone();

            let req_chain_ws_client = Provider::<Ws>::connect_with_reconnects(
                    self_clone.req_chain_clients[&chain_id].ws_rpc_url.clone(),
                    5,
                ).await
                .context(
                    "Failed to connect to the request chain websocket provider. Please check the chain url.",
                )?;

            // Spawn a new task for each Request Chain Contract
            task::spawn(async move {
                let mut stream = self_clone
                    .req_chain_jobs(
                        &req_chain_ws_client,
                        &self_clone.req_chain_clients[&chain_id],
                    )
                    .await
                    .unwrap();

                while let Some(log) = stream.next().await {
                    let topics = log.topics.clone();

                    if let Some(is_removed) = log.removed {
                        if is_removed {
                            continue;
                        }
                    } else {
                        continue;
                    }

                    if topics[0]
                        == keccak256(
                            "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,uint256)",
                        )
                        .into()
                    {
                        info!(
                            "Request Chain ID: {:?}, JobPlace jobID: {:?}",
                            chain_id, log.topics[1]
                        );

                        let self_clone = Arc::clone(&self_clone);
                        let tx = tx_clone.clone();
                        task::spawn(async move {
                            // TODO: what to do in case of error? Let it panic or return None?
                            let job = self_clone.clone()
                                .get_job_from_job_relay_event(
                                    log,
                                    1 as u8,
                                    chain_id
                                )
                                .await
                                .context("Failed to get Job from Log")
                                .unwrap();
                            self_clone.job_placed_handler(
                                    job,
                                    tx.clone(),
                                )
                                .await;
                        });
                    } else if topics[0] == keccak256("JobCancelled(uint256)").into() {
                        info!(
                            "Request Chain ID: {:?}, JobCancelled jobID: {:?}",
                            chain_id, log.topics[1]
                        );

                        let self_clone = Arc::clone(&self_clone);
                        task::spawn(async move {
                            self_clone.cancel_job_with_job_id(
                                log.topics[1].into_uint(),
                                chain_id
                            ).await;
                        });
                    } else {
                        error!(
                            "Request Chain ID: {:?}, Unknown event: {:?}",
                            chain_id, log
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
        req_chain_id: u64,
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

        let decoded = decode(&types, &log.data.0);
        let decoded = match decoded {
            Ok(decoded) => decoded,
            Err(err) => {
                error!("Error while decoding event: {}", err);
                return Err(anyhow::Error::msg("Error while decoding event"));
            }
        };

        let req_chain_client = self.req_chain_clients[&req_chain_id].clone();
        let job_id = log.topics[1].into_uint();

        Ok(Job {
            job_id,
            req_chain_id: req_chain_client.chain_id.clone(),
            job_key: get_key_for_job_id(job_id, req_chain_client.chain_id.clone()).await,
            tx_hash: decoded[0].clone().into_fixed_bytes().unwrap(),
            code_input: decoded[1].clone().into_bytes().unwrap().into(),
            user_timeout: decoded[2].clone().into_uint().unwrap(),
            starttime: decoded[6].clone().into_uint().unwrap(),
            job_owner: log.address,
            job_type: ComChainJobType::JobRelay,
            sequence_number,
            gateway_address: None,
        })
    }

    pub async fn job_placed_handler(
        self: Arc<Self>,
        mut job: Job,
        tx: Sender<(Job, Arc<CommonChainClient>)>,
    ) {
        let req_chain_client = self.req_chain_clients[&job.req_chain_id].clone();

        let gateway_address = self
            .select_gateway_for_job_id(
                job.clone(),
                job.starttime.as_u64(), // TODO: Update seed
                job.sequence_number,
                req_chain_client,
            )
            .await;

        // if error message is returned, then the job is older than the maintained block states
        match gateway_address {
            Ok(gateway_address) => {
                job.gateway_address = Some(gateway_address);

                if gateway_address == Address::zero() {
                    return;
                }

                if gateway_address == self.address {
                    // scope for the write lock
                    {
                        self.active_jobs
                            .write()
                            .unwrap()
                            .insert(job.job_key, job.clone());
                    }
                    tx.send((job, self.clone())).await.unwrap();
                } else {
                    self.job_relayed_slash_timer(job.clone(), None, tx.clone())
                        .await
                        .unwrap();
                }
            }
            Err(err) => {
                // confirm error message
                if err.to_string() != "Job is older than the maintained block states" {
                    error!("Error while selecting gateway: {}", err);
                    panic!("Error while selecting gateway: {}", err);
                }
            }
        };
    }

    // Return value meaning
    // 1 - JobRelayed event triggered
    // 2 - JobRelayed event not triggered, retrying
    // 3 - Max retries reached
    #[async_recursion]
    async fn job_relayed_slash_timer(
        self: Arc<Self>,
        mut job: Job,
        mut job_timeout: Option<u64>,
        tx: Sender<(Job, Arc<CommonChainClient>)>,
    ) -> Result<u64> {
        if job_timeout.is_none() {
            job_timeout = Some(REQUEST_RELAY_TIMEOUT);
        }
        time::sleep(Duration::from_secs(job_timeout.unwrap())).await;

        // TODO: Issue with event logs -
        // get_logs might not provide the latest logs for the latest block
        // SOLUTION 1 - Wait for the next block.
        //          Problem: Extra time spent here waiting.
        let logs = self
            .common_chain_job_relayed_logs(job.clone())
            .await
            .context("Failed to get logs")?;

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
                let tx_hash = decoded[0].clone().into_fixed_bytes().unwrap();
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
                    return Ok(1);
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
            return Ok(3);
        }
        job.gateway_address = None;

        task::spawn(async move {
            self.job_placed_handler(job.clone(), tx.clone()).await;
        });

        Ok(2)
    }

    async fn select_gateway_for_job_id(
        &self,
        job: Job,
        seed: u64,
        skips: u8,
        req_chain_client: Arc<RequestChainClient>,
    ) -> Result<Address> {
        let job_cycle =
            (job.starttime.as_u64() - self.epoch - OFFEST_FOR_GATEWAY_EPOCH_STATE_CYCLE)
                / self.time_interval;

        let all_gateways_data: Vec<GatewayData>;

        {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let current_cycle =
                (ts - self.epoch - OFFEST_FOR_GATEWAY_EPOCH_STATE_CYCLE) / self.time_interval;
            if current_cycle >= GATEWAY_BLOCK_STATES_TO_MAINTAIN + job_cycle {
                return Err(anyhow::Error::msg(
                    "Job is older than the maintained block states",
                ));
            }
            let gateway_epoch_state_guard = self.gateway_epoch_state.read().unwrap();
            if let Some(gateway_epoch_state) = gateway_epoch_state_guard.get(&job_cycle) {
                all_gateways_data = gateway_epoch_state
                    .values()
                    .cloned()
                    .collect::<Vec<GatewayData>>();
            } else {
                let mut waitlist_handle = self.gateway_epoch_state_waitlist.write().unwrap();
                waitlist_handle
                    .entry(job_cycle)
                    .and_modify(|jobs| jobs.push(job.clone()))
                    .or_insert(vec![job]);
                return Ok(Address::zero());
            }
        }

        // create a weighted probability distribution for gateways based on stake amount
        // For example, if there are 3 gateways with stake amounts 100, 200, 300
        // then the distribution array will be [100, 300, 600]
        let mut stake_distribution: Vec<u64> = vec![];
        let mut total_stake: u64 = 0;
        let mut gateway_data_of_req_chain: Vec<GatewayData> = vec![];
        if all_gateways_data.is_empty() {
            return Err(anyhow::Error::msg("No Gateways Registered"));
        }
        for gateway_data in all_gateways_data.iter() {
            if gateway_data
                .req_chain_ids
                .contains(&req_chain_client.chain_id)
                && gateway_data.stake_amount.as_u64() > MIN_GATEWAY_STAKE
                && gateway_data.status
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
        let res = stake_distribution.binary_search_by(|&probe| probe.cmp(&random_number));

        let index = match res {
            Ok(index) => index,
            Err(index) => index,
        };
        let selected_gateway = &gateway_data_of_req_chain[index];

        info!(
            "Job ID: {:?}, Gateway Address: {:?}",
            job.job_id, selected_gateway.address
        );

        Ok(selected_gateway.address)
    }

    async fn cancel_job_with_job_id(self: Arc<Self>, job_id: U256, req_chain_id: u64) {
        info!("Remove the job from the active jobs list");
        let job_key = get_key_for_job_id(job_id, req_chain_id).await;

        // scope for the write lock
        {
            self.active_jobs.write().unwrap().remove(&job_key);
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
            job.user_timeout,
            &job.job_owner,
            job.sequence_number,
            job.starttime,
        )
        .await
        .unwrap();
        let Ok(signature) = types::Bytes::from_hex(signature) else {
            error!("Failed to decode signature hex string");
            return;
        };
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
        let Ok(signature) = types::Bytes::from_hex(signature) else {
            error!("Failed to decode signature hex string");
            return;
        };

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
        let mut stream = self.common_chain_jobs().await.unwrap();

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
                .unwrap()
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
        let mut active_jobs = self.active_jobs.write().unwrap();
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

        let active_jobs_guard = self.active_jobs.read().unwrap();
        let job = active_jobs_guard.get(&job_key);
        if job.is_none() {
            return;
        }
        let job = job.unwrap().clone();
        drop(active_jobs_guard);

        if job.gateway_address.unwrap() != self.address {
            return;
        }

        // scope for the write lock
        {
            self.active_jobs.write().unwrap().remove(&job_key);
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
            job = self
                .active_jobs
                .read()
                .unwrap()
                .get(&job_key)
                .unwrap()
                .clone();
        }

        if job.sequence_number != sequence_number {
            return;
        }

        // scope for the write lock
        {
            self.active_jobs.write().unwrap().remove(&job_key);
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

        let req_chain_client = self.req_chain_clients[&job_response.req_chain_id].clone();

        let signature = sign_job_response_response(
            &self.enclave_signer_key,
            job_response.job_id,
            job_response.output.clone(),
            job_response.total_time,
            job_response.error_code,
        )
        .await
        .unwrap();
        let Ok(signature) = types::Bytes::from_hex(signature) else {
            error!("Failed to decode signature hex string");
            return;
        };

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
        let mut active_jobs = self.active_jobs.write().unwrap();
        active_jobs.remove(&job_key);
    }
}

impl LogsProvider for CommonChainClient {
    async fn common_chain_jobs<'a>(&'a self) -> Result<SubscriptionStream<'a, Ws, Log>> {
        info!("Subscribing to events for Common Chain");
        let event_filter: Filter = Filter::new()
            .address(self.jobs_contract_addr)
            .select(0..)
            .topic0(vec![
                keccak256("JobResponded(uint256,uint256,bytes,uint256,uint8,uint8)"),
                keccak256("JobResourceUnavailable(uint256,uint256,address)"),
                keccak256("GatewayReassigned(uint256,uint256,address,address,uint8)"),
            ]);

        let stream = self
            .chain_ws_client
            .subscribe_logs(&event_filter)
            .await
            .context("failed to subscribe to events on the Common Chain")
            .unwrap();

        Ok(stream)
    }

    async fn req_chain_jobs<'a>(
        &'a self,
        req_chain_ws_client: &'a Provider<Ws>,
        req_chain_client: &'a RequestChainClient,
    ) -> Result<SubscriptionStream<'a, Ws, Log>> {
        info!(
            "Subscribing to events for Req Chain chain_id: {}",
            req_chain_client.chain_id
        );

        let event_filter = Filter::new()
            .address(req_chain_client.contract_address)
            .select(0..)
            .topic0(vec![
                keccak256(
                    "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,uint256)",
                ),
                keccak256("JobCancelled(bytes32)"),
            ]);

        // register subscription
        let stream = req_chain_ws_client
            .subscribe_logs(&event_filter)
            .await
            .context(format!(
                "failed to subscribe to events on Request Chain: {}",
                req_chain_client.chain_id
            ))
            .unwrap();

        Ok(stream)
    }

    #[cfg(not(test))]
    async fn common_chain_job_relayed_logs<'a>(&'a self, job: Job) -> Result<Vec<Log>> {
        let job_relayed_event_filter = Filter::new()
            .address(self.jobs_contract_addr)
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

        Ok(logs)
    }

    #[cfg(test)]
    async fn common_chain_job_relayed_logs<'a>(&'a self, job: Job) -> Result<Vec<Log>> {
        use ethers::abi::{encode, Token};
        use ethers::prelude::*;
        use serde_json::json;

        if job.job_id == U256::from(1) {
            Ok(vec![Log {
                address: self.jobs_contract_addr,
                topics: vec![
                keccak256(
                    "JobRelayed(uint256,uint256,bytes32,bytes,uint256,address,address,address[])",
                )
                .into(),
                H256::from_uint(&job.job_id),
                H256::from_uint(&job.req_chain_id.into()),
            ],
                data: encode(&[
                    Token::FixedBytes(
                        hex::decode(
                            "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e"
                                .to_owned(),
                        )
                        .unwrap(),
                    ),
                    Token::Bytes(
                        serde_json::to_vec(&json!({
                            "num": 10
                        }))
                        .unwrap(),
                    ),
                    Token::Uint(2000.into()),
                    Token::Address(job.job_owner),
                    Token::Address(job.gateway_address.unwrap()),
                    Token::Array(vec![]),
                ])
                .into(),
                ..Default::default()
            }])
        } else {
            Ok(vec![])
        }
    }
}

#[cfg(test)]
mod serverless_executor_test {
    use std::collections::{BTreeMap, BTreeSet};
    use std::str::FromStr;
    use std::sync::{Arc, RwLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use actix_web::body::MessageBody;
    use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
    use actix_web::web::Data;
    use actix_web::{http, test, App, Error};
    use ethers::abi::{encode, Token};
    use ethers::prelude::*;
    use ethers::types::{Address, Bytes as EthBytes};
    use ethers::utils::keccak256;
    use k256::ecdsa::SigningKey;
    use rand::rngs::{OsRng, StdRng};
    use rand::{Rng, SeedableRng};
    use serde_json::json;
    use tokio::sync::mpsc::channel;
    use tokio::task;
    use tokio::time::{sleep, Duration};

    use crate::api_impl::{deregister_enclave, index, inject_key, register_enclave};
    use crate::chain_util::get_key_for_job_id;
    use crate::constant::{MAX_GATEWAY_RETRIES, OFFEST_FOR_GATEWAY_EPOCH_STATE_CYCLE};
    use crate::model::{AppState, ComChainJobType, CommonChainClient, GatewayData, Job};

    // Testnet or Local blockchain (Hardhat) configurations
    const CHAIN_ID: u64 = 421614;
    const HTTP_RPC_URL: &str = "https://sepolia-rollup.arbitrum.io/rpc";
    const WS_URL: &str = "wss://arbitrum-sepolia.infura.io/ws/v3/cd72f20b9fd544f8a5b8da706441e01c";
    const GATEWAY_CONTRACT_ADDR: &str = "0x819d9b4087D88359B6d7fFcd16F17A13Ca79fd0E";
    const JOB_CONTRACT_ADDR: &str = "0xAc6Ae536203a3ec290ED4aA1d3137e6459f4A963";
    const REQ_CHAIN_CONTRACT_ADDR: &str = "0xaF7E4CB6B3729C65c4a9a63d89Ae04e97C9093C4";
    const WALLET_PRIVATE_KEY: &str =
        "0x083f09e4d950da6eee7eac93ba7fa046d12eb3c8ca4e4ba92487ae3526e87bda";
    const REGISTER_ATTESTATION: &str = "0xcfa7554f87ba13620037695d62a381a2d876b74c2e1b435584fe5c02c53393ac1c5cd5a8b6f92e866f9a65af751e0462cfa7554f87ba13620037695d62a381a2d8";
    const REGISTER_PCR_0: &str = "0xcfa7554f87ba13620037695d62a381a2d876b74c2e1b435584fe5c02c53393ac1c5cd5a8b6f92e866f9a65af751e0462";
    const REGISTER_PCR_1: &str = "0xbcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f";
    const REGISTER_PCR_2: &str = "0x20caae8a6a69d9b1aecdf01a0b9c5f3eafd1f06cb51892bf47cef476935bfe77b5b75714b68a69146d650683a217c5b3";
    const REGISTER_TIMESTAMP: usize = 1722134849000;
    const REGISTER_STAKE_AMOUNT: usize = 100;
    const EPOCH: u64 = 1713433800;
    const TIME_INTERVAL: u64 = 300;

    // Generate test app state
    async fn generate_app_state() -> Data<AppState> {
        // Initialize random 'secp256k1' signing key for the enclave
        let signer = SigningKey::random(&mut OsRng);
        let signer_verifier_key: [u8; 64] =
            signer.verifying_key().to_encoded_point(false).to_bytes()[1..]
                .try_into()
                .unwrap();

        Data::new(AppState {
            enclave_signer_key: signer,
            wallet: None.into(),
            common_chain_id: CHAIN_ID,
            common_chain_http_url: HTTP_RPC_URL.to_owned(),
            common_chain_ws_url: WS_URL.to_owned(),
            gateway_contract_addr: GATEWAY_CONTRACT_ADDR.parse::<Address>().unwrap(),
            job_contract_addr: JOB_CONTRACT_ADDR.parse::<Address>().unwrap(),
            chain_list: vec![].into(),
            registered: false.into(),
            enclave_pub_key: EthBytes::from(&signer_verifier_key),
            gateway_epoch_state: Arc::new(RwLock::new(BTreeMap::new())),
            epoch: EPOCH,
            time_interval: TIME_INTERVAL,
            common_chain_client: None.into(),
        })
    }

    // Return the actix server with the provided app state
    fn new_app(
        app_state: Data<AppState>,
    ) -> App<
        impl ServiceFactory<
            ServiceRequest,
            Response = ServiceResponse<impl MessageBody + std::fmt::Debug>,
            Config = (),
            InitError = (),
            Error = Error,
        >,
    > {
        App::new()
            .app_data(app_state)
            .service(index)
            .service(inject_key)
            .service(register_enclave)
            .service(deregister_enclave)
    }

    #[actix_web::test]
    // Test the various response cases for the 'inject_key' endpoint
    async fn inject_key_test() {
        let app = test::init_service(new_app(generate_app_state().await)).await;

        // Inject invalid hex private key string
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": "0x32255"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to hex decode the key into 32 bytes: Odd number of digits".as_bytes()
        );

        // Inject invalid length private key
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": "0x322c322c322c332c352c35"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to hex decode the key into 32 bytes: Invalid string length"
        );

        // Inject invalid private(signing) key
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid secret key provided: signature error"
        );

        // Inject a valid private key
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": WALLET_PRIVATE_KEY
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret key injected successfully"
        );

        // Inject the valid private key again
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": WALLET_PRIVATE_KEY
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret key has already been injected"
        );
    }

    #[actix_web::test]
    // Test the various response cases for the 'register_enclave' & 'deregister_enclave' endpoint
    async fn register_deregister_enclave_test() {
        let app = test::init_service(new_app(generate_app_state().await)).await;

        // Register the executor without injecting the operator's private key
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&json!({
                "attestation": REGISTER_ATTESTATION,
                "pcr_0": REGISTER_PCR_0,
                "pcr_1": REGISTER_PCR_1,
                "pcr_2": REGISTER_PCR_2,
                "timestamp": REGISTER_TIMESTAMP,
                "stake_amount": REGISTER_STAKE_AMOUNT,
                "chain_list": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Operator secret key not injected yet!"
        );

        // Deregister the enclave without even injecting the private key
        let req = test::TestRequest::delete().uri("/deregister").to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Enclave is not registered yet."
        );

        // Inject a valid private key into the enclave
        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": WALLET_PRIVATE_KEY
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Secret key injected successfully"
        );

        // Deregister the enclave before even registering it
        let req = test::TestRequest::delete().uri("/deregister").to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Enclave is not registered yet."
        );

        // Register the enclave with an invalid attestation hex string
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&json!({
                "attestation": "0x32255",
                "pcr_0": "0x",
                "pcr_1": "0x",
                "pcr_2": "0x",
                "timestamp": 2160,
                "stake_amount": 100,
                "chain_list": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid format of attestation."
        );

        // Register the enclave with valid data points
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&json!({
                "attestation": REGISTER_ATTESTATION,
                "pcr_0": REGISTER_PCR_0,
                "pcr_1": REGISTER_PCR_1,
                "pcr_2": REGISTER_PCR_2,
                "timestamp": REGISTER_TIMESTAMP,
                "stake_amount": REGISTER_STAKE_AMOUNT,
                "chain_list": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(resp
            .into_body()
            .try_into_bytes()
            .unwrap()
            .starts_with("Enclave Node successfully registered on the common chain".as_bytes()));

        // Register the enclave again before deregistering
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&json!({
                "attestation": REGISTER_ATTESTATION,
                "pcr_0": REGISTER_PCR_0,
                "pcr_1": REGISTER_PCR_1,
                "pcr_2": REGISTER_PCR_2,
                "timestamp": REGISTER_TIMESTAMP,
                "stake_amount": REGISTER_STAKE_AMOUNT,
                "chain_list": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Enclave has already been registered."
        );

        sleep(Duration::from_secs(2)).await;
        // Deregister the enclave
        let req = test::TestRequest::delete().uri("/deregister").to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(resp.into_body().try_into_bytes().unwrap().starts_with(
            "Enclave Node successfully deregistered from the common chain".as_bytes()
        ));

        // Deregister the enclave again before registering it
        let req = test::TestRequest::delete().uri("/deregister").to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Enclave is not registered yet."
        );
    }

    async fn generate_common_chain_client() -> CommonChainClient {
        let app_state = generate_app_state().await;
        let app = test::init_service(new_app(app_state.clone())).await;

        let req = test::TestRequest::post()
            .uri("/inject-key")
            .set_json(&json!({
                "operator_secret": WALLET_PRIVATE_KEY
            }))
            .to_request();

        test::call_service(&app, req).await;

        // Register the enclave again before deregistering
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&json!({
                "attestation": REGISTER_ATTESTATION,
                "pcr_0": REGISTER_PCR_0,
                "pcr_1": REGISTER_PCR_1,
                "pcr_2": REGISTER_PCR_2,
                "timestamp": REGISTER_TIMESTAMP,
                "stake_amount": REGISTER_STAKE_AMOUNT,
                "chain_list": [CHAIN_ID]
            }))
            .to_request();

        test::call_service(&app, req).await;

        let common_chain_client = app_state
            .common_chain_client
            .lock()
            .unwrap()
            .clone()
            .unwrap();

        common_chain_client
    }

    async fn add_gateway_epoch_state(
        common_chain_client: Arc<CommonChainClient>,
        num: Option<u64>,
    ) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current_cycle = (ts - common_chain_client.epoch - OFFEST_FOR_GATEWAY_EPOCH_STATE_CYCLE)
            / common_chain_client.time_interval;

        let mut gateway_epoch_state_guard =
            common_chain_client.gateway_epoch_state.write().unwrap();
        gateway_epoch_state_guard
            .entry(current_cycle)
            .or_insert(BTreeMap::new())
            .insert(
                common_chain_client.address,
                GatewayData {
                    last_block_number: 5600 as u64,
                    address: common_chain_client.address,
                    stake_amount: U256::from(100),
                    status: true,
                    req_chain_ids: BTreeSet::from([CHAIN_ID]),
                },
            );

        let num = num.unwrap_or(1);

        for _ in 1..num {
            gateway_epoch_state_guard
                .entry(current_cycle)
                .or_insert(BTreeMap::new())
                .insert(
                    Address::random(),
                    GatewayData {
                        last_block_number: 5600 as u64,
                        address: Address::random(),
                        stake_amount: U256::from(100),
                        status: true,
                        req_chain_ids: BTreeSet::from([CHAIN_ID]),
                    },
                );
        }
    }

    async fn generate_job_relayed_log(job_id: Option<U256>, job_starttime: u64) -> Log {
        let job_id = job_id.unwrap_or(U256::from(1));

        Log {
            address: H160::from_str(REQ_CHAIN_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256(
                    "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,uint256)",
                )
                .into(),
                H256::from_uint(&job_id),
            ],
            data: encode(&[
                Token::FixedBytes(
                    hex::decode(
                        "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e"
                            .to_owned(),
                    )
                    .unwrap(),
                ),
                Token::Bytes(
                    serde_json::to_vec(&json!({
                        "num": 10
                    }))
                    .unwrap(),
                ),
                Token::Uint(2000.into()),
                Token::Uint(20.into()),
                Token::Uint(100.into()),
                Token::Uint(100.into()),
                Token::Uint(U256::from(job_starttime)),
            ])
            .into(),
            ..Default::default()
        }
    }

    async fn generate_generic_job(job_id: Option<U256>, job_starttime: Option<u64>) -> Job {
        let job_id = job_id.unwrap_or(U256::from(1));

        Job {
            job_id,
            req_chain_id: CHAIN_ID,
            job_key: get_key_for_job_id(job_id, CHAIN_ID).await,
            tx_hash: hex::decode(
                "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e".to_owned(),
            )
            .unwrap(),
            code_input: serde_json::to_vec(&json!({
                "num": 10
            }))
            .unwrap()
            .into(),
            user_timeout: U256::from(2000),
            starttime: U256::from(
                job_starttime.unwrap_or(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                ),
            ),
            job_owner: H160::from_str(REQ_CHAIN_CONTRACT_ADDR).unwrap(),
            job_type: ComChainJobType::JobRelay,
            sequence_number: 1 as u8,
            gateway_address: None,
        }
    }

    #[actix_web::test]
    async fn test_get_job_from_job_relay_event() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let job_starttime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let log = generate_job_relayed_log(None, job_starttime).await;

        let expected_job = generate_generic_job(None, Some(job_starttime)).await;

        let job = common_chain_client
            .get_job_from_job_relay_event(log, 1 as u8, CHAIN_ID)
            .await
            .unwrap();

        assert_eq!(job, expected_job);
    }

    #[actix_web::test]
    async fn test_get_job_from_job_relay_event_invalid_log() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let log = Log {
            address: H160::from_str(REQ_CHAIN_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256(
                    "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,uint256)",
                )
                .into(),
                H256::from_uint(&U256::from(1)),
            ],
            data: EthBytes::from(vec![0x00]),
            ..Default::default()
        };

        let job = common_chain_client
            .get_job_from_job_relay_event(log, 1 as u8, CHAIN_ID)
            .await;

        // expect an error
        assert_eq!(job.err().unwrap().to_string(), "Error while decoding event");
    }

    #[actix_web::test]
    async fn test_select_gateway_for_job_id() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(common_chain_client.clone(), None).await;

        let req_chain_client = common_chain_client.req_chain_clients[&job.req_chain_id].clone();
        let gateway_address = common_chain_client
            .select_gateway_for_job_id(
                job.clone(),
                job.starttime.as_u64(),
                job.sequence_number,
                req_chain_client,
            )
            .await
            .unwrap();

        assert_eq!(gateway_address, common_chain_client.address);
    }

    #[actix_web::test]
    async fn test_select_gateway_for_job_id_no_cycle_state() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let job = generate_generic_job(None, None).await;

        let req_chain_client = common_chain_client.req_chain_clients[&job.req_chain_id].clone();
        let gateway_address = common_chain_client
            .select_gateway_for_job_id(
                job.clone(),
                job.starttime.as_u64(),
                job.sequence_number,
                req_chain_client,
            )
            .await
            .unwrap();

        assert_eq!(gateway_address, Address::zero());

        let waitlisted_jobs_hashmap = common_chain_client
            .gateway_epoch_state_waitlist
            .read()
            .unwrap()
            .clone();

        let waitlisted_jobs: Vec<Vec<Job>> = waitlisted_jobs_hashmap.values().cloned().collect();

        assert_eq!(waitlisted_jobs.len(), 1);
        assert_eq!(waitlisted_jobs[0].len(), 1);
        assert_eq!(waitlisted_jobs[0][0], job);
    }

    #[actix_web::test]
    async fn test_select_gateway_for_job_id_multiple_gateways() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(common_chain_client.clone(), Some(5)).await;

        let req_chain_client = common_chain_client.req_chain_clients[&job.req_chain_id].clone();
        let gateway_address = common_chain_client
            .select_gateway_for_job_id(
                job.clone(),
                job.starttime.as_u64(),
                job.sequence_number,
                req_chain_client,
            )
            .await
            .unwrap();

        let total_stake = 100 * 5 as u64;
        let seed = job.starttime.as_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        for _ in 0..job.sequence_number - 1 {
            let _ = rng.gen_range(1..=total_stake);
        }
        let random_number = rng.gen_range(1..=total_stake);
        let indx = random_number / 100;
        let expected_gateway_address = common_chain_client
            .gateway_epoch_state
            .read()
            .unwrap()
            .values()
            .nth(0 as usize)
            .unwrap()
            .values()
            .nth(indx as usize)
            .unwrap()
            .address;

        assert_eq!(gateway_address, expected_gateway_address);
    }

    #[actix_web::test]
    async fn test_select_gateway_for_job_id_multiple_gateways_seq_number() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let mut job = generate_generic_job(None, None).await;
        job.sequence_number = 5;

        add_gateway_epoch_state(common_chain_client.clone(), Some(5)).await;

        let req_chain_client = common_chain_client.req_chain_clients[&job.req_chain_id].clone();
        let gateway_address = common_chain_client
            .select_gateway_for_job_id(
                job.clone(),
                job.starttime.as_u64(),
                job.sequence_number,
                req_chain_client,
            )
            .await
            .unwrap();

        let total_stake = 100 * 5 as u64;
        let seed = job.starttime.as_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        for _ in 0..job.sequence_number - 1 {
            let _ = rng.gen_range(1..=total_stake);
        }
        let random_number = rng.gen_range(1..=total_stake);
        let indx = random_number / 100;
        let expected_gateway_address = common_chain_client
            .gateway_epoch_state
            .read()
            .unwrap()
            .values()
            .nth(0 as usize)
            .unwrap()
            .values()
            .nth(indx as usize)
            .unwrap()
            .address;

        assert_eq!(gateway_address, expected_gateway_address);
    }

    #[actix_web::test]
    async fn test_job_placed_handler() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let mut job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(common_chain_client.clone(), None).await;

        let (req_chain_tx, mut com_chain_rx) = channel::<(Job, Arc<CommonChainClient>)>(100);

        let job_clone = job.clone();
        let common_chain_client_clone = common_chain_client.clone();
        task::spawn(async move {
            common_chain_client_clone
                .job_placed_handler(job_clone, req_chain_tx.clone())
                .await;
        });

        while let Some((rx_job, rx_com_chain_client)) = com_chain_rx.recv().await {
            job.gateway_address = Some(common_chain_client.address);
            assert_eq!(rx_job, job);

            assert_eq!(rx_com_chain_client.active_jobs.read().unwrap().len(), 1);
            assert_eq!(
                rx_com_chain_client
                    .active_jobs
                    .read()
                    .unwrap()
                    .get(&job.job_key),
                Some(&rx_job)
            );
            break;
        }
    }

    #[actix_web::test]
    async fn test_job_placed_handler_no_cycle_state() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let job = generate_generic_job(None, None).await;

        let (req_chain_tx, _) = channel::<(Job, Arc<CommonChainClient>)>(100);

        common_chain_client
            .clone()
            .job_placed_handler(job.clone(), req_chain_tx.clone())
            .await;

        let waitlisted_jobs_hashmap = common_chain_client
            .gateway_epoch_state_waitlist
            .read()
            .unwrap()
            .clone();

        let waitlisted_jobs: Vec<Vec<Job>> = waitlisted_jobs_hashmap.values().cloned().collect();

        assert_eq!(waitlisted_jobs.len(), 1);
        assert_eq!(waitlisted_jobs[0].len(), 1);
        assert_eq!(waitlisted_jobs[0][0], job);
    }

    #[actix_web::test]
    async fn test_job_relayed_slash_timer_txn_success() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let mut job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(common_chain_client.clone(), Some(5)).await;
        job.gateway_address = Some(
            common_chain_client
                .gateway_epoch_state
                .read()
                .unwrap()
                .values()
                .nth(0 as usize)
                .unwrap()
                .values()
                .nth(1 as usize)
                .unwrap()
                .address,
        );

        let (req_chain_tx, _com_chain_rx) = channel::<(Job, Arc<CommonChainClient>)>(100);

        let res = common_chain_client
            .job_relayed_slash_timer(job, Some(1 as u64), req_chain_tx)
            .await
            .unwrap();

        assert_eq!(res, 1);
    }

    #[actix_web::test]
    async fn test_job_relayed_slash_timer_txn_fail_retry() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let mut job = generate_generic_job(Some(U256::from(2)), None).await;

        add_gateway_epoch_state(common_chain_client.clone(), Some(5)).await;
        job.gateway_address = Some(
            common_chain_client
                .gateway_epoch_state
                .read()
                .unwrap()
                .values()
                .nth(0 as usize)
                .unwrap()
                .values()
                .nth(1 as usize)
                .unwrap()
                .address,
        );

        let (req_chain_tx, mut com_chain_rx) = channel::<(Job, Arc<CommonChainClient>)>(100);

        let res = common_chain_client
            .clone()
            .job_relayed_slash_timer(job.clone(), Some(1 as u64), req_chain_tx)
            .await
            .unwrap();

        assert_eq!(res, 2);

        while let Some((rx_job, _rx_com_chain_client)) = com_chain_rx.recv().await {
            job.job_type = ComChainJobType::SlashGatewayJob;
            assert_eq!(rx_job, job);
            break;
        }
    }

    #[actix_web::test]
    async fn test_job_relayed_slash_timer_txn_fail_max_retry() {
        let common_chain_client = Arc::from(generate_common_chain_client().await);

        let mut job = generate_generic_job(Some(U256::from(2)), None).await;

        add_gateway_epoch_state(common_chain_client.clone(), Some(5)).await;
        job.gateway_address = Some(
            common_chain_client
                .gateway_epoch_state
                .read()
                .unwrap()
                .values()
                .nth(0 as usize)
                .unwrap()
                .values()
                .nth(1 as usize)
                .unwrap()
                .address,
        );
        job.sequence_number = MAX_GATEWAY_RETRIES;

        let (req_chain_tx, mut com_chain_rx) = channel::<(Job, Arc<CommonChainClient>)>(100);

        let res = common_chain_client
            .clone()
            .job_relayed_slash_timer(job.clone(), Some(1 as u64), req_chain_tx)
            .await
            .unwrap();

        assert_eq!(res, 3);

        while let Some((rx_job, _rx_com_chain_client)) = com_chain_rx.recv().await {
            job.job_type = ComChainJobType::SlashGatewayJob;
            assert_eq!(rx_job, job);

            break;
        }
    }

    // TODO: tests for gateway_epoch_state_service
}
