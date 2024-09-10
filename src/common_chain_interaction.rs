use actix_web::web::Data;
use anyhow::{Context, Result};
use ethers::abi::{decode, ParamType};
use ethers::prelude::*;
use ethers::providers::Provider;
use ethers::types::Address;
use ethers::utils::keccak256;
use futures_core::stream::Stream;
use hex::FromHex;
use log::{error, info};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashSet;
use std::error::Error;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time;

use crate::chain_util::{
    confirm_event, sign_job_response_request, sign_reassign_gateway_relay_request,
    sign_relay_job_request, HttpProvider, HttpProviderLogs, LogsProvider,
};
use crate::common_chain_gateway_state_service::gateway_epoch_state_service;
use crate::constant::{
    COMMON_CHAIN_GATEWAY_REASSIGNED_EVENT, COMMON_CHAIN_GATEWAY_REGISTERED_EVENT,
    COMMON_CHAIN_JOB_RELAYED_EVENT, COMMON_CHAIN_JOB_RESOURCE_UNAVAILABLE_EVENT,
    COMMON_CHAIN_JOB_RESPONDED_EVENT, GATEWAY_BLOCK_STATES_TO_MAINTAIN,
    GATEWAY_STAKE_ADJUSTMENT_FACTOR, MAX_GATEWAY_RETRIES, MIN_GATEWAY_STAKE,
    REQUEST_CHAIN_GATEWAY_REGISTERED_EVENT, REQUEST_CHAIN_JOB_CANCELLED_EVENT,
    REQUEST_CHAIN_JOB_RELAYED_EVENT, REQUEST_CHAIN_JOB_SUBSCRIPTION_JOB_PARAMS_UPDATED_EVENT,
    REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT,
    REQUEST_CHAIN_JOB_SUBSCRIPTION_TERMINATION_PARAMS_UPDATED_EVENT, REQUEST_RELAY_TIMEOUT,
};
use crate::error::ServerlessError;
use crate::job_subscription_management::{
    add_subscription_job, job_subscription_manager, process_historic_job_subscriptions,
    update_subscription_job_params, update_subscription_job_termination_params,
};
use crate::model::{
    AppState, ContractsClient, GatewayData, GatewayJobType, Job, JobMode, JobSubscriptionAction,
    JobSubscriptionChannelType, RegisterType, RegisteredData, RequestChainClient, ResponseJob,
};

impl ContractsClient {
    pub async fn wait_for_registration(self: Arc<Self>, app_state: Data<AppState>) {
        info!("Waiting for registration on the Common Chain and all Request Chains...");
        // create a channel to communicate with the main thread
        let (tx, mut rx) = channel::<RegisteredData>(100);

        let common_chain_block_number = *self.common_chain_start_block_number.lock().unwrap();

        let common_chain_registered_filter = Filter::new()
            .address(self.gateways_contract_address)
            .select(common_chain_block_number..)
            .topic0(vec![keccak256(COMMON_CHAIN_GATEWAY_REGISTERED_EVENT)])
            .topic1(self.enclave_address)
            .topic2(self.enclave_owner);

        let tx_clone = tx.clone();
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            'socket_loop: loop {
                let common_chain_ws_provider =
                    match Provider::<Ws>::connect(&self_clone.common_chain_ws_url).await {
                        Ok(common_chain_ws_provider) => common_chain_ws_provider,
                        Err(err) => {
                            error!(
                                "Failed to connect to the common chain websocket provider: {}",
                                err
                            );
                            continue;
                        }
                    };

                // TODO: an error here can effect can panic the thread. What possible errors are possible?
                let mut common_chain_stream = common_chain_ws_provider
                    .subscribe_logs(&common_chain_registered_filter)
                    .await
                    .context("failed to subscribe to events on the Common Chain")
                    .unwrap();

                while let Some(log) = common_chain_stream.next().await {
                    if log.removed.unwrap_or(true) {
                        continue;
                    }

                    *self_clone.common_chain_start_block_number.lock().unwrap() = log
                        .block_number
                        .unwrap_or(common_chain_block_number.into())
                        .as_u64();

                    let registered_data = RegisteredData {
                        register_type: RegisterType::CommonChain,
                        chain_id: None,
                    };
                    tx_clone.send(registered_data).await.unwrap();

                    info!("Common Chain Registered");
                    break 'socket_loop;
                }
            }
        });

        // listen to all the request chains for the GatewayRegistered event
        for request_chain_client in self.request_chain_clients.values().cloned() {
            let request_chain_registered_filter = Filter::new()
                .address(request_chain_client.relay_address)
                .select(request_chain_client.request_chain_start_block_number..)
                .topic0(vec![keccak256(REQUEST_CHAIN_GATEWAY_REGISTERED_EVENT)])
                .topic1(self.enclave_owner)
                .topic2(self.enclave_address);

            let tx_clone = tx.clone();
            let request_chain_client_clone = request_chain_client.clone();
            tokio::spawn(async move {
                'socket_loop: loop {
                    let request_chain_ws_provider = match Provider::<Ws>::connect(
                        request_chain_client_clone.ws_rpc_url.clone(),
                    )
                    .await
                    {
                        Ok(request_chain_ws_provider) => request_chain_ws_provider,
                        Err(err) => {
                            error!(
                                "Failed to connect to the request chain websocket provider: {}",
                                err
                            );
                            continue;
                        }
                    };

                    // TODO: an error here can effect can panic the thread. What possible errors are possible?
                    let mut request_chain_stream = request_chain_ws_provider
                        .subscribe_logs(&request_chain_registered_filter)
                        .await
                        .context("failed to subscribe to events on the Request Chain")
                        .unwrap();

                    while let Some(log) = request_chain_stream.next().await {
                        let log = confirm_event(
                            log,
                            &request_chain_client_clone.http_rpc_url,
                            request_chain_client_clone.confirmation_blocks,
                            request_chain_client_clone.last_seen_block.clone(),
                        )
                        .await;

                        if log.removed.unwrap_or(true) {
                            continue;
                        }

                        let registered_data = RegisteredData {
                            register_type: RegisterType::RequestChain,
                            chain_id: Some(request_chain_client.chain_id),
                        };
                        tx_clone.send(registered_data).await.unwrap();

                        info!(
                            "Request Chain ID: {:?} Registered",
                            request_chain_client.chain_id
                        );
                        break 'socket_loop;
                    }
                }
            });
        }

        let mut common_chain_registered = false;
        let mut req_chain_ids_not_registered: HashSet<u64> = self
            .request_chain_clients
            .keys()
            .cloned()
            .collect::<HashSet<u64>>();
        while let Some(registered_data) = rx.recv().await {
            match registered_data.register_type {
                RegisterType::CommonChain => {
                    common_chain_registered = true;
                }
                RegisterType::RequestChain => {
                    req_chain_ids_not_registered.remove(&registered_data.chain_id.unwrap());
                }
            }

            if common_chain_registered && req_chain_ids_not_registered.is_empty() {
                // All registration completed on common chain and all request chains
                // Mark registered in the app state
                app_state.registered.store(true, Ordering::SeqCst);
                // Start the ContractsClient service
                tokio::spawn(async move {
                    let _ = self.run().await;
                });
                break;
            }
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        // setup for the listening events on Request Chain and calling Common Chain functions
        let (req_chain_tx, com_chain_rx) = channel::<Job>(100);
        // Start the gateway epoch state service
        {
            let service_start_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let contracts_client_clone = self.clone();
            let tx_clone = req_chain_tx.clone();
            let common_chain_http_url_clone = self.common_chain_http_url.clone();
            tokio::spawn(async move {
                gateway_epoch_state_service(
                    service_start_time,
                    common_chain_http_url_clone,
                    contracts_client_clone,
                    tx_clone,
                )
                .await;
            });
        }

        // Start the job subscription management service
        let (job_subscription_tx, job_subscription_rx) = channel::<JobSubscriptionChannelType>(100);
        {
            let contracts_client_clone = self.clone();
            let req_chain_tx_clone = req_chain_tx.clone();
            let job_subscription_tx_clone = job_subscription_tx.clone();

            tokio::spawn(async move {
                process_historic_job_subscriptions(
                    &contracts_client_clone,
                    req_chain_tx_clone,
                    job_subscription_tx_clone,
                )
                .await;
            });

            let contracts_client_clone = self.clone();
            let req_chain_tx_clone = req_chain_tx.clone();

            tokio::spawn(async move {
                let _ = job_subscription_manager(
                    contracts_client_clone,
                    job_subscription_rx,
                    req_chain_tx_clone,
                )
                .await;
            });
        }

        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            let _ = self_clone.txns_to_common_chain(com_chain_rx).await;
        });
        let _ = &self
            .handle_all_req_chain_events(req_chain_tx.clone(), job_subscription_tx)
            .await?;

        // setup for the listening events on Common Chain and calling Request Chain functions
        let (com_chain_tx, req_chain_rx) = channel::<ResponseJob>(100);
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            let _ = self_clone.txns_to_request_chain(req_chain_rx).await;
        });
        let _ = &self
            .handle_all_common_chain_events(com_chain_tx, req_chain_tx)
            .await;
        Ok(())
    }

    async fn handle_all_req_chain_events(
        self: &Arc<Self>,
        req_chain_tx: Sender<Job>,
        job_subscription_tx: Sender<JobSubscriptionChannelType>,
    ) -> Result<()> {
        info!("Initializing Request Chain Clients for all request chains...");
        let chains_ids = self.request_chain_ids.clone();

        for chain_id in chains_ids {
            let self_clone = Arc::clone(&self);
            let req_chain_tx_clone = req_chain_tx.clone();
            let job_subscription_tx_clone = job_subscription_tx.clone();

            // Spawn a new task for each Request Chain Contract
            tokio::spawn(async move {
                _ = self_clone
                    .handle_single_request_chain_events(
                        req_chain_tx_clone,
                        chain_id,
                        job_subscription_tx_clone,
                    )
                    .await;
            });
        }

        Ok(())
    }

    async fn handle_single_request_chain_events(
        self: &Arc<Self>,
        req_chain_tx: Sender<Job>,
        chain_id: u64,
        job_subscription_tx: Sender<JobSubscriptionChannelType>,
    ) {
        loop {
            let req_chain_ws_client =
                match Provider::<Ws>::connect(&self.request_chain_clients[&chain_id].ws_rpc_url)
                    .await
                {
                    Ok(req_chain_ws_client) => req_chain_ws_client,
                    Err(err) => {
                        error!(
                            "Failed to connect to the request chain websocket provider: {}",
                            err
                        );
                        continue;
                    }
                };

            let mut stream = self
                .req_chain_jobs(&req_chain_ws_client, &self.request_chain_clients[&chain_id])
                .await
                .unwrap();
            while let Some(log) = stream.next().await {
                let ref topics = log.topics;
                if log.removed.unwrap_or(true) {
                    continue;
                }

                if topics[0] == keccak256(REQUEST_CHAIN_JOB_RELAYED_EVENT).into() {
                    info!(
                        "Request Chain ID: {:?}, JobPlace jobID: {:?}",
                        chain_id, log.topics[1]
                    );

                    let self_clone = Arc::clone(&self);
                    let req_chain_tx_clone = req_chain_tx.clone();
                    tokio::spawn(async move {
                        let job = self_clone
                            .get_job_from_job_relay_event(log, 1u8, chain_id)
                            .await;
                        if job.is_ok() {
                            self_clone
                                .job_relayed_handler(job.unwrap(), req_chain_tx_clone.clone())
                                .await;
                        }
                    });
                } else if topics[0] == keccak256(REQUEST_CHAIN_JOB_CANCELLED_EVENT).into() {
                    info!(
                        "Request Chain ID: {:?}, JobCancelled jobID: {:?}",
                        chain_id, log.topics[1]
                    );

                    let self_clone = Arc::clone(&self);
                    tokio::spawn(async move {
                        self_clone
                            .cancel_job_with_job_id(log.topics[1].into_uint())
                            .await;
                    });
                } else if topics[0]
                    == keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT).into()
                {
                    let subscription_id: U256 = log.topics[1].into_uint();

                    info!(
                        "Request Chain ID: {:?}, JobSubscriptionStarted jobID: {:?}",
                        chain_id, subscription_id
                    );

                    let self_clone = Arc::clone(&self);
                    let req_chain_tx_clone = req_chain_tx.clone();
                    let job_subscription_tx_clone = job_subscription_tx.clone();

                    tokio::spawn(async move {
                        let _ = add_subscription_job(
                            &self_clone,
                            log,
                            chain_id,
                            req_chain_tx_clone,
                            false,
                        )
                        .await;
                        job_subscription_tx_clone
                            .send(JobSubscriptionChannelType {
                                subscription_action: JobSubscriptionAction::Add,
                                subscription_id,
                            })
                            .await
                            .unwrap();
                    });
                } else if topics[0]
                    == keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_JOB_PARAMS_UPDATED_EVENT).into()
                {
                    info!(
                        "Request Chain ID: {:?}, JobSubscriptionJobParamsUpdated jobID: {:?}",
                        chain_id, log.topics[1]
                    );

                    let self_clone = Arc::clone(&self);

                    tokio::spawn(async move {
                        let _ = update_subscription_job_params(&self_clone, log);
                    });
                } else if topics[0]
                    == keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_TERMINATION_PARAMS_UPDATED_EVENT)
                        .into()
                {
                    info!(
                        "Request Chain ID: {:?}, JobSubscriptionTerminationParamsUpdated jobID: {:?}",
                        chain_id, log.topics[1]
                    );

                    let self_clone = Arc::clone(&self);
                    tokio::spawn(async move {
                        let _ = update_subscription_job_termination_params(&self_clone, log);
                    });
                } else {
                    error!("Request Chain ID: {:?}, Unknown event: {:?}", chain_id, log);
                }
            }
        }
    }

    async fn get_job_from_job_relay_event(
        self: &Arc<Self>,
        log: Log,
        sequence_number: u8,
        request_chain_id: u64,
    ) -> Result<Job, ServerlessError> {
        let types = vec![
            ParamType::FixedBytes(32),
            ParamType::Bytes,
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Address,
            ParamType::Address,
            ParamType::Uint(256),
            ParamType::Uint(256),
        ];

        let decoded = decode(&types, &log.data.0);
        let decoded = match decoded {
            Ok(decoded) => decoded,
            Err(err) => {
                error!("Error while decoding event: {}", err);
                return Err(ServerlessError::LogDecodeFailure);
            }
        };

        let job_id = log.topics[1].into_uint();

        Ok(Job {
            job_id,
            request_chain_id,
            tx_hash: decoded[0].clone().into_fixed_bytes().unwrap(),
            code_input: decoded[1].clone().into_bytes().unwrap().into(),
            user_timeout: decoded[2].clone().into_uint().unwrap(),
            starttime: decoded[8].clone().into_uint().unwrap(),
            job_owner: log.address,
            job_type: GatewayJobType::JobRelay,
            sequence_number,
            gateway_address: None,
            job_mode: JobMode::Once,
        })
    }

    pub async fn job_relayed_handler(self: Arc<Self>, mut job: Job, tx: Sender<Job>) {
        let gateway_address = self
            .select_gateway_for_job_id(
                job.clone(),
                job.starttime.as_u64(), // TODO: Update seed
                job.sequence_number,
            )
            .await;

        // if error message is returned, then the job is older than the maintained block states
        match gateway_address {
            Ok(gateway_address) => {
                job.gateway_address = Some(gateway_address);

                if gateway_address == Address::zero() {
                    return;
                }

                if gateway_address == self.enclave_address {
                    // scope for the write lock
                    {
                        self.active_jobs
                            .write()
                            .unwrap()
                            .insert(job.job_id, job.clone());
                    }
                    tx.send(job).await.unwrap();
                } else {
                    // scope for the write lock
                    {
                        self.current_jobs
                            .write()
                            .unwrap()
                            .insert(job.job_id, job.clone());
                    }
                    let self_clone = Arc::clone(&self);
                    tokio::spawn(async move {
                        let common_chain_http_provider =
                            HttpProvider::new(self_clone.common_chain_http_url.clone());
                        self_clone
                            .job_relayed_slash_timer(job, None, tx, &common_chain_http_provider)
                            .await;
                    });
                }
            }
            Err(err) => {
                error!(
                    "Job Id: {}, Error while selecting gateway: {}",
                    job.job_id, err
                );
            }
        }
    }

    async fn job_relayed_slash_timer<'a, P: HttpProviderLogs>(
        self: Arc<Self>,
        job: Job,
        mut job_timeout: Option<u64>,
        tx: Sender<Job>,
        common_chain_http_provider: &'a P,
    ) {
        if job_timeout.is_none() {
            job_timeout = Some(REQUEST_RELAY_TIMEOUT);
        }
        time::sleep(Duration::from_secs(job_timeout.unwrap())).await;

        // TODO: Issue with event logs -
        // get_logs might not provide the latest logs for the latest block
        // SOLUTION 1 - Wait for the next block.
        //          Problem: Extra time spent here waiting.

        let logs = self
            .gateways_job_relayed_logs(job.clone(), common_chain_http_provider)
            .await
            .context("Failed to get logs")
            .unwrap();

        for log in logs {
            let ref topics = log.topics;
            if topics[0] == keccak256(COMMON_CHAIN_JOB_RELAYED_EVENT).into() {
                let decoded = decode(
                    &vec![ParamType::Uint(256), ParamType::Address, ParamType::Address],
                    &log.data.0,
                )
                .unwrap();

                let job_id = log.topics[1].into_uint();
                let job_owner = decoded[1].clone().into_address().unwrap();
                let gateway_operator = decoded[2].clone().into_address().unwrap();

                if job_id == job.job_id
                    && job_owner == job.job_owner
                    && gateway_operator != Address::zero()
                    && gateway_operator == job.gateway_address.unwrap()
                {
                    info!(
                        "Job ID: {:?}, JobRelayed event triggered for job ID: {:?}",
                        job.job_id, job_id
                    );
                    // scope for the write lock
                    {
                        let _ = self.current_jobs.write().unwrap().remove(&job.job_id);
                    }
                    return;
                }
            }
        }

        info!("Job ID: {:?}, JobRelayed event not triggered", job.job_id);

        // slash the previous gateway
        let mut job_clone = job.clone();
        job_clone.job_type = GatewayJobType::SlashGatewayJob;
        tx.send(job_clone).await.unwrap();
    }

    async fn select_gateway_for_job_id(
        self: &Arc<Self>,
        job: Job,
        seed: u64,
        skips: u8,
    ) -> Result<Address, ServerlessError> {
        let job_cycle =
            (job.starttime.as_u64() - self.epoch - self.offset_for_epoch) / self.time_interval;

        let all_gateways_data: Vec<GatewayData>;

        {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let current_cycle = (ts - self.epoch - self.offset_for_epoch) / self.time_interval;
            if current_cycle >= GATEWAY_BLOCK_STATES_TO_MAINTAIN + job_cycle {
                return Err(ServerlessError::JobOlderThanMaintainedBlockStates);
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

        if all_gateways_data.is_empty() {
            return Err(ServerlessError::NoGatewaysRegisteredInCycle(job_cycle));
        }

        // create a weighted probability distribution for gateways based on stake amount
        // For example, if there are 3 gateways with stake amounts 100, 200, 300
        // then the distribution array will be [100, 300, 600]
        let mut stake_distribution: Vec<u128> = vec![];
        let mut total_stake: u128 = 0;
        let mut gateway_addresses_of_req_chain: Vec<H160> = vec![];

        for gateway_data in all_gateways_data.iter() {
            if gateway_data.req_chain_ids.contains(&job.request_chain_id)
                && gateway_data.stake_amount > *MIN_GATEWAY_STAKE
                && gateway_data.draining == false
            {
                gateway_addresses_of_req_chain.push(gateway_data.address.clone());
                total_stake +=
                    (gateway_data.stake_amount / *GATEWAY_STAKE_ADJUSTMENT_FACTOR).as_u128();
                stake_distribution.push(total_stake);
            }
        }

        if total_stake == 0 {
            return Err(ServerlessError::NoValidGatewaysForChain(
                job_cycle,
                job.request_chain_id,
            ));
        }

        // random number between 1 to total_stake from the seed for the weighted random selection.
        // use this seed in std_rng to generate a random number between 1 to total_stake
        // skipping skips numbers from the random number generated
        // skips comes from sequence_number of the job which starts from 1. That's why its (skips-1)
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
        let selected_gateway_address = gateway_addresses_of_req_chain[index];

        info!(
            "Job ID: {:?}, Gateway Address: {:?}",
            job.job_id, selected_gateway_address
        );

        Ok(selected_gateway_address)
    }

    async fn cancel_job_with_job_id(self: Arc<Self>, job_id: U256) {
        info!(
            "Remove the Job ID: {:} from the active and current jobs list",
            job_id
        );

        let job: Option<Job> = self.active_jobs.write().unwrap().remove(&job_id);

        if job.is_none() {
            let _job: Option<Job> = self.current_jobs.write().unwrap().remove(&job_id);
            if _job.is_some() {
                info!("Job ID: {:?} removed from current jobs", job_id);
            }
        } else {
            info!("Job ID: {:?} removed from active jobs", job_id);
        }
    }

    async fn txns_to_common_chain(self: Arc<Self>, mut rx: Receiver<Job>) {
        while let Some(job) = rx.recv().await {
            match job.job_type {
                GatewayJobType::JobRelay => {
                    self.relay_job_txn(job).await;
                }
                GatewayJobType::SlashGatewayJob => {
                    self.reassign_gateway_relay_txn(job).await;
                }
                _ => {
                    error!("Unknown job type: {:?}", job.job_type);
                }
            }
        }
    }

    async fn relay_job_txn(self: &Arc<Self>, job: Job) {
        info!("Creating a transaction for relayJob");
        let (signature, sign_timestamp) = sign_relay_job_request(
            &self.enclave_signer_key,
            job.job_id,
            &job.tx_hash,
            &job.code_input,
            job.user_timeout,
            job.starttime,
            job.sequence_number,
            &job.job_owner,
        )
        .await
        .unwrap();
        let Ok(signature) = types::Bytes::from_hex(signature) else {
            error!("Failed to decode signature hex string");
            return;
        };
        let tx_hash: [u8; 32] = job.tx_hash[..].try_into().unwrap();

        let txn = self.gateway_jobs_contract.read().unwrap().relay_job(
            signature,
            job.job_id,
            tx_hash,
            job.code_input,
            job.user_timeout,
            job.starttime,
            job.sequence_number,
            job.job_owner,
            sign_timestamp.into(),
        );

        for i in 0..3 {
            let pending_txn = txn.send().await;
            let Ok(pending_txn) = pending_txn else {
                let err = pending_txn.unwrap_err();

                let err_string = format!("{:#?}", err);
                if err_string.contains("code: -32000") && err_string.contains("nonce") {
                    // Handle the specific error case
                    error!("Error: Nonce Error - {}. Retrying - {} of 3", err, i);
                    continue;
                }
                error!(
                    "Failed to submit transaction {} for job relay to CommonChain",
                    err
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
            return;
        }
    }

    async fn reassign_gateway_relay_txn(self: &Arc<Self>, job: Job) {
        info!("Creating a transaction for reassignGatewayRelay");
        let (signature, sign_timestamp) = sign_reassign_gateway_relay_request(
            &self.enclave_signer_key,
            job.job_id,
            job.gateway_address.as_ref().unwrap(),
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

        let txn = self
            .gateway_jobs_contract
            .read()
            .unwrap()
            .reassign_gateway_relay(
                job.gateway_address.unwrap(),
                job.job_id,
                signature,
                job.sequence_number,
                job.starttime,
                job.job_owner,
                sign_timestamp.into(),
            );

        for i in 0..3 {
            let pending_txn = txn.send().await;
            let Ok(pending_txn) = pending_txn else {
                let err = pending_txn.unwrap_err();

                let err_string = format!("{:#?}", err);
                if err_string.contains("code: -32000") && err_string.contains("nonce") {
                    // Handle the specific error case
                    error!("Error: Nonce Error - {}. Retrying - {} of 3", err, i);
                    continue;
                }

                error!(
                    "Failed to submit transaction {} for reassign gateway relay to CommonChain",
                    err
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
            return;
        }
    }

    async fn handle_all_common_chain_events(
        self: &Arc<Self>,
        com_chain_tx: Sender<ResponseJob>,
        req_chain_tx: Sender<Job>,
    ) {
        loop {
            let common_chain_ws_provider =
                match Provider::<Ws>::connect(&self.common_chain_ws_url).await {
                    Ok(common_chain_ws_provider) => common_chain_ws_provider,
                    Err(err) => {
                        error!(
                            "Failed to connect to the common chain websocket provider: {}",
                            err
                        );
                        continue;
                    }
                };
            let mut stream = self
                .common_chain_jobs(&common_chain_ws_provider)
                .await
                .unwrap();

            while let Some(log) = stream.next().await {
                let ref topics = log.topics;

                if topics[0] == keccak256(COMMON_CHAIN_JOB_RESPONDED_EVENT).into() {
                    info!(
                        "JobResponded event triggered for Job ID: {:?}",
                        log.topics[1]
                    );
                    let self_clone = Arc::clone(&self);
                    let com_chain_tx = com_chain_tx.clone();
                    tokio::spawn(async move {
                        let response_job_result =
                            self_clone.get_job_from_job_responded_event(log).await;
                        match response_job_result {
                            Ok(response_job) => {
                                self_clone
                                    .job_responded_handler(response_job, com_chain_tx)
                                    .await;
                            }
                            Err(ServerlessError::JobDoesNotBelongToEnclave) => {
                                info!("Job does not belong to the enclave");
                            }
                            Err(err) => {
                                error!("Error while getting job from JobResponded event: {}", err);
                            }
                        }
                    });
                } else if topics[0] == keccak256(COMMON_CHAIN_JOB_RESOURCE_UNAVAILABLE_EVENT).into()
                {
                    info!("JobResourceUnavailable event triggered");
                    let self_clone = Arc::clone(&self);
                    tokio::spawn(async move {
                        self_clone.job_resource_unavailable_handler(log).await;
                    });
                } else if topics[0] == keccak256(COMMON_CHAIN_GATEWAY_REASSIGNED_EVENT).into() {
                    info!("GatewayReassigned for Job ID: {:?}", log.topics[1]);
                    let self_clone = Arc::clone(&self);
                    let req_chain_tx = req_chain_tx.clone();
                    tokio::spawn(async move {
                        self_clone
                            .gateway_reassigned_handler(log, req_chain_tx)
                            .await;
                    });
                } else {
                    error!("Unknown event: {:?}", log);
                }
            }
        }
    }

    async fn get_job_from_job_responded_event(
        self: &Arc<Self>,
        log: Log,
    ) -> Result<ResponseJob, ServerlessError> {
        let job_id = log.topics[1].into_uint();

        // Check if job belongs to the enclave
        let active_jobs = self.active_jobs.read().unwrap();
        let job = active_jobs.get(&job_id);
        if job.is_none() {
            return Err(ServerlessError::JobDoesNotBelongToEnclave);
        }

        let job = job.unwrap();

        let types = vec![ParamType::Bytes, ParamType::Uint(256), ParamType::Uint(8)];

        let decoded = decode(&types, &log.data.0);
        let decoded = match decoded {
            Ok(decoded) => decoded,
            Err(err) => {
                error!("Error while decoding event: {}", err);
                return Err(ServerlessError::LogDecodeFailure);
            }
        };
        let request_chain_id = job.request_chain_id;
        let job_mode = job.job_mode;

        Ok(ResponseJob {
            job_id,
            request_chain_id,
            output: decoded[0].clone().into_bytes().unwrap().into(),
            total_time: decoded[1].clone().into_uint().unwrap(),
            error_code: decoded[2].clone().into_uint().unwrap().low_u64() as u8,
            job_type: GatewayJobType::JobResponded,
            gateway_address: None,
            job_mode,
            // sequence_number: 1,
        })
    }

    async fn job_responded_handler(
        self: Arc<Self>,
        mut response_job: ResponseJob,
        tx: Sender<ResponseJob>,
    ) {
        let job: Option<Job>;
        // scope for the read lock
        {
            job = self
                .active_jobs
                .read()
                .unwrap()
                .get(&response_job.job_id)
                .cloned();
        }
        if job.is_some() {
            let job = job.unwrap();
            response_job.gateway_address = job.gateway_address;
            self.remove_job(job).await;

            // Currently, slashing is not implemented for the JobResponded event
            // } else if response_job.sequence_number > 1 {
            //     let gateway_address: Address;
            //     // let seed be absolute difference between (job_id and request_chain_id) + total_time
            //     let seed = {
            //         let job_id_req_chain_id = match response_job
            //             .job_id
            //             .as_u64()
            //             .checked_sub(response_job.request_chain_id)
            //         {
            //             Some(val) => val,
            //             None => response_job.request_chain_id - response_job.job_id.as_u64(),
            //         };
            //         job_id_req_chain_id + response_job.total_time.as_u64()
            //     };
            //     gateway_address = self
            //         .select_gateway_for_job_id(
            //             response_job.job_id.clone(),
            //             seed,
            //             response_job.sequence_number,
            //         )
            //         .await
            //         .context("Failed to select a gateway for the job")
            //         .unwrap();
            //     response_job.gateway_address = Some(gateway_address);
            // }
            // if response_job.gateway_address.unwrap() == self.enclave_address {
            tx.send(response_job).await.unwrap();
            // } else {
            //     self.job_responded_slash_timer(response_job.clone(), tx.clone())
            //         .await
            //         .unwrap();
        }
    }

    async fn remove_job(self: &Arc<Self>, job: Job) {
        let mut active_jobs = self.active_jobs.write().unwrap();
        // The retry number check is to make sure we are removing the correct job from the active jobs list
        // In a case where this txn took longer than the REQUEST_RELAY_TIMEOUT, the job might have been retried
        // and the active_jobs list might have the same job_id with a different retry number.
        if active_jobs.contains_key(&job.job_id)
            && active_jobs[&job.job_id].sequence_number == job.sequence_number
        {
            active_jobs.remove(&job.job_id);
        }
    }

    // TODO: Discuss with the team about the implementation of slashing for the JobResponded event
    // Currently, slashing is not implemented for the JobResponded event
    // async fn job_responded_slash_timer(
    //     self: &Arc<Self>,
    //     mut response_job: ResponseJob,
    //     tx: Sender<ResponseJob>,
    // ) -> Result<()> {
    //     time::sleep(Duration::from_secs(RESPONSE_RELAY_TIMEOUT)).await;
    //     // get request chain client
    //     let req_chain_client =
    //         &self.request_chain_clients[&response_job.request_chain_id.to_string()];
    //     let onchain_response_job = req_chain_client
    //         .contract
    //         .jobs(response_job.job_id)
    //         .await
    //         .unwrap();
    //     let output_received: bool = onchain_response_job.8;
    //     let onchain_response_job: ResponseJob = ResponseJob {
    //         job_id: response_job.job_id,
    //         request_chain_id: response_job.request_chain_id,
    //         output: Bytes::default().into(),
    //         total_time: U256::zero(),
    //         error_code: 0,
    //         output_count: 0,
    //         job_type: GatewayJobType::JobResponded,
    //         gateway_address: Some(onchain_response_job.7),
    //         // depending on how the gateway is reassigned, the retry number might be different
    //         // can be added to event and a check below in the if condition
    //         // if retry number is added to the event,
    //         // remove_response_job_from_active_jobs needs to be updated accordingly
    //         sequence_number: 1,
    //     };
    //     // if output is received and the gateway is the same as the one assigned by the common chain
    //     // then the job is relayed
    //     // sequence_number check is missing
    //     if output_received && onchain_response_job.gateway_address.unwrap() != H160::zero() {
    //         info!(
    //             "Job ID: {:?}, JobResponded event triggered",
    //             response_job.job_id
    //         );
    //         return Ok(());
    //     }
    //     // TODO: how to slash the gateway now?
    //     // The same function used with the JobRelayed event won't work here.
    //     // For now, use the same function.
    //     {
    //         let mut response_job_clone = response_job.clone();
    //         response_job_clone.job_type = GatewayJobType::SlashGatewayResponse;
    //         let tx_clone = tx.clone();
    //         tx_clone
    //             .send(response_job_clone)
    //             .await
    //             .unwrap();
    //     }
    //     response_job.sequence_number += 1;
    //     if response_job.sequence_number > MAX_GATEWAY_RETRIES {
    //         info!("Job ID: {:?}, Max retries reached", response_job.job_id);
    //         return Ok(());
    //     }
    //     // If gateway is already set, job_responded_handler will reassign the gateway
    //     response_job.gateway_address = onchain_response_job.gateway_address;
    //     self.job_responded_handler(response_job, tx).await;
    //     Ok(())
    // }

    async fn job_resource_unavailable_handler(self: Arc<Self>, log: Log) {
        let job_id = log.topics[1].into_uint();

        self.cancel_job_with_job_id(job_id).await;
    }

    async fn gateway_reassigned_handler(self: Arc<Self>, log: Log, req_chain_tx: Sender<Job>) {
        let job_id = log.topics[1].into_uint();

        let types = vec![ParamType::Address, ParamType::Address, ParamType::Uint(8)];
        let decoded = decode(&types, &log.data.0).unwrap();

        let old_gateway = decoded[0].clone().into_address().unwrap();
        let sequence_number = decoded[2].clone().into_uint().unwrap().low_u64() as u8;

        let mut job: Job;

        if old_gateway == self.enclave_address {
            let active_jobs_guard = self.active_jobs.read().unwrap();
            let active_job = active_jobs_guard.get(&job_id);
            if active_job.is_some() {
                job = active_job.unwrap().clone();
                drop(active_jobs_guard);
            } else {
                return;
            }
        } else {
            let current_jobs_guard = self.current_jobs.read().unwrap();
            let current_job = current_jobs_guard.get(&job_id);
            if current_job.is_some() {
                job = current_job.unwrap().clone();
                drop(current_jobs_guard);
            } else {
                return;
            }
        }

        if job.sequence_number != sequence_number {
            return;
        }

        self.clone().cancel_job_with_job_id(job_id).await;

        job.sequence_number += 1;
        if job.sequence_number > MAX_GATEWAY_RETRIES {
            info!("Job ID: {:?}, Max retries reached", job.job_id);
            return;
        }
        job.gateway_address = None;

        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            self_clone.job_relayed_handler(job, req_chain_tx).await;
        });
    }

    async fn txns_to_request_chain(self: Arc<Self>, mut rx: Receiver<ResponseJob>) -> Result<()> {
        while let Some(response_job) = rx.recv().await {
            match response_job.job_type {
                GatewayJobType::JobResponded => {
                    let response_job_job_id = response_job.job_id.clone();
                    self.job_response_txn(response_job).await;
                    self.remove_response_job_from_active_jobs(response_job_job_id)
                        .await;
                }
                // Currently, slashing is not implemented for the JobResponded event
                // GatewayJobType::SlashGatewayResponse => {
                //     self.reassign_gateway_response_txn(response_job)
                //         .await;
                // }

                // Ignore other types of jobs
                _ => {
                    error!("Unknown job type: {:?}", response_job.job_type);
                }
            }
        }
        Ok(())
    }

    async fn job_response_txn(self: &Arc<Self>, response_job: ResponseJob) {
        info!("Creating a transaction for jobResponse");

        let response_job_id = response_job.job_id;

        let req_chain_client = &self.request_chain_clients[&response_job.request_chain_id];

        let (signature, sign_timestamp) = sign_job_response_request(
            &self.enclave_signer_key,
            response_job_id,
            response_job.output.clone(),
            response_job.total_time,
            response_job.error_code,
            response_job.job_mode,
        )
        .await
        .unwrap();
        let Ok(signature) = types::Bytes::from_hex(signature) else {
            error!("Failed to decode signature hex string");
            return;
        };

        let txn;
        if response_job.job_mode == JobMode::Once {
            txn = req_chain_client
                .relay_contract
                .read()
                .unwrap()
                .job_response(
                    signature,
                    response_job_id,
                    response_job.output,
                    response_job.total_time,
                    response_job.error_code,
                    sign_timestamp.into(),
                );
        } else {
            txn = req_chain_client
                .relay_subscriptions_contract
                .read()
                .unwrap()
                .job_subs_response(
                    signature,
                    response_job_id,
                    response_job.output,
                    response_job.total_time,
                    response_job.error_code,
                    sign_timestamp.into(),
                );
        }

        for i in 0..3 {
            let pending_txn = txn.send().await;
            let Ok(pending_txn) = pending_txn else {
                let err = pending_txn.unwrap_err();

                let err_string = format!("{:#?}", err);
                if err_string.contains("code: -32000") && err_string.contains("nonce") {
                    // Handle the specific error case
                    error!(
                        "Error: Transaction nonce too low. {}. Retrying - {} of 3",
                        err, i
                    );
                    continue;
                }

                error!(
                    "Failed to submit transaction {} for job response to RequestChain",
                    err
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
            return;
        }
    }

    async fn remove_response_job_from_active_jobs(self: &Arc<Self>, job_id: U256) {
        let mut active_jobs = self.active_jobs.write().unwrap();
        active_jobs.remove(&job_id);
    }
}

impl LogsProvider for ContractsClient {
    async fn common_chain_jobs<'a>(
        &'a self,
        common_chain_ws_provider: &'a Provider<Ws>,
    ) -> Result<SubscriptionStream<'a, Ws, Log>> {
        info!("Subscribing to events for Common Chain");

        let common_chain_start_block_number =
            self.common_chain_start_block_number.lock().unwrap().clone();
        let event_filter: Filter = Filter::new()
            .address(self.gateway_jobs_contract.read().unwrap().address())
            .select(common_chain_start_block_number..)
            .topic0(vec![
                keccak256(COMMON_CHAIN_JOB_RESPONDED_EVENT),
                keccak256(COMMON_CHAIN_JOB_RESOURCE_UNAVAILABLE_EVENT),
                keccak256(COMMON_CHAIN_GATEWAY_REASSIGNED_EVENT),
            ]);

        let stream = common_chain_ws_provider
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
    ) -> Result<impl Stream<Item = Log> + Unpin> {
        info!(
            "Subscribing to events for Req Chain chain_id: {}",
            req_chain_client.chain_id
        );
        let event_filter = Filter::new()
            .address(vec![
                req_chain_client.relay_address,
                req_chain_client.relay_subscriptions_address,
            ])
            .select(req_chain_client.request_chain_start_block_number..)
            .topic0(vec![
                keccak256(REQUEST_CHAIN_JOB_RELAYED_EVENT),
                keccak256(REQUEST_CHAIN_JOB_CANCELLED_EVENT),
                keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT),
                keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_JOB_PARAMS_UPDATED_EVENT),
                keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_TERMINATION_PARAMS_UPDATED_EVENT),
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

        let stream = stream
            .then(|log| {
                confirm_event(
                    log,
                    &req_chain_client.http_rpc_url,
                    req_chain_client.confirmation_blocks,
                    req_chain_client.last_seen_block.clone(),
                )
            })
            .boxed();
        Ok(stream)
    }

    async fn gateways_job_relayed_logs<'a, P: HttpProviderLogs>(
        &'a self,
        job: Job,
        common_chain_http_provider: &'a P,
    ) -> Result<Vec<Log>> {
        let common_chain_start_block_number =
            self.common_chain_start_block_number.lock().unwrap().clone();

        let job_relayed_event_filter = Filter::new()
            .address(self.gateway_jobs_contract.read().unwrap().address())
            .select(common_chain_start_block_number..)
            .topic0(vec![keccak256(COMMON_CHAIN_JOB_RELAYED_EVENT)])
            .topic1(job.job_id);

        let logs = common_chain_http_provider
            .get_logs(&job_relayed_event_filter)
            .await
            .unwrap();

        Ok(logs)
    }

    async fn request_chain_historic_subscription_jobs<'a, P: HttpProviderLogs>(
        &'a self,
        req_chain_client: &'a RequestChainClient,
        http_provider: &'a P,
    ) -> Result<Vec<Log>> {
        let event_filter = Filter::new()
            .address(req_chain_client.relay_subscriptions_address)
            .select(..req_chain_client.request_chain_start_block_number - 1)
            .topic0(vec![
                keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_STARTED_EVENT),
                keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_JOB_PARAMS_UPDATED_EVENT),
                keccak256(REQUEST_CHAIN_JOB_SUBSCRIPTION_TERMINATION_PARAMS_UPDATED_EVENT),
            ]);

        let logs = http_provider.get_logs(&event_filter).await.unwrap();
        Ok(logs)
    }
}

#[cfg(test)]
mod common_chain_interaction_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::str::FromStr;

    use abi::{encode, Token};
    use ethers::types::{Address, Bytes as EthBytes, H160};
    use serde_json::json;

    use crate::test_util::{
        generate_contracts_client, MockHttpProvider, CHAIN_ID, GATEWAY_JOBS_CONTRACT_ADDR,
        RELAY_CONTRACT_ADDR,
    };

    use super::*;

    async fn add_gateway_epoch_state(
        contracts_client: Arc<ContractsClient>,
        num: Option<u64>,
        add_self: Option<bool>,
    ) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current_cycle = (ts - contracts_client.epoch - contracts_client.offset_for_epoch)
            / contracts_client.time_interval;

        let add_self = add_self.unwrap_or(true);

        let mut gateway_epoch_state_guard = contracts_client.gateway_epoch_state.write().unwrap();

        let mut num = num.unwrap_or(1);

        if add_self {
            gateway_epoch_state_guard
                .entry(current_cycle)
                .or_insert(BTreeMap::new())
                .insert(
                    contracts_client.enclave_address,
                    GatewayData {
                        last_block_number: 5600 as u64,
                        address: contracts_client.enclave_address,
                        stake_amount: U256::from(2) * (*MIN_GATEWAY_STAKE),
                        req_chain_ids: BTreeSet::from([CHAIN_ID]),
                        draining: false,
                    },
                );

            num -= 1;
        }

        for _ in 0..num {
            gateway_epoch_state_guard
                .entry(current_cycle)
                .or_insert(BTreeMap::new())
                .insert(
                    Address::random(),
                    GatewayData {
                        last_block_number: 5600 as u64,
                        address: Address::random(),
                        stake_amount: U256::from(2) * (*MIN_GATEWAY_STAKE),
                        req_chain_ids: BTreeSet::from([CHAIN_ID]),
                        draining: false,
                    },
                );
        }
    }

    async fn generate_job_relayed_log(job_id: Option<U256>, job_starttime: u64) -> Log {
        let job_id = job_id.unwrap_or(U256::from(1));

        Log {
            address: H160::from_str(RELAY_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256(REQUEST_CHAIN_JOB_RELAYED_EVENT).into(),
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
                Token::Address(Address::random()),
                Token::Address(Address::random()),
                Token::Uint(U256::from(job_starttime)),
                Token::Uint(1.into()),
            ])
            .into(),
            ..Default::default()
        }
    }

    async fn generate_job_responded_log(job_id: Option<U256>) -> Log {
        let job_id = job_id.unwrap_or(U256::from(1));

        Log {
            address: H160::from_str(GATEWAY_JOBS_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256(COMMON_CHAIN_JOB_RESPONDED_EVENT).into(),
                H256::from_uint(&job_id),
            ],
            data: encode(&[
                Token::Bytes([].into()),
                Token::Uint(U256::from(1000)),
                Token::Uint((0 as u8).into()),
            ])
            .into(),
            ..Default::default()
        }
    }

    async fn generate_generic_job(job_id: Option<U256>, job_starttime: Option<u64>) -> Job {
        let job_id = job_id.unwrap_or(U256::from(1));

        Job {
            job_id,
            request_chain_id: CHAIN_ID,
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
            job_owner: H160::from_str(RELAY_CONTRACT_ADDR).unwrap(),
            job_type: GatewayJobType::JobRelay,
            sequence_number: 1 as u8,
            gateway_address: None,
            job_mode: JobMode::Once,
        }
    }

    async fn generate_generic_response_job(job_id: Option<U256>) -> ResponseJob {
        let job_id = job_id.unwrap_or(U256::from(1));

        ResponseJob {
            job_id,
            request_chain_id: CHAIN_ID,
            output: Bytes::default(),
            total_time: U256::from(1000),
            error_code: 0 as u8,
            job_type: GatewayJobType::JobResponded,
            gateway_address: None,
            job_mode: JobMode::Once,
        }
    }

    #[tokio::test]
    async fn test_get_job_from_job_relay_event() {
        let contracts_client = generate_contracts_client().await;

        let job_starttime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let log = generate_job_relayed_log(None, job_starttime).await;

        let expected_job = generate_generic_job(None, Some(job_starttime)).await;

        let job = contracts_client
            .get_job_from_job_relay_event(log, 1 as u8, CHAIN_ID)
            .await
            .unwrap();

        assert_eq!(job, expected_job);
    }

    #[tokio::test]
    async fn test_get_job_from_job_relay_event_invalid_log() {
        let contracts_client = generate_contracts_client().await;

        let log = Log {
            address: H160::from_str(RELAY_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256(REQUEST_CHAIN_JOB_RELAYED_EVENT).into(),
                H256::from_uint(&U256::from(1)),
            ],
            data: EthBytes::from(vec![0x00]),
            ..Default::default()
        };

        let job = contracts_client
            .get_job_from_job_relay_event(log, 1 as u8, CHAIN_ID)
            .await;

        // expect an error
        assert_eq!(job.err().unwrap(), ServerlessError::LogDecodeFailure);
    }

    #[tokio::test]
    async fn test_select_gateway_for_job_id() {
        let contracts_client = generate_contracts_client().await;

        let job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(contracts_client.clone(), None, None).await;

        let gateway_address = contracts_client
            .select_gateway_for_job_id(job.clone(), job.starttime.as_u64(), job.sequence_number)
            .await
            .unwrap();

        assert_eq!(gateway_address, contracts_client.enclave_address);
    }

    #[tokio::test]
    async fn test_select_gateway_for_job_id_no_cycle_state() {
        let contracts_client = generate_contracts_client().await;

        let job = generate_generic_job(None, None).await;

        let gateway_address = contracts_client
            .select_gateway_for_job_id(job.clone(), job.starttime.as_u64(), job.sequence_number)
            .await
            .unwrap();

        assert_eq!(gateway_address, Address::zero());

        let waitlisted_jobs_hashmap = contracts_client
            .gateway_epoch_state_waitlist
            .read()
            .unwrap()
            .clone();

        let waitlisted_jobs: Vec<Vec<Job>> = waitlisted_jobs_hashmap.values().cloned().collect();

        assert_eq!(waitlisted_jobs.len(), 1);
        assert_eq!(waitlisted_jobs[0].len(), 1);
        assert_eq!(waitlisted_jobs[0][0], job);
    }

    #[tokio::test]
    async fn test_select_gateway_for_job_id_multiple_gateways() {
        let contracts_client = generate_contracts_client().await;

        let job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(contracts_client.clone(), Some(5), None).await;

        let gateway_address = contracts_client
            .select_gateway_for_job_id(job.clone(), job.starttime.as_u64(), job.sequence_number)
            .await
            .unwrap();

        let each_gateway_stake =
            (U256::from(2) * (*MIN_GATEWAY_STAKE)) / *GATEWAY_STAKE_ADJUSTMENT_FACTOR;
        let total_stake = (each_gateway_stake * U256::from(5)).as_u128();
        let seed = job.starttime.as_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        for _ in 0..job.sequence_number - 1 {
            let _ = rng.gen_range(1..=total_stake);
        }
        let random_number = rng.gen_range(1..=total_stake);
        let indx = random_number / each_gateway_stake.as_u128();
        let expected_gateway_address = contracts_client
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

    #[tokio::test]
    async fn test_select_gateway_for_job_id_multiple_gateways_seq_number() {
        let contracts_client = generate_contracts_client().await;

        let mut job = generate_generic_job(None, None).await;
        job.sequence_number = 5;

        add_gateway_epoch_state(contracts_client.clone(), Some(5), None).await;

        let gateway_address = contracts_client
            .select_gateway_for_job_id(job.clone(), job.starttime.as_u64(), job.sequence_number)
            .await
            .unwrap();

        let each_gateway_stake =
            (U256::from(2) * (*MIN_GATEWAY_STAKE)) / *GATEWAY_STAKE_ADJUSTMENT_FACTOR;
        let total_stake = (each_gateway_stake * U256::from(5)).as_u128();
        let seed = job.starttime.as_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        for _ in 0..job.sequence_number - 1 {
            let _ = rng.gen_range(1..=total_stake);
        }
        let random_number = rng.gen_range(1..=total_stake);
        let indx = random_number / each_gateway_stake.as_u128();
        let expected_gateway_address = contracts_client
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

    // TODO: Add select gateway for job id test - Error cases

    #[tokio::test]
    async fn test_job_relayed_handler() {
        let contracts_client = generate_contracts_client().await;

        let mut job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(contracts_client.clone(), None, None).await;

        let (req_chain_tx, mut com_chain_rx) = channel::<Job>(100);

        let job_clone = job.clone();
        let contracts_client_clone = contracts_client.clone();
        tokio::spawn(async move {
            contracts_client_clone
                .job_relayed_handler(job_clone, req_chain_tx.clone())
                .await
        });

        if let Some(rx_job) = com_chain_rx.recv().await {
            job.gateway_address = Some(contracts_client.enclave_address);
            assert_eq!(rx_job, job);

            assert_eq!(contracts_client.active_jobs.read().unwrap().len(), 1);
            assert_eq!(
                contracts_client
                    .active_jobs
                    .read()
                    .unwrap()
                    .get(&job.job_id),
                Some(&rx_job)
            );

            assert_eq!(
                contracts_client
                    .gateway_epoch_state_waitlist
                    .read()
                    .unwrap()
                    .len(),
                0
            );
        } else {
            assert!(false);
        }

        assert!(com_chain_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_job_relayed_handler_selected_gateway_not_self() {
        let contracts_client = generate_contracts_client().await;

        let job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(contracts_client.clone(), Some(4), Some(false)).await;

        let (req_chain_tx, _com_chain_rx) = channel::<Job>(100);

        let job_clone = job.clone();
        let contracts_client_clone = contracts_client.clone();

        contracts_client_clone
            .job_relayed_handler(job_clone, req_chain_tx.clone())
            .await;

        assert_eq!(
            contracts_client
                .active_jobs
                .read()
                .unwrap()
                .get(&job.job_id),
            None
        );

        let current_jobs_guard = contracts_client.current_jobs.read().unwrap();
        let current_job = current_jobs_guard.get(&job.job_id);

        assert!(current_job.is_some());

        let current_job = current_job.unwrap().clone();
        drop(current_jobs_guard);

        assert_eq!(current_job.job_id, job.job_id);
        assert_eq!(current_job.request_chain_id, job.request_chain_id);
        assert_eq!(current_job.tx_hash, job.tx_hash);
        assert_eq!(current_job.code_input, job.code_input);
        assert_eq!(current_job.user_timeout, job.user_timeout);
        assert_eq!(current_job.starttime, job.starttime);
        assert_eq!(current_job.job_owner, job.job_owner);
        assert_eq!(current_job.job_type, job.job_type);
        assert_eq!(current_job.sequence_number, job.sequence_number);

        assert_eq!(
            contracts_client
                .gateway_epoch_state_waitlist
                .read()
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn test_job_relayed_handler_no_cycle_state() {
        let contracts_client = generate_contracts_client().await;

        let job = generate_generic_job(None, None).await;

        let (req_chain_tx, _) = channel::<Job>(100);

        contracts_client
            .clone()
            .job_relayed_handler(job.clone(), req_chain_tx.clone())
            .await;

        let waitlisted_jobs_hashmap = contracts_client
            .gateway_epoch_state_waitlist
            .read()
            .unwrap()
            .clone();

        let waitlisted_jobs: Vec<Vec<Job>> = waitlisted_jobs_hashmap.values().cloned().collect();

        assert_eq!(waitlisted_jobs.len(), 1);
        assert_eq!(waitlisted_jobs[0].len(), 1);
        assert_eq!(waitlisted_jobs[0][0], job);

        assert_eq!(
            contracts_client
                .active_jobs
                .read()
                .unwrap()
                .get(&job.job_id),
            None
        );
    }

    #[tokio::test]
    async fn test_job_relayed_slash_timer_txn_success() {
        let contracts_client = generate_contracts_client().await;

        let mut job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(contracts_client.clone(), Some(5), None).await;
        job.gateway_address = Some(
            contracts_client
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

        let (req_chain_tx, mut com_chain_rx) = channel::<Job>(100);

        let mock_provider = MockHttpProvider::new(Some(job.clone()));
        contracts_client
            .job_relayed_slash_timer(job.clone(), Some(1), req_chain_tx, &mock_provider)
            .await;

        assert!(com_chain_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_job_relayed_slash_timer_txn_fail_retry() {
        let contracts_client = generate_contracts_client().await;

        let mut job = generate_generic_job(Some(U256::from(2)), None).await;

        add_gateway_epoch_state(contracts_client.clone(), Some(5), None).await;
        job.gateway_address = Some(
            contracts_client
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

        let (req_chain_tx, mut com_chain_rx) = channel::<Job>(100);

        let mock_provider = MockHttpProvider::new(Some(job.clone()));

        contracts_client
            .clone()
            .job_relayed_slash_timer(job.clone(), Some(1 as u64), req_chain_tx, &mock_provider)
            .await;

        if let Some(rx_job) = com_chain_rx.recv().await {
            job.job_type = GatewayJobType::SlashGatewayJob;
            assert_eq!(rx_job, job);
        } else {
            assert!(false);
        }

        assert!(com_chain_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_job_relayed_slash_timer_txn_fail_max_retry() {
        let contracts_client = generate_contracts_client().await;

        let mut job = generate_generic_job(Some(U256::from(2)), None).await;

        add_gateway_epoch_state(contracts_client.clone(), Some(5), None).await;
        job.gateway_address = Some(
            contracts_client
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

        let (req_chain_tx, mut com_chain_rx) = channel::<Job>(100);

        let mock_provider = MockHttpProvider::new(Some(job.clone()));
        contracts_client
            .clone()
            .job_relayed_slash_timer(job.clone(), Some(1 as u64), req_chain_tx, &mock_provider)
            .await;

        if let Some(rx_job) = com_chain_rx.recv().await {
            job.job_type = GatewayJobType::SlashGatewayJob;
            assert_eq!(rx_job, job);
        } else {
            assert!(false);
        }

        assert!(com_chain_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_cancel_job_with_job_id_single_active_job() {
        let contracts_client = generate_contracts_client().await;

        let job = generate_generic_job(None, None).await;
        contracts_client
            .active_jobs
            .write()
            .unwrap()
            .insert(job.job_id, job.clone());

        assert_eq!(contracts_client.active_jobs.read().unwrap().len(), 1);

        contracts_client
            .clone()
            .cancel_job_with_job_id(job.job_id)
            .await;

        assert_eq!(contracts_client.active_jobs.read().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_cancel_job_with_job_id_multiple_active_jobs() {
        let contracts_client = generate_contracts_client().await;

        let job = generate_generic_job(None, None).await;
        contracts_client
            .active_jobs
            .write()
            .unwrap()
            .insert(job.job_id, job.clone());

        let job2 = generate_generic_job(Some(U256::from(2)), None).await;
        contracts_client
            .active_jobs
            .write()
            .unwrap()
            .insert(job2.job_id, job2.clone());

        assert_eq!(contracts_client.active_jobs.read().unwrap().len(), 2);

        contracts_client
            .clone()
            .cancel_job_with_job_id(job.job_id)
            .await;

        assert_eq!(contracts_client.active_jobs.read().unwrap().len(), 1);
        assert_eq!(
            contracts_client
                .active_jobs
                .read()
                .unwrap()
                .get(&job2.job_id),
            Some(&job2)
        );
    }

    #[tokio::test]
    async fn test_cancel_job_with_job_id_no_active_jobs() {
        let contracts_client = generate_contracts_client().await;

        let job = generate_generic_job(None, None).await;

        assert_eq!(contracts_client.active_jobs.read().unwrap().len(), 0);

        contracts_client
            .clone()
            .cancel_job_with_job_id(job.job_id)
            .await;

        assert_eq!(contracts_client.active_jobs.read().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_get_job_from_job_responded_event_job_not_of_enclave() {
        let contracts_client = generate_contracts_client().await;

        let log = generate_job_responded_log(None).await;

        // let expected_job = generate_generic_response_job(None).await;

        let job = contracts_client.get_job_from_job_responded_event(log).await;

        assert!(job.is_err());
        assert_eq!(
            job.err().unwrap().to_string(),
            "Job does not belong to the enclave"
        );
    }

    #[tokio::test]
    async fn test_get_job_from_job_responded_event_job_of_enclave() {
        let contracts_client = generate_contracts_client().await;

        let log = generate_job_responded_log(None).await;

        let job = generate_generic_job(None, None).await;
        let expected_job = generate_generic_response_job(None).await;
        contracts_client
            .active_jobs
            .write()
            .unwrap()
            .insert(job.job_id, job.clone());

        let job = contracts_client.get_job_from_job_responded_event(log).await;

        assert!(job.is_ok());
        assert_eq!(job.unwrap(), expected_job);
    }

    #[tokio::test]
    async fn test_get_job_from_job_responded_event_job_of_enclave_invalid_log() {
        let contracts_client = generate_contracts_client().await;

        let log = Log {
            address: H160::from_str(GATEWAY_JOBS_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256(COMMON_CHAIN_JOB_RESPONDED_EVENT).into(),
                H256::from_low_u64_be(1),
            ],
            data: encode(&[Token::Bytes([].into())]).into(),
            ..Default::default()
        };

        let job = generate_generic_job(None, None).await;
        contracts_client
            .active_jobs
            .write()
            .unwrap()
            .insert(job.job_id, job.clone());

        let job = contracts_client.get_job_from_job_responded_event(log).await;

        assert!(job.is_err());
        assert_eq!(job.err().unwrap().to_string(), "Failed to decode log");
    }

    // TODO: tests for gateway_epoch_state_service
}
