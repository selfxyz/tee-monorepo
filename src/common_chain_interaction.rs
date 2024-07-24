use actix_web::web::Data;
use anyhow::{Context, Result};
use ethers::abi::{decode, Address, ParamType};
use ethers::prelude::*;
use ethers::providers::Provider;
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
use tokio::{task, time};

use crate::chain_util::{
    confirm_event, sign_job_response_request, sign_reassign_gateway_relay_request,
    sign_relay_job_request, LogsProvider,
};
use crate::common_chain_gateway_state_service::gateway_epoch_state_service;
use crate::constant::{
    GATEWAY_BLOCK_STATES_TO_MAINTAIN, GATEWAY_STAKE_ADJUSTMENT_FACTOR, MAX_GATEWAY_RETRIES,
    MIN_GATEWAY_STAKE, OFFEST_FOR_GATEWAY_EPOCH_STATE_CYCLE, REQUEST_RELAY_TIMEOUT,
};
use crate::error::ServerlessError;
use crate::model::{
    AppState, ContractsClient, GatewayData, GatewayJobType, Job, RegisterType, RegisteredData,
    RequestChainClient, ResponseJob,
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
            .topic0(vec![keccak256(
                "GatewayRegistered(address,address,uint256[])",
            )])
            .topic1(self.enclave_address)
            .topic2(self.enclave_owner);

        let tx_clone = tx.clone();
        let self_clone = Arc::clone(&self);
        task::spawn(async move {
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
                .address(request_chain_client.contract_address)
                .select(request_chain_client.request_chain_start_block_number..)
                .topic0(vec![keccak256("GatewayRegistered(address,address)")])
                .topic1(self.enclave_owner)
                .topic2(self.enclave_address);

            let tx_clone = tx.clone();
            let request_chain_client_clone = request_chain_client.clone();
            task::spawn(async move {
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

                    let mut request_chain_stream = request_chain_ws_provider
                        .subscribe_logs(&request_chain_registered_filter)
                        .await
                        .context("failed to subscribe to events on the Request Chain")
                        .unwrap();

                    while let Some(log) = request_chain_stream.next().await {
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

        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            let _ = self_clone.txns_to_common_chain(com_chain_rx).await;
        });
        let _ = &self
            .handle_all_req_chain_events(req_chain_tx.clone())
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

    async fn handle_all_req_chain_events(self: &Arc<Self>, tx: Sender<Job>) -> Result<()> {
        info!("Initializing Request Chain Clients for all request chains...");
        let chains_ids = self.request_chain_ids.clone();

        for chain_id in chains_ids {
            let self_clone = Arc::clone(&self);
            let tx_clone = tx.clone();

            // Spawn a new task for each Request Chain Contract
            task::spawn(async move {
                _ = self_clone
                    .handle_single_request_chain_events(tx_clone, chain_id)
                    .await;
            });
        }

        Ok(())
    }

    async fn handle_single_request_chain_events(self: &Arc<Self>, tx: Sender<Job>, chain_id: u64) {
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

                if topics[0]
                == keccak256(
                    "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,address,address,uint256,uint256)",
                )
                .into()
                {
                    info!(
                        "Request Chain ID: {:?}, JobPlace jobID: {:?}",
                        chain_id, log.topics[1]
                    );

                    let self_clone = Arc::clone(&self);
                    let tx_clone = tx.clone();
                    task::spawn(async move {
                        // TODO: what to do in case of error? Let it panic or return None?
                        let job = self_clone
                            .get_job_from_job_relay_event(
                                log,
                                1u8,
                                chain_id
                            )
                            .await;
                        if job.is_ok() {
                            self_clone.job_placed_handler(
                                job.unwrap(),
                                tx_clone.clone(),
                            )
                            .await;
                        }
                    });
                } else if topics[0] == keccak256("JobCancelled(uint256)").into() {
                    info!(
                        "Request Chain ID: {:?}, JobCancelled jobID: {:?}",
                        chain_id, log.topics[1]
                    );

                    let self_clone = Arc::clone(&self);
                    task::spawn(async move {
                        self_clone.cancel_job_with_job_id(
                            log.topics[1].into_uint(),
                        ).await;
                    });
                } else {
                    error!(
                        "Request Chain ID: {:?}, Unknown event: {:?}",
                        chain_id, log
                    );
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
                return Err(ServerlessError::LogDecodingError);
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
        })
    }

    pub async fn job_placed_handler(self: Arc<Self>, mut job: Job, tx: Sender<Job>) {
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
                    task::spawn(async move {
                        self_clone.job_relayed_slash_timer(job, None, tx).await;
                    });
                }
            }
            Err(err) => {
                error!("Error while selecting gateway: {}", err);
            }
        }
    }

    async fn job_relayed_slash_timer(
        self: Arc<Self>,
        job: Job,
        mut job_timeout: Option<u64>,
        tx: Sender<Job>,
    ) {
        if job_timeout.is_none() {
            job_timeout = Some(REQUEST_RELAY_TIMEOUT);
        }
        time::sleep(Duration::from_secs(job_timeout.unwrap())).await;

        // TODO: Issue with event logs -
        // get_logs might not provide the latest logs for the latest block
        // SOLUTION 1 - Wait for the next block.
        //          Problem: Extra time spent here waiting.

        let common_chain_http_provider: Provider<Http> =
            Provider::<Http>::try_from(&self.common_chain_http_url).unwrap();

        let logs = self
            .gateways_job_relayed_logs(job.clone(), &common_chain_http_provider)
            .await
            .context("Failed to get logs")
            .unwrap();

        for log in logs {
            let ref topics = log.topics;
            if topics[0] == keccak256("JobRelayed(uint256,uint256,address,address)").into() {
                let decoded = decode(
                    &vec![
                        ParamType::Uint(256),
                        ParamType::Uint(256),
                        ParamType::Address,
                        ParamType::Address,
                    ],
                    &log.data.0,
                )
                .unwrap();

                let job_id = log.topics[1].into_uint();
                let job_owner = decoded[1].clone().into_address().unwrap();
                let gateway_operator = decoded[2].clone().into_address().unwrap();

                if job_id == job.job_id
                    && job_owner == job.job_owner
                    && gateway_operator != Address::zero()
                    && gateway_operator != job.gateway_address.unwrap()
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
            return Err(ServerlessError::NoGatewaysRegistered);
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
            return Err(ServerlessError::NoGatewaysAvailableForRequestChain(
                job.request_chain_id,
            ));
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
        let selected_gateway_address = gateway_addresses_of_req_chain[index];

        info!(
            "Job ID: {:?}, Gateway Address: {:?}",
            job.job_id, selected_gateway_address
        );

        Ok(selected_gateway_address)
    }

    async fn cancel_job_with_job_id(self: Arc<Self>, job_id: U256) {
        info!("Remove the Job ID: {:} from the active jobs list", job_id);

        // scope for the write lock
        {
            self.active_jobs.write().unwrap().remove(&job_id);
        }
        // scope for the write lock
        {
            self.current_jobs.write().unwrap().remove(&job_id);
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
                    error!(
                        "Error: Transaction nonce too low. {}. Retrying - {} of 3",
                        err, i
                    );
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
                    error!(
                        "Error: Transaction nonce too low. {}. Retrying - {} of 3",
                        err, i
                    );
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

                if topics[0] == keccak256("JobResponded(uint256,bytes,uint256,uint8)").into() {
                    info!(
                        "JobResponded event triggered for job ID: {:?}",
                        log.topics[1]
                    );
                    let self_clone = Arc::clone(&self);
                    let com_chain_tx = com_chain_tx.clone();
                    task::spawn(async move {
                        let response_job_result =
                            self_clone.get_job_from_job_responded_event(log).await;
                        match response_job_result {
                            Ok(response_job) => {
                                self_clone
                                    .job_responded_handler(response_job, com_chain_tx)
                                    .await;
                            }
                            Err(err) => match err {
                                ServerlessError::JobNotBelongToEnclave => {
                                    info!("Job does not belong to the enclave")
                                }
                                _ => error!(
                                    "Error while getting job from JobResponded event: {}",
                                    err
                                ),
                            },
                        }
                    });
                } else if topics[0] == keccak256("JobResourceUnavailable(uint256,address)").into() {
                    info!("JobResourceUnavailable event triggered");
                    let self_clone = Arc::clone(&self);
                    task::spawn(async move {
                        self_clone.job_resource_unavailable_handler(log).await;
                    });
                } else if topics[0]
                    == keccak256("GatewayReassigned(uint256,address,address,uint8)").into()
                {
                    info!("GatewayReassigned jobID: {:?}", log.topics[1]);
                    let self_clone = Arc::clone(&self);
                    let req_chain_tx = req_chain_tx.clone();
                    task::spawn(async move {
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
            return Err(ServerlessError::JobNotBelongToEnclave);
        }

        let job = job.unwrap();

        let types = vec![ParamType::Bytes, ParamType::Uint(256), ParamType::Uint(8)];

        let decoded = decode(&types, &log.data.0);
        let decoded = match decoded {
            Ok(decoded) => decoded,
            Err(err) => {
                error!("Error while decoding event: {}", err);
                return Err(ServerlessError::LogDecodingError);
            }
        };
        let request_chain_id = job.request_chain_id;

        Ok(ResponseJob {
            job_id,
            request_chain_id,
            output: decoded[0].clone().into_bytes().unwrap().into(),
            total_time: decoded[1].clone().into_uint().unwrap(),
            error_code: decoded[2].clone().into_uint().unwrap().low_u64() as u8,
            job_type: GatewayJobType::JobResponded,
            gateway_address: None,
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

        let active_jobs_guard = self.active_jobs.read().unwrap();
        let job = active_jobs_guard.get(&job_id);
        if job.is_none() {
            return;
        }
        let job = job.unwrap();
        if job.gateway_address.unwrap() != self.enclave_address {
            return;
        }
        drop(active_jobs_guard);

        // scope for the write lock
        {
            let job = self.active_jobs.write().unwrap().remove(&job_id);
            if job.is_some() {
                info!(
                    "Job ID: {:?} - removed from active jobs",
                    job.unwrap().job_id
                );
            } else {
                info!("Job ID: {:?} - not found in active jobs", job_id);
            }
        }
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

        // scope for write lock
        {
            self.active_jobs.write().unwrap().remove(&job_id);
        }
        // scope for write lock
        {
            self.current_jobs.write().unwrap().remove(&job_id);
        }

        job.sequence_number += 1;
        if job.sequence_number > MAX_GATEWAY_RETRIES {
            info!("Job ID: {:?}, Max retries reached", job.job_id);
            return;
        }
        job.gateway_address = None;

        let self_clone = Arc::clone(&self);
        task::spawn(async move {
            self_clone.job_placed_handler(job, req_chain_tx).await;
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

        let req_chain_client = &self.request_chain_clients[&response_job.request_chain_id];

        let (signature, sign_timestamp) = sign_job_response_request(
            &self.enclave_signer_key,
            response_job.job_id,
            response_job.output.clone(),
            response_job.total_time,
            response_job.error_code,
        )
        .await
        .unwrap();
        let Ok(signature) = types::Bytes::from_hex(signature) else {
            error!("Failed to decode signature hex string");
            return;
        };

        let txn = req_chain_client.contract.read().unwrap().job_response(
            signature,
            response_job.job_id,
            response_job.output,
            response_job.total_time,
            response_job.error_code,
            sign_timestamp.into(),
        );

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
                keccak256("JobResponded(uint256,bytes,uint256,uint8)"),
                keccak256("JobResourceUnavailable(uint256,address)"),
                keccak256("GatewayReassigned(uint256,address,address,uint8)"),
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
            .address(req_chain_client.contract_address)
            .select(req_chain_client.request_chain_start_block_number..)
            .topic0(vec![
                keccak256(
                    "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,address,address,uint256,uint256)",
                ),
                keccak256("JobCancelled(uint256)"),
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

    #[cfg(not(test))]
    async fn gateways_job_relayed_logs<'a>(
        &'a self,
        job: Job,
        common_chain_http_provider: &'a Provider<Http>,
    ) -> Result<Vec<Log>> {
        let common_chain_start_block_number =
            self.common_chain_start_block_number.lock().unwrap().clone();

        let job_relayed_event_filter = Filter::new()
            .address(self.gateway_jobs_contract.read().unwrap().address())
            .select(common_chain_start_block_number..)
            .topic0(vec![keccak256(
                "JobRelayed(uint256,uint256,address,address)",
            )])
            .topic1(job.job_id);

        let logs = common_chain_http_provider
            .get_logs(&job_relayed_event_filter)
            .await
            .unwrap();

        Ok(logs)
    }

    #[cfg(test)]
    async fn gateways_job_relayed_logs<'a>(
        &'a self,
        job: Job,
        _common_chain_http_provider: &'a Provider<Http>,
    ) -> Result<Vec<Log>> {
        use ethers::abi::{encode, Token};
        use ethers::prelude::*;

        if job.job_id == U256::from(1) {
            Ok(vec![Log {
                address: self.gateway_jobs_contract.read().unwrap().address(),
                topics: vec![
                    keccak256("JobRelayed(uint256,uint256,address,address)").into(),
                    H256::from_uint(&job.job_id),
                ],
                data: encode(&[
                    Token::Uint(job.job_id),
                    Token::Uint(U256::from(100)),
                    Token::Address(job.job_owner),
                    Token::Address(job.gateway_address.unwrap()),
                ])
                .into(),
                ..Default::default()
            }])
        } else {
            Ok(vec![Log {
                address: Address::default(),
                topics: vec![H256::default(), H256::default(), H256::default()],
                data: Bytes::default(),
                ..Default::default()
            }])
        }
    }
}

#[cfg(test)]
mod serverless_executor_test {
    use std::collections::{BTreeMap, BTreeSet};
    use std::str::FromStr;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;

    use abi::{encode, encode_packed, Token};
    use actix_web::{
        body::MessageBody,
        dev::{ServiceFactory, ServiceRequest, ServiceResponse},
        http, test, App, Error,
    };
    use ethers::types::{Address, Bytes as EthBytes, H160};
    use ethers::utils::public_key_to_address;
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use rand::rngs::OsRng;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use crate::api_impl::{
        export_signed_registration_message, get_gateway_details, index, inject_immutable_config,
        inject_mutable_config,
    };

    use super::*;

    // Testnet or Local blockchain (Hardhat) configurations
    const CHAIN_ID: u64 = 421614;
    const HTTP_RPC_URL: &str = "https://sepolia-rollup.arbitrum.io/rpc";
    const WS_URL: &str = "wss://arbitrum-sepolia.infura.io/ws/v3/cd72f20b9fd544f8a5b8da706441e01c";
    const GATEWAY_CONTRACT_ADDR: &str = "0x819d9b4087D88359B6d7fFcd16F17A13Ca79fd0E";
    const JOB_CONTRACT_ADDR: &str = "0xAc6Ae536203a3ec290ED4aA1d3137e6459f4A963";
    const RELAY_CONTRACT_ADDR: &str = "0xaF7E4CB6B3729C65c4a9a63d89Ae04e97C9093C4";
    const OWNER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const GAS_WALLET_KEY: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const GAS_WALLET_PUBLIC_ADDRESS: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
    const EPOCH: u64 = 1713433800;
    const TIME_INTERVAL: u64 = 300;

    #[derive(Serialize, Deserialize, Debug)]
    struct ExportResponse {
        owner: H160,
        sign_timestamp: usize,
        chain_ids: Vec<u64>,
        common_chain_signature: String,
        request_chain_signature: String,
    }

    // Generate test app state
    async fn generate_app_state() -> Data<AppState> {
        // Initialize random 'secp256k1' signing key for the enclave
        let signer_key = SigningKey::random(&mut OsRng);

        Data::new(AppState {
            enclave_signer_key: signer_key.clone(),
            enclave_address: public_key_to_address(&signer_key.verifying_key()),
            wallet: None.into(),
            common_chain_id: CHAIN_ID,
            common_chain_http_url: HTTP_RPC_URL.to_owned(),
            common_chain_ws_url: WS_URL.to_owned(),
            gateways_contract_addr: GATEWAY_CONTRACT_ADDR.parse::<Address>().unwrap(),
            gateway_jobs_contract_addr: JOB_CONTRACT_ADDR.parse::<Address>().unwrap(),
            request_chain_ids: HashSet::new().into(),
            registered: Arc::new(AtomicBool::new(false)),
            registration_events_listener_active: false.into(),
            epoch: EPOCH,
            time_interval: TIME_INTERVAL,
            enclave_owner: H160::zero().into(),
            immutable_params_injected: false.into(),
            mutable_params_injected: false.into(),
            contracts_client: Mutex::new(None),
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
            .service(inject_immutable_config)
            .service(inject_mutable_config)
            .service(export_signed_registration_message)
            .service(get_gateway_details)
    }

    // Test the various response cases for the 'immutable-config' endpoint
    #[actix_web::test]
    async fn inject_immutable_config_test() {
        let app_state = generate_app_state().await;
        let app = test::init_service(new_app(app_state.clone())).await;

        // Inject invalid hex address string
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": "0x32255"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid owner address provided: Invalid input length".as_bytes()
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!*app_state.mutable_params_injected.lock().unwrap());
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), H160::zero());

        // Inject invalid hex character address
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": "0xzfffffffffffffffffffffffffffffffffffffff"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid owner address provided: Invalid character 'z' at position 0".as_bytes()
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!*app_state.mutable_params_injected.lock().unwrap());
        assert_eq!(*app_state.enclave_owner.lock().unwrap(), H160::zero());

        // Inject a valid address
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params configured!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!*app_state.mutable_params_injected.lock().unwrap());
        assert_eq!(
            *app_state.enclave_owner.lock().unwrap(),
            H160::from_str(OWNER_ADDRESS).unwrap()
        );

        // Inject the valid address again
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params already configured!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!*app_state.mutable_params_injected.lock().unwrap());
        assert_eq!(
            *app_state.enclave_owner.lock().unwrap(),
            H160::from_str(OWNER_ADDRESS).unwrap()
        );
    }

    fn wallet_from_hex(hex: &str) -> LocalWallet {
        let mut bytes32 = [0u8; 32];
        let _ = hex::decode_to_slice(hex, &mut bytes32);
        LocalWallet::from_bytes(&bytes32)
            .unwrap()
            .with_chain_id(CHAIN_ID)
    }

    // Test the various response cases for the 'mutable-config' endpoint
    #[actix_web::test]
    async fn inject_mutable_config_test() {
        let app_state = generate_app_state().await;
        let app = test::init_service(new_app(app_state.clone())).await;

        // Inject invalid hex private key string
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": "0x32255"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to hex decode the gas private key into 32 bytes: OddLength".as_bytes()
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!*app_state.mutable_params_injected.lock().unwrap());
        assert_eq!(*app_state.wallet.lock().unwrap(), None);

        // Inject invalid private(signing) key
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": "ffffffffffffffffffffffffffffffffffffffffff"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Failed to hex decode the gas private key into 32 bytes: InvalidStringLength"
                .as_bytes()
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!*app_state.mutable_params_injected.lock().unwrap());
        assert_eq!(*app_state.wallet.lock().unwrap(), None);

        // Inject invalid gas private key hex string (not ecdsa valid key)
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Invalid gas private key provided: EcdsaError(signature::Error { source: None })"
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!*app_state.mutable_params_injected.lock().unwrap());
        assert_eq!(*app_state.wallet.lock().unwrap(), None);

        // Inject a valid private key for gas wallet
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": GAS_WALLET_KEY
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!"
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(*app_state.mutable_params_injected.lock().unwrap());
        assert_eq!(
            *app_state.wallet.lock().unwrap(),
            Some(wallet_from_hex(GAS_WALLET_KEY))
        );
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(app_state.contracts_client.lock().unwrap().is_none());
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());

        // Build contracts client to verify the contracts client public address
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                    "chain_ids": [CHAIN_ID]
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);

        assert_eq!(
            app_state
                .contracts_client
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .gateway_jobs_contract
                .read()
                .unwrap()
                .client()
                .inner()
                .signer()
                .address(),
            GAS_WALLET_PUBLIC_ADDRESS.parse::<Address>().unwrap()
        );

        // Inject the same valid private key for gas wallet again
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": GAS_WALLET_KEY
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "The same wallet address already set."
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(*app_state.mutable_params_injected.lock().unwrap());
        assert_eq!(
            *app_state.wallet.lock().unwrap(),
            Some(wallet_from_hex(GAS_WALLET_KEY))
        );
        assert_eq!(
            app_state
                .contracts_client
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .gateway_jobs_contract
                .read()
                .unwrap()
                .client()
                .inner()
                .signer()
                .address(),
            GAS_WALLET_PUBLIC_ADDRESS.parse::<Address>().unwrap()
        );

        const GAS_WALLET_KEY_2: &str =
            "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
        const GAS_WALLET_PUBLIC_ADDRESS_2: &str = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc";

        // Inject another valid private key for gas wallet
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": GAS_WALLET_KEY_2
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(*app_state.mutable_params_injected.lock().unwrap());
        assert_eq!(
            *app_state.wallet.lock().unwrap(),
            Some(wallet_from_hex(GAS_WALLET_KEY_2))
        );
        assert_eq!(
            app_state
                .contracts_client
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .gateway_jobs_contract
                .read()
                .unwrap()
                .client()
                .inner()
                .signer()
                .address(),
            GAS_WALLET_PUBLIC_ADDRESS_2.parse::<Address>().unwrap()
        );
    }

    fn recover_key(
        chain_ids: Vec<u64>,
        enclave_owner: H160,
        sign_timestamp: usize,
        common_chain_signature: String,
        request_chain_signature: String,
        verifying_key: VerifyingKey,
    ) -> bool {
        let common_chain_register_typehash =
            keccak256("Register(address owner,uint256[] chainIds,uint256 signTimestamp)");

        let chain_ids = chain_ids.into_iter().collect::<BTreeSet<u64>>();
        let chain_ids_tokens: Vec<Token> = chain_ids
            .clone()
            .into_iter()
            .map(|x| Token::Uint(x.into()))
            .collect::<Vec<Token>>();
        let chain_ids_bytes = keccak256(encode_packed(&[Token::Array(chain_ids_tokens)]).unwrap());
        let hash_struct = keccak256(encode(&[
            Token::FixedBytes(common_chain_register_typehash.to_vec()),
            Token::Address(enclave_owner),
            Token::FixedBytes(chain_ids_bytes.into()),
            Token::Uint(sign_timestamp.into()),
        ]));

        let domain_separator = keccak256(encode(&[
            Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
            Token::FixedBytes(keccak256("marlin.oyster.Gateways").to_vec()),
            Token::FixedBytes(keccak256("1").to_vec()),
        ]));

        let digest = encode_packed(&[
            Token::String("\x19\x01".to_string()),
            Token::FixedBytes(domain_separator.to_vec()),
            Token::FixedBytes(hash_struct.to_vec()),
        ])
        .unwrap();
        let digest = keccak256(digest);

        let signature = Signature::from_slice(
            hex::decode(&common_chain_signature[0..128])
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let v =
            RecoveryId::try_from((hex::decode(&common_chain_signature[128..]).unwrap()[0]) - 27)
                .unwrap();
        let common_chain_recovered_key =
            VerifyingKey::recover_from_prehash(&digest, &signature, v).unwrap();

        if common_chain_recovered_key != verifying_key {
            return false;
        }

        // create request chain signature and add it to the request chain signatures map
        let request_chain_register_typehash =
            keccak256("Register(address owner,uint256 signTimestamp)");
        let hash_struct = keccak256(encode(&[
            Token::FixedBytes(request_chain_register_typehash.to_vec()),
            Token::Address(enclave_owner),
            Token::Uint(sign_timestamp.into()),
        ]));

        let request_chain_domain_separator = keccak256(encode(&[
            Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
            Token::FixedBytes(keccak256("marlin.oyster.Relay").to_vec()),
            Token::FixedBytes(keccak256("1").to_vec()),
        ]));

        let digest = encode_packed(&[
            Token::String("\x19\x01".to_string()),
            Token::FixedBytes(request_chain_domain_separator.to_vec()),
            Token::FixedBytes(hash_struct.to_vec()),
        ])
        .unwrap();
        let digest = keccak256(digest);

        let signature = Signature::from_slice(
            hex::decode(&request_chain_signature[0..128])
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let v =
            RecoveryId::try_from((hex::decode(&request_chain_signature[128..]).unwrap()[0]) - 27)
                .unwrap();
        let request_chain_recovered_key =
            VerifyingKey::recover_from_prehash(&digest, &signature, v).unwrap();

        if request_chain_recovered_key != verifying_key {
            return false;
        }

        true
    }

    #[actix_web::test]
    async fn export_signed_registration_message_test() {
        let app_state = generate_app_state().await;
        let app = test::init_service(new_app(app_state.clone())).await;

        // Get signature without injecting the operator's address or gas key
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params not configured yet!"
        );
        assert!(!*app_state.immutable_params_injected.lock().unwrap());
        assert!(!*app_state.mutable_params_injected.lock().unwrap());
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Inject a valid address into the enclave
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params configured!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!*app_state.mutable_params_injected.lock().unwrap());
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature without injecting a gas key
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params not configured yet!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(!*app_state.mutable_params_injected.lock().unwrap());
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Inject a valid private key
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": GAS_WALLET_KEY
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!"
        );
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(*app_state.mutable_params_injected.lock().unwrap());
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature with invalid chain id
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": ["invalid u64"]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert!(resp.into_body().try_into_bytes().unwrap().starts_with(
            "Json deserialize error: invalid type: string \"invalid u64\"".as_bytes()
        ));
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(*app_state.mutable_params_injected.lock().unwrap());
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature with no chain_ids field in json
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({}))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert!(resp
            .into_body()
            .try_into_bytes()
            .unwrap()
            .starts_with("Json deserialize error: missing field `chain_ids`".as_bytes()));
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(*app_state.mutable_params_injected.lock().unwrap());
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(!*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), HashSet::new());

        // Get signature with valid data points
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                    "chain_ids": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<ExportResponse, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let mut chain_id_set: HashSet<u64> = HashSet::new();
        chain_id_set.insert(CHAIN_ID);

        let verifying_key = app_state.enclave_signer_key.verifying_key().to_owned();

        let response = response.unwrap();
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(*app_state.mutable_params_injected.lock().unwrap());
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), chain_id_set);
        assert_eq!(response.owner, *app_state.enclave_owner.lock().unwrap());
        assert_eq!(response.common_chain_signature.len(), 130);
        assert_eq!(response.request_chain_signature.len(), 130);
        assert!(recover_key(
            vec![CHAIN_ID],
            *app_state.enclave_owner.lock().unwrap(),
            response.sign_timestamp,
            response.common_chain_signature,
            response.request_chain_signature,
            verifying_key
        ));

        // Get signature again with the same chain ids
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response: Result<ExportResponse, serde_json::Error> =
            serde_json::from_slice(&resp.into_body().try_into_bytes().unwrap());
        assert!(response.is_ok());

        let mut chain_id_set: HashSet<u64> = HashSet::new();
        chain_id_set.insert(CHAIN_ID);

        let verifying_key = app_state.enclave_signer_key.verifying_key().to_owned();

        let response = response.unwrap();
        assert!(*app_state.immutable_params_injected.lock().unwrap());
        assert!(*app_state.mutable_params_injected.lock().unwrap());
        assert!(!app_state.registered.load(Ordering::SeqCst));
        assert!(*app_state
            .registration_events_listener_active
            .lock()
            .unwrap());
        assert_eq!(*app_state.request_chain_ids.lock().unwrap(), chain_id_set);
        assert_eq!(response.owner, *app_state.enclave_owner.lock().unwrap());
        assert_eq!(response.common_chain_signature.len(), 130);
        assert_eq!(response.request_chain_signature.len(), 130);
        assert!(recover_key(
            vec![CHAIN_ID],
            *app_state.enclave_owner.lock().unwrap(),
            response.sign_timestamp,
            response.common_chain_signature,
            response.request_chain_signature,
            verifying_key
        ));

        // Get signature with a different chain id
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": [CHAIN_ID + 1]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            json!({
                    "message": "Request chain ids mismatch!",
                    "chain_ids": [CHAIN_ID],
            })
            .to_string()
            .try_into_bytes()
            .unwrap()
        );

        // After on chain registration
        app_state.registered.store(true, Ordering::SeqCst);

        // Get signature after registration
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Enclave has already been registered."
        );
    }

    #[actix_web::test]
    async fn get_gateway_details_test() {
        let app_state = generate_app_state().await;
        let app = test::init_service(new_app(app_state.clone())).await;

        // Get gateway details without adding wallet and gas key
        let req = test::TestRequest::get()
            .uri("/gateway-details")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params not configured yet!"
        );

        // Inject a valid address into the enclave
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Immutable params configured!"
        );

        // Get gateway details without gas key
        let req = test::TestRequest::get()
            .uri("/gateway-details")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params not configured yet!"
        );

        // Inject a valid private gas key
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": GAS_WALLET_KEY
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.into_body().try_into_bytes().unwrap(),
            "Mutable params configured!"
        );

        // Get gateway details
        let req = test::TestRequest::get()
            .uri("/gateway-details")
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), http::StatusCode::OK);

        assert_eq!(
            json!({
                "enclave_public_key": "0x".to_string() + &hex::encode(
                    &app_state.enclave_signer_key.verifying_key().to_encoded_point(false).as_bytes()[1..]
                ),
                "enclave_address": app_state.enclave_address,
                "owner_address": *app_state.enclave_owner.lock().unwrap(),
                "gas_address": app_state.wallet.lock().unwrap().clone().unwrap().address(),
            }).to_string().try_into_bytes().unwrap(),
            &resp.into_body().try_into_bytes().unwrap(),
        );
    }

    async fn generate_contracts_client() -> Arc<ContractsClient> {
        let app_state = generate_app_state().await;
        let app = test::init_service(new_app(app_state.clone())).await;

        // add immutable config
        let req = test::TestRequest::post()
            .uri("/immutable-config")
            .set_json(&json!({
                "owner_address_hex": OWNER_ADDRESS
            }))
            .to_request();
        test::call_service(&app, req).await;

        // add mutable config
        let req = test::TestRequest::post()
            .uri("/mutable-config")
            .set_json(&json!({
                "gas_key_hex": GAS_WALLET_KEY
            }))
            .to_request();
        test::call_service(&app, req).await;

        // Get signature with valid data points
        let req = test::TestRequest::get()
            .uri("/signed-registration-message")
            .set_json(&json!({
                "chain_ids": [CHAIN_ID]
            }))
            .to_request();

        test::call_service(&app, req).await;

        let contracts_client = app_state.contracts_client.lock().unwrap().clone().unwrap();

        contracts_client
    }

    async fn add_gateway_epoch_state(
        contracts_client: Arc<ContractsClient>,
        num: Option<u64>,
        add_self: Option<bool>,
    ) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current_cycle = (ts - contracts_client.epoch - OFFEST_FOR_GATEWAY_EPOCH_STATE_CYCLE)
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
                        stake_amount: U256::from(100),
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
                        stake_amount: U256::from(100),
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
                keccak256(
                   "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,address,address,uint256,uint256)",
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
            address: H160::from_str(JOB_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256("JobResponded(uint256,bytes,uint8").into(),
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
        }
    }

    #[actix_web::test]
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

    #[actix_web::test]
    async fn test_get_job_from_job_relay_event_invalid_log() {
        let contracts_client = generate_contracts_client().await;

        let log = Log {
            address: H160::from_str(RELAY_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256(
                    "JobRelayed(uint256,bytes32,bytes,uint256,uint256,uint256,uint256,address,address,uint256,uint256)",
                )
                .into(),
                H256::from_uint(&U256::from(1)),
            ],
            data: EthBytes::from(vec![0x00]),
            ..Default::default()
        };

        let job = contracts_client
            .get_job_from_job_relay_event(log, 1 as u8, CHAIN_ID)
            .await;

        // expect an error
        assert_eq!(job.err().unwrap(), ServerlessError::LogDecodingError);
    }

    #[actix_web::test]
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

    #[actix_web::test]
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

    #[actix_web::test]
    async fn test_select_gateway_for_job_id_multiple_gateways() {
        let contracts_client = generate_contracts_client().await;

        let job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(contracts_client.clone(), Some(5), None).await;

        let gateway_address = contracts_client
            .select_gateway_for_job_id(job.clone(), job.starttime.as_u64(), job.sequence_number)
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

    #[actix_web::test]
    async fn test_select_gateway_for_job_id_multiple_gateways_seq_number() {
        let contracts_client = generate_contracts_client().await;

        let mut job = generate_generic_job(None, None).await;
        job.sequence_number = 5;

        add_gateway_epoch_state(contracts_client.clone(), Some(5), None).await;

        let gateway_address = contracts_client
            .select_gateway_for_job_id(job.clone(), job.starttime.as_u64(), job.sequence_number)
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

    #[actix_web::test]
    async fn test_job_placed_handler() {
        let contracts_client = generate_contracts_client().await;

        let mut job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(contracts_client.clone(), None, None).await;

        let (req_chain_tx, mut com_chain_rx) = channel::<Job>(100);

        let job_clone = job.clone();
        let contracts_client_clone = contracts_client.clone();
        contracts_client_clone
            .job_placed_handler(job_clone, req_chain_tx.clone())
            .await;

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

    #[actix_web::test]
    async fn test_job_placed_handler_selected_gateway_not_self() {
        let contracts_client = generate_contracts_client().await;

        let job = generate_generic_job(None, None).await;

        add_gateway_epoch_state(contracts_client.clone(), Some(4), Some(false)).await;

        let (req_chain_tx, mut com_chain_rx) = channel::<Job>(100);

        let job_clone = job.clone();
        let contracts_client_clone = contracts_client.clone();
        contracts_client_clone
            .job_placed_handler(job_clone, req_chain_tx.clone())
            .await;

        assert!(com_chain_rx.recv().await.is_none());

        assert_eq!(
            contracts_client
                .active_jobs
                .read()
                .unwrap()
                .get(&job.job_id),
            None
        );

        assert_eq!(
            contracts_client
                .gateway_epoch_state_waitlist
                .read()
                .unwrap()
                .len(),
            0
        );
    }

    #[actix_web::test]
    async fn test_job_placed_handler_no_cycle_state() {
        let contracts_client = generate_contracts_client().await;

        let job = generate_generic_job(None, None).await;

        let (req_chain_tx, _) = channel::<Job>(100);

        contracts_client
            .clone()
            .job_placed_handler(job.clone(), req_chain_tx.clone())
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

    #[actix_web::test]
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

        contracts_client
            .job_relayed_slash_timer(job.clone(), Some(1), req_chain_tx)
            .await;

        assert!(com_chain_rx.recv().await.is_none());
    }

    #[actix_web::test]
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

        contracts_client
            .clone()
            .job_relayed_slash_timer(job.clone(), Some(1 as u64), req_chain_tx)
            .await;

        if let Some(rx_job) = com_chain_rx.recv().await {
            job.job_type = GatewayJobType::SlashGatewayJob;
            assert_eq!(rx_job, job);
        } else {
            assert!(false);
        }

        assert!(com_chain_rx.recv().await.is_none());
    }

    #[actix_web::test]
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

        contracts_client
            .clone()
            .job_relayed_slash_timer(job.clone(), Some(1 as u64), req_chain_tx)
            .await;

        if let Some(rx_job) = com_chain_rx.recv().await {
            job.job_type = GatewayJobType::SlashGatewayJob;
            assert_eq!(rx_job, job);
        } else {
            assert!(false);
        }

        assert!(com_chain_rx.recv().await.is_none());
    }

    #[actix_web::test]
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

    #[actix_web::test]
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

    #[actix_web::test]
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

    #[actix_web::test]
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

    #[actix_web::test]
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

    #[actix_web::test]
    async fn test_get_job_from_job_responded_event_job_of_enclave_invalid_log() {
        let contracts_client = generate_contracts_client().await;

        let log = Log {
            address: H160::from_str(JOB_CONTRACT_ADDR).unwrap(),
            topics: vec![
                keccak256("JobResponded(uint256,bytes,uint8").into(),
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
        assert_eq!(
            job.err().unwrap().to_string(),
            "Error while decoding event: Invalid data"
        );
    }

    // TODO: tests for gateway_epoch_state_service
}
