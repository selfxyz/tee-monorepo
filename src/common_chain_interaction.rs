use anyhow::{Context, Result};
use async_recursion::async_recursion;
use ethers::abi::{decode, Address, FixedBytes, ParamType};
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
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::{task, time};

use crate::common_chain_util::{
    get_next_block_number, prune_old_blocks, pub_key_to_address,
    sign_reassign_gateway_relay_response, sign_relay_job_response, BlockData,
};
use crate::constant::{MAX_GATEWAY_RETRIES, REQUEST_RELAY_TIMEOUT};
use crate::HttpProvider;

abigen!(CommonChainGatewayContract, "./CommonChainGateway.json",);
abigen!(RequestChainContract, "./RequestChainContract.json",);
abigen!(CommonChainJobsContract, "./CommonChainJobs.json",);

#[derive(Debug, Clone)]
pub struct GatewayData {
    pub address: Address,
    pub request_chains: Vec<RequestChainData>,
    pub stake_amount: U256,
    pub status: bool,
}

#[derive(Debug, Clone)]
pub struct CommonChainClient {
    pub signer: LocalWallet,
    pub enclave_signer_key: SigningKey,
    pub address: Address,
    pub chain_ws_client: Provider<Ws>,
    pub gateway_contract_addr: H160,
    pub contract_addr: H160,
    pub start_block: u64,
    pub gateway_contract: CommonChainGatewayContract<HttpProvider>,
    pub com_chain_jobs_contract: CommonChainJobsContract<HttpProvider>,
    pub req_chain_clients: HashMap<String, Arc<RequestChainClient>>,
    pub recent_blocks: Arc<RwLock<BTreeMap<u64, BlockData>>>,
    pub request_chain_list: Vec<RequestChainData>,
    pub active_jobs: Arc<RwLock<HashMap<U256, Job>>>,
}

#[derive(Debug, Clone)]
pub struct RequestChainData {
    pub chain_id: u64,
    pub contract_address: Address,
    pub rpc_url: String,
}

#[derive(Debug, Clone)]
pub struct RequestChainClient {
    pub chain_id: u64,
    pub contract_address: Address,
    pub rpc_url: String,
    pub contract: RequestChainContract<HttpProvider>,
}

#[derive(Debug, Clone)]
pub enum JobType {
    JobRelay,
    SlashGatewayJob,
}

#[derive(Debug, Clone)]
pub struct Job {
    pub job_id: U256,
    pub tx_hash: FixedBytes,
    pub code_input: Bytes,
    pub user_timout: U256,
    pub starttime: U256,
    pub max_gas_price: U256,
    pub deposit: Address,
    pub callback_deposit: U256,
    pub req_chain_id: u64,
    pub job_owner: Address,
    pub job_type: JobType,
    pub retry_number: u8,
    pub gateway_address: Option<Address>,
}

impl CommonChainClient {
    pub async fn new(
        enclave_signer_key: SigningKey,
        enclave_pub_key: Bytes,
        signer: LocalWallet,
        com_chain_ws_url: &String,
        chain_http_provider: Arc<HttpProvider>,
        gateway_contract_addr: &H160,
        contract_addr: &H160,
        start_block: u64,
        recent_blocks: Arc<RwLock<BTreeMap<u64, BlockData>>>,
        request_chain_list: Vec<RequestChainData>,
    ) -> Self {
        info!("Initializing Common Chain Client...");
        // let signer_address = signer.address();
        // let chain_http_client = chain_http_provider
        //     .clone()
        //     .with_signer(signer.clone())
        //     .nonce_manager(signer_address);

        let gateway_contract = CommonChainGatewayContract::new(
            gateway_contract_addr.clone(),
            chain_http_provider.clone(),
        );
        // pub_key_to_address
        // let gateway = gateway_contract
        //     .get_gateway(pub_key_to_address(&enclave_pub_key).unwrap())
        //     .await
        //     .context("Failed to get gateway data")
        //     .unwrap();

        // let mut request_chains: Vec<RequestChainData> = vec![];
        // for chain_id in gateway.1.iter() {
        //     let (contract_address, rpc_url) = gateway_contract
        //         .request_chains(chain_id.clone())
        //         .await
        //         .context("Failed to get request chain data")
        //         .unwrap();
        //     request_chains.push(RequestChainData {
        //         chain_id: chain_id.clone(),
        //         contract_address,
        //         rpc_url,
        //     });
        // }
        // let gateway_data = GatewayData {
        //     address: gateway.0,
        //     request_chains: request_chain_list,
        //     stake_amount: gateway.2,
        //     status: gateway.3,
        // };

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
            start_block,
            gateway_contract,
            com_chain_jobs_contract,
            req_chain_clients: HashMap::new(),
            recent_blocks,
            request_chain_list,
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        let (req_chain_tx, com_chain_rx) = channel::<(Job, Arc<CommonChainClient>)>(100);
        let self_clone = Arc::clone(&self);
        self_clone.txns_to_common_chain(com_chain_rx).await?;
        self.handle_all_req_chain_events(req_chain_tx).await?;
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

            // let req_chain_client_clone = Arc::clone(&req_chain_client);
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
                    // let req_chain_client = Arc::clone(&req_chain_client_clone);
                    let self_clone = Arc::clone(&self_clone);
                    let tx = tx_clone.clone();
                    task::spawn(async move {
                        let job = self_clone.clone()
                            .get_job_from_job_relay_event(
                                log,
                                 0 as u8,
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
                } else if topics[0] == keccak256("JobCancel(uint256)").into() {
                    info!(
                        "Request Chain ID: {:?}, JobCancel jobID: {:?}",
                        request_chain.chain_id, log.topics[1]
                    );
                    let self_clone = Arc::clone(&self_clone);
                    // TODO: Isn't it better if we also receive the Gateway Address in the event parameters?
                    // This will help in identifying the gateway for the job and prevent an unnecessary
                    // write lock to the active_jobs map.
                    task::spawn(async move {
                        self_clone.cancel_job_with_job_id(U256::from_big_endian(log.topics[1].as_fixed_bytes())).await;
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
        retry_number: u8,
        req_chain_id: &String,
    ) -> Result<Job> {
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

        let req_chain_client = self.req_chain_clients[req_chain_id].clone();

        Ok(Job {
            job_id: decoded[0].clone().into_uint().unwrap(),
            tx_hash: decoded[1].clone().into_bytes().unwrap(),
            code_input: decoded[2].clone().into_bytes().unwrap().into(),
            user_timout: decoded[3].clone().into_uint().unwrap(),
            starttime: decoded[4].clone().into_uint().unwrap(),
            max_gas_price: decoded[5].clone().into_uint().unwrap(),
            deposit: decoded[6].clone().into_address().unwrap(),
            callback_deposit: decoded[7].clone().into_uint().unwrap(),
            req_chain_id: req_chain_client.chain_id.clone(),
            job_owner: log.address,
            job_type: JobType::JobRelay,
            retry_number,
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
            .select_gateway_for_job_relayed(job.clone(), req_chain_client)
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
                    .insert(job.job_id, job.clone());
            }
            tx.send((job, self.clone())).await.unwrap();
        } else {
            self.job_slash_timer(job.clone(), tx.clone()).await.unwrap();
        }
    }

    #[async_recursion]
    async fn job_slash_timer(
        self: Arc<Self>,
        mut job: Job,
        tx: Sender<(Job, Arc<CommonChainClient>)>,
    ) -> Result<()> {
        time::sleep(Duration::from_secs(REQUEST_RELAY_TIMEOUT)).await;

        let onchain_job = self.com_chain_jobs_contract.jobs(job.job_id).await.unwrap();

        let onchain_job: Job = Job {
            job_id: job.job_id,
            tx_hash: onchain_job.1.to_vec(),
            code_input: onchain_job.2,
            user_timout: onchain_job.3,
            starttime: onchain_job.4,
            max_gas_price: U256::zero(),
            deposit: H160::zero(),
            callback_deposit: U256::zero(),
            req_chain_id: onchain_job.0.as_u64(),
            job_owner: onchain_job.5,
            job_type: JobType::JobRelay,
            retry_number: onchain_job.8,
            gateway_address: Some(onchain_job.6),
        };

        if onchain_job.tx_hash != FixedBytes::default()
            && onchain_job.code_input != Bytes::default()
            && onchain_job.user_timout != U256::zero()
            && onchain_job.starttime != U256::zero()
            && onchain_job.req_chain_id != 0
            && onchain_job.job_owner != H160::zero()
            && onchain_job.gateway_address != Some(H160::zero())
            && onchain_job.retry_number == job.retry_number
        {
            info!("Job ID: {:?}, JobRelayed event triggered", job.job_id);
            return Ok(());
        }

        // slash the previous gateway
        {
            let self_clone = self.clone();
            let mut job_clone = job.clone();
            job_clone.job_type = JobType::SlashGatewayJob;
            let tx_clone = tx.clone();
            tx_clone.send((job_clone, self_clone)).await.unwrap();
        }

        job.retry_number += 1;
        if job.retry_number >= MAX_GATEWAY_RETRIES {
            info!("Job ID: {:?}, Max retries reached", job.job_id);
            return Ok(());
        }
        job.gateway_address = None;

        self.job_placed_handler(&job.req_chain_id.to_string(), job, tx)
            .await;

        Ok(())
    }

    async fn select_gateway_for_job_relayed(
        &self,
        job: Job,
        req_chain_client: Arc<RequestChainClient>,
    ) -> Result<Address> {
        let next_block_number = get_next_block_number(&self.recent_blocks, job.starttime.as_u64())
            .await
            .context("Failed to get the next block number")?;

        // fetch all gateways' using getAllGateways function from the contract
        let gateways: Vec<common_chain_gateway_contract::Gateway> = self
            .gateway_contract
            .get_active_gateways_for_req_chain(req_chain_client.chain_id.into())
            .block(next_block_number)
            .call()
            .await
            .context("Failed to get all gateways")?;

        // convert Vec<Gateway> to Vec<GatewayData>
        let mut gateway_data: Vec<GatewayData> = vec![];
        for gateway in gateways {
            let request_chains: Vec<RequestChainData> = vec![];
            gateway_data.push(GatewayData {
                address: gateway.operator,
                request_chains,
                stake_amount: gateway.stake_amount,
                status: gateway.status,
            });
        }

        // create a weighted probability distribution for gateways based on stake amount
        // For example, if there are 3 gateways with stake amounts 100, 200, 300
        // then the distribution arrat will be [100, 300, 600]
        let mut stake_distribution: Vec<u64> = vec![];
        let mut total_stake: u64 = 0;
        for gateway in gateway_data.iter() {
            total_stake += gateway.stake_amount.as_u64();
            stake_distribution.push(total_stake);
        }

        // random number between 1 to total_stake from the job timestamp as a seed for the weighted random selection.
        let seed = job.starttime.as_u64();
        // use this seed in std_rng to generate a random number between 1 to total_stake
        let mut rng = StdRng::seed_from_u64(seed);
        let random_number = rng.gen_range(1..=total_stake);

        // select the gateway based on the random number
        // TODO: Can use binary search on stake_distribution to optimize this.
        let selected_gateway = gateway_data
            .iter()
            .zip(stake_distribution.iter())
            .find(|(_, stake)| random_number <= **stake)
            .map(|(gateway, _)| gateway)
            .context("Failed to select a gateway")?;

        info!(
            "Job ID: {:?}, Gateway Address: {:?}",
            job.job_id, selected_gateway.address
        );

        Ok(selected_gateway.address)
    }

    async fn txns_to_common_chain(
        self: Arc<Self>,
        mut rx: Receiver<(Job, Arc<CommonChainClient>)>,
    ) -> Result<()> {
        while let Some((job, com_chain_client)) = rx.recv().await {
            match job.job_type {
                JobType::JobRelay => {
                    let com_chain_client_clone = com_chain_client.clone();
                    let job_clone = job.clone();
                    com_chain_client_clone.relay_job_txn(job_clone).await;
                    com_chain_client.remove_job(job).await;
                }
                JobType::SlashGatewayJob => {
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
            job.user_timout.as_u64(),
            &job.job_owner,
            job.retry_number,
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
            job.user_timout,
            job.starttime,
            job.retry_number,
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

    async fn remove_job(self: Arc<Self>, job: Job) {
        let mut active_jobs = self.active_jobs.write().await;
        // The retry number check is to make sure we are removing the correct job from the active jobs list
        // In a case where this txn took longer than the REQUEST_RELAY_TIMEOUT, the job might have been retried
        // and the active_jobs list might have the same job_id with a different retry number.
        if active_jobs.contains_key(&job.job_id)
            && active_jobs[&job.job_id].retry_number == job.retry_number
        {
            active_jobs.remove(&job.job_id);
        }
    }

    async fn cancel_job_with_job_id(self: Arc<Self>, job_id: U256) {
        info!("Remove the job from the active jobs list");

        // scope for the write lock
        {
            self.active_jobs.write().await.remove(&job_id);
        }
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
            signature,
            job.retry_number,
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

        // scope for the write lock
        {
            // Update the 'recent_blocks' map
            recent_blocks.write().await.insert(
                timestamp,
                BlockData {
                    number: latest_block,
                    timestamp,
                },
            );
        }

        // Prune old entries
        prune_old_blocks(&recent_blocks).await;
    }
}
