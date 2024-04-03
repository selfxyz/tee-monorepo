use std::collections::{BTreeMap, HashMap};
use std::error::Error;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ethers::abi::{decode, Address, ParamType};
use ethers::prelude::*;
use ethers::providers::Provider;
use ethers::utils::keccak256;
use k256::ecdsa::SigningKey;
use log::{error, info};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::{task, time};

use crate::common_chain_util::{get_next_block_number, prune_old_blocks, sign_response, BlockData, pub_key_to_address};
use crate::HttpProvider;

abigen!(CommonChainContract, "./CommonChainContract.json",);
abigen!(CommonChainGateway, "./CommonChainGateway.json",);
abigen!(RequestChainContract, "./RequestChainContract.json",);
abigen!(CommonChainJobs, "./CommonChainJobs.json",);

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
    pub gateway_contract: CommonChainGateway<HttpProvider>,
    pub com_chain_contract: CommonChainContract<HttpProvider>,
    pub req_chain_clients: HashMap<String, Arc<RequestChainClient>>,
    pub recent_blocks: Arc<RwLock<BTreeMap<u64, BlockData>>>,
    pub request_chain_list: Vec<RequestChainData>,
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
pub struct Job {
    pub job_id: U256,
    pub tx_hash: H256,
    pub code_input: Bytes,
    pub user_timout: U256,
    pub starttime: U256,
    pub max_gas_price: U256,
    pub deposit: Address,
    pub callback_deposit: U256,
    pub req_chain_id: u64,
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

        let gateway_contract =
            CommonChainGateway::new(gateway_contract_addr.clone(), chain_http_provider.clone());
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

        let com_chain_contract =
            CommonChainContract::new(contract_addr.clone(), chain_http_provider.clone());

        info!("Gateway Data fetched. Common Chain Client Initialized");

        let chain_ws_client = Provider::<Ws>::connect_with_reconnects(com_chain_ws_url, 5)
            .await
            .context(
                "Failed to connect to the chain websocket provider. Please check the chain url.",
            ).unwrap();

        CommonChainClient {
            signer,
            enclave_signer_key,
            address: pub_key_to_address(&enclave_pub_key).unwrap(),
            chain_ws_client,
            contract_addr: *contract_addr,
            gateway_contract_addr: *gateway_contract_addr,
            start_block,
            gateway_contract,
            com_chain_contract,
            req_chain_clients: HashMap::new(),
            recent_blocks: recent_blocks,
            request_chain_list,
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        let (req_chain_tx, com_chain_rx) = channel::<(Job, Arc<CommonChainClient>)>(100);
        let self_clone = Arc::clone(&self);
        self_clone.tx_to_common_chain(com_chain_rx).await?;
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
        while let Some(request_chain) = req_chain_data.pop() {
            let signer = self
                .signer
                .clone()
                .with_chain_id(request_chain.chain_id);
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
                request_chain.chain_id
            );
            info!(
                "Subscribing to events for chain_id: {}",
                request_chain.chain_id
            );

            let req_chain_client = Arc::from(RequestChainClient {
                chain_id: request_chain.chain_id,
                contract_address: request_chain.contract_address,
                rpc_url: request_chain.rpc_url,
                contract,
            });

            let req_chain_client_clone = Arc::clone(&req_chain_client);
            let self_clone = Arc::clone(&self);
            let tx_clone = tx.clone();

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
                    let tx = tx_clone.clone();
                    task::spawn(async move {
                        self_clone.job_placed_handler(req_chain_client, log, tx.clone()).await;
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
        tx: Sender<(Job, Arc<CommonChainClient>)>,
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
            req_chain_id: req_chain_client.chain_id.clone(),
        };

        let gateway_address = self
            .select_gateway_for_job_relayed(job.clone(), req_chain_client)
            .await
            .context("Failed to select a gateway for the job")
            .unwrap();

        info!(
            "Job ID: {:?}, Gateway Address: {:?}",
            job.job_id, gateway_address
        );

        if gateway_address == self.address {
            tx.send((job, self.clone())).await.unwrap();
        }
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
        let gateways: Vec<common_chain_gateway::Gateway> = self
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

        Ok(selected_gateway.address)
    }

    async fn tx_to_common_chain(
        self: Arc<Self>,
        mut rx: Receiver<(Job, Arc<CommonChainClient>)>,
    ) -> Result<()> {
        while let Some((job, com_chain_client)) = rx.recv().await {
            info!("Creating a transaction for relayJob");
            //TODO let signature = sign_response(&self.enclave_signer_key, job.job_id, job.req_chain_id.into(), codehash, code_inputs, deadline, job_owner);
        }

        Ok(())
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
