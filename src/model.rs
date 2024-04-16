use ethers::abi::FixedBytes;
use ethers::providers::{Provider, Ws};
use ethers::signers::LocalWallet;
use ethers::types::{Address, Bytes};
use ethers::types::{H160, U256};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::RwLock;

use crate::contract_abi::{
    CommonChainGatewayContract, CommonChainJobsContract, RequestChainContract,
};
use crate::HttpProvider;

pub struct AppState {
    pub enclave_signer_key: SigningKey,
    pub wallet: Mutex<Option<LocalWallet>>,
    pub common_chain_id: u64,
    pub common_chain_http_url: String,
    pub common_chain_ws_url: String,
    pub gateway_contract_addr: Address,
    pub job_contract_addr: Address,
    pub chain_list: Mutex<Vec<RequestChainData>>,
    pub registered: Mutex<bool>,
    pub enclave_pub_key: Bytes,
    pub gateway_epoch_state: Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
    pub epoch: u64,
    pub time_interval: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InjectKeyInfo {
    pub operator_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterEnclaveInfo {
    pub attestation: String,
    pub pcr_0: String,
    pub pcr_1: String,
    pub pcr_2: String,
    pub enclave_cpus: usize,
    pub enclave_memory: usize,
    pub timestamp: usize,
    pub stake_amount: usize,
    pub chain_list: Vec<u64>,
}

pub struct ConfigManager {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub com_chain_id: u64,
    pub com_chain_ws_url: String,
    pub com_chain_http_url: String,
    pub gateway_contract_addr: H160,
    pub job_contract_addr: H160,
    pub enclave_secret_key: String,
    pub enclave_public_key: String,
    pub epoch: u64,
    pub time_interval: u64,
}

#[derive(Debug, Clone)]
pub struct GatewayData {
    pub last_block_number: u64,
    pub address: Address,
    pub stake_amount: U256,
    pub status: bool,
    pub req_chain_ids: BTreeSet<U256>,
}

#[derive(Debug, Clone)]
pub struct CommonChainClient {
    pub signer: LocalWallet,
    pub enclave_signer_key: SigningKey,
    pub address: Address,
    pub chain_ws_client: Provider<Ws>,
    pub gateway_contract_addr: H160,
    pub contract_addr: H160,
    pub gateway_contract: CommonChainGatewayContract<HttpProvider>,
    pub com_chain_jobs_contract: CommonChainJobsContract<HttpProvider>,
    pub req_chain_clients: HashMap<String, Arc<RequestChainClient>>,
    pub gateway_epoch_state: Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
    pub request_chain_list: Vec<RequestChainData>,
    pub active_jobs: Arc<RwLock<HashMap<U256, Job>>>,
    pub epoch: u64,
    pub time_interval: u64,
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
pub enum ComChainJobType {
    JobRelay,
    SlashGatewayJob,
}

#[derive(Debug, Clone)]
pub enum ReqChainJobType {
    JobResponded,
    SlashGatewayResponse,
}

#[derive(Debug, Clone)]
pub struct Job {
    pub job_id: U256,
    pub req_chain_id: u64,
    pub job_key: U256,
    pub tx_hash: FixedBytes,
    pub code_input: Bytes,
    pub user_timout: U256,
    pub starttime: U256,
    pub max_gas_price: U256,
    pub deposit: Address,
    pub callback_deposit: U256,
    pub job_owner: Address,
    pub job_type: ComChainJobType,
    pub sequence_number: u8,
    pub gateway_address: Option<Address>,
}

#[derive(Debug, Clone)]
pub struct JobResponse {
    pub job_id: U256,
    pub req_chain_id: u64,
    pub job_key: U256,
    pub output: Bytes,
    pub total_time: U256,
    pub error_code: u8,
    pub output_count: u8,
    pub job_type: ReqChainJobType,
    pub gateway_address: Option<Address>,
    pub sequence_number: u8,
}
