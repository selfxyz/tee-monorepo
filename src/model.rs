use ethers::abi::FixedBytes;
use ethers::signers::LocalWallet;
use ethers::types::{Address, Bytes};
use ethers::types::{H160, U256};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

use crate::contract_abi::{GatewayJobsContract, GatewaysContract, RelayContract};
use crate::HttpProvider;

#[derive(Debug)]
pub struct AppState {
    pub enclave_signer_key: SigningKey,
    pub enclave_address: H160,
    pub wallet: Mutex<Option<LocalWallet>>,
    pub common_chain_id: u64,
    pub common_chain_http_url: String,
    pub common_chain_ws_url: String,
    pub gateways_contract_addr: Address,
    pub gateway_jobs_contract_addr: Address,
    pub request_chain_ids: Mutex<HashSet<u64>>,
    pub request_chain_data: Mutex<Vec<RequestChainData>>,
    pub registered: Mutex<bool>,
    pub epoch: u64,
    pub time_interval: u64,
    pub enclave_owner: Mutex<H160>,
    pub immutable_params_injected: Mutex<bool>,
    pub mutable_params_injected: Mutex<bool>,
    pub registration_events_listener_active: Mutex<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImmutableConfig {
    pub owner_address_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MutableConfig {
    pub gas_key_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedRegistrationBody {
    pub chain_ids: Vec<u64>,
}

pub enum RegisterType {
    CommonChain,
    RequestChain,
}

pub struct RegisteredData {
    pub register_type: RegisterType,
    pub chain_id: Option<u64>,
}

pub struct ConfigManager {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub common_chain_id: u64,
    pub common_chain_http_url: String,
    pub common_chain_ws_url: String,
    pub gateways_contract_addr: H160,
    pub gateway_jobs_contract_addr: H160,
    pub enclave_secret_key: String,
    pub epoch: u64,
    pub time_interval: u64,
}

#[derive(Debug, Clone)]
pub struct GatewayData {
    pub last_block_number: u64,
    pub address: Address,
    pub stake_amount: U256,
    pub req_chain_ids: BTreeSet<u64>,
    pub draining: bool,
}

#[derive(Debug, Clone)]
pub struct ContractsClient {
    pub enclave_owner: Address,
    pub signer: LocalWallet,
    pub enclave_signer_key: SigningKey,
    pub enclave_address: Address,
    pub common_chain_ws_url: String,
    pub common_chain_http_provider: Arc<HttpProvider>,
    pub gateways_contract: GatewaysContract<HttpProvider>,
    pub gateway_jobs_contract: GatewayJobsContract<HttpProvider>,
    pub request_chain_clients: HashMap<u64, Arc<RequestChainClient>>,
    pub gateway_epoch_state: Arc<RwLock<BTreeMap<u64, BTreeMap<Address, GatewayData>>>>,
    pub request_chain_ids: HashSet<u64>,
    pub active_jobs: Arc<RwLock<HashMap<U256, Job>>>,
    pub current_jobs: Arc<RwLock<HashMap<U256, Job>>>,
    pub epoch: u64,
    pub time_interval: u64,
    pub gateway_epoch_state_waitlist: Arc<RwLock<HashMap<u64, Vec<Job>>>>,
    pub common_chain_start_block_number: Arc<Mutex<u64>>,
}

#[derive(Debug, Clone)]
pub struct RequestChainData {
    pub chain_id: u64,
    pub contract_address: Address,
    pub http_rpc_url: String,
    pub ws_rpc_url: String,
}

#[derive(Debug, Clone)]
pub struct RequestChainClient {
    pub chain_id: u64,
    pub contract_address: Address,
    pub ws_rpc_url: String,
    pub contract: RelayContract<HttpProvider>,
    pub request_chain_start_block_number: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GatewayJobType {
    JobRelay,
    SlashGatewayJob,
    JobResponded,
    // SlashGatewayResponse,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Job {
    pub job_id: U256,
    pub request_chain_id: u64,
    pub tx_hash: FixedBytes,
    pub code_input: Bytes,
    pub user_timeout: U256,
    pub starttime: U256,
    pub job_owner: Address,
    pub job_type: GatewayJobType,
    pub sequence_number: u8,
    pub gateway_address: Option<Address>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResponseJob {
    pub job_id: U256,
    pub request_chain_id: u64,
    pub output: Bytes,
    pub total_time: U256,
    pub error_code: u8,
    pub job_type: GatewayJobType,
    pub gateway_address: Option<Address>,
    // pub sequence_number: u8,
}
