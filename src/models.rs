use alloy::primitives::{Address, Bytes};
use alloy::signers::local::PrivateKeySigner;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

#[derive(Clone, Debug)]
pub(crate) struct Transaction {
    pub id: String,
    pub contract_address: Address,
    pub transaction_data: Bytes,
    pub timeout: Instant,
    pub private_signer: PrivateKeySigner,
    pub nonce: Option<u64>,
    pub(crate) gas_price: u128,
    pub(crate) estimated_gas: u64,
    pub txn_hash: Option<String>,
    pub status: TxnStatus,
    pub(crate) last_monitored: Instant,
}

#[derive(Debug)]
pub struct TxnManager {
    pub rpc_url: String,
    pub chain_id: u64,
    pub private_signer: Arc<RwLock<PrivateKeySigner>>,
    pub(crate) nonce_to_send: Arc<RwLock<u64>>,
    pub(crate) transactions: Arc<RwLock<HashMap<String, Transaction>>>,
    pub(crate) gas_price_increment_percent: u128,
    pub(crate) gas_limit_increment_amount: u64,
    pub(crate) transaction_ids_queue: Arc<RwLock<VecDeque<String>>>,
    pub(crate) garbage_collect_interval_sec: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxnStatus {
    Sending,
    Pending,
    Confirmed,
    Failed,
}
