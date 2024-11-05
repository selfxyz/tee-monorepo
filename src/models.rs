use alloy::primitives::{Address, Bytes};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub(crate) struct Transaction {
    pub id: String,
    pub contract_address: Address,
    pub data: Bytes,
    pub timeout: Instant,
    pub gas_wallet: String,
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
    pub gas_wallet: Arc<RwLock<String>>,
    pub(crate) nonce_to_send: Arc<RwLock<u64>>,
    pub(crate) transactions: Arc<RwLock<HashMap<String, Transaction>>>,
    pub(crate) gas_price_increment_percent: u128,
    pub(crate) gas_limit_increment_amount: u64,
    pub(crate) transactions_queue: Arc<RwLock<VecDeque<Transaction>>>,
}

#[derive(Clone, Debug)]
pub enum TxnStatus {
    Sending,
    Pending,
    Confirmed,
    Failed,
}

#[derive(Debug)]
pub enum TxnResendError {
    NonceTooLow,
    Timeout,
    TransactionFailed,
    GasWalletChanged,
}
