use alloy::primitives::{Address, Bytes};
use alloy::signers::local::PrivateKeySigner;
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxnStatus {
    Sending,
    Pending,
    Confirmed,
    Failed,
}
