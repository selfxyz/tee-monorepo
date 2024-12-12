use alloy::primitives::{Address, Bytes};
use alloy::signers::local::PrivateKeySigner;
use std::time::Instant;

#[derive(Clone, Debug)]
pub(crate) struct Transaction {
    pub(crate) id: String,
    pub(crate) contract_address: Address,
    pub(crate) transaction_data: Bytes,
    pub(crate) timeout: Instant,
    pub(crate) private_signer: PrivateKeySigner,
    pub(crate) nonce: Option<u64>,
    pub(crate) gas_price: u128,
    pub(crate) estimated_gas: u64,
    pub(crate) txn_hash: Option<String>,
    pub(crate) status: TxnStatus,
    pub(crate) last_monitored: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxnStatus {
    Sending,
    Pending,
    Confirmed,
    Failed,
}
