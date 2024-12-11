use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use alloy::dyn_abi::DynSolValue;
use alloy::primitives::{keccak256, Address, FixedBytes, B256, U256};
use alloy::providers::RootProvider;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::transports::http::reqwest::Url;
use alloy::transports::http::{Client, Http};
use anyhow::{anyhow, Context, Error, Result};
use multi_block_txns::TxnManager;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::secret_manager::SecretManagerContract::SecretManagerContractInstance;

pub type SecretManagerAbi = SecretManagerContractInstance<Http<Client>, RootProvider<Http<Client>>>;

// TODO: add support for automatically determining enclave storage capacity based on system config
pub const SECRET_STORAGE_CAPACITY: usize = 100000000; // this is roughly 95 MB

// Deadline (in secs) for resending pending/dropped acknowledgement timeout txns
pub const ACKNOWLEDGEMENT_TIMEOUT_TXN_RESEND_DEADLINE: u64 = 20;
// Buffer time (in secs) for sending store alive transaction under the set timeout
pub const SEND_TRANSACTION_BUFFER: u64 = 2;
// Interval (in secs) for removing expired secrets
pub const GARBAGE_CLEAN_JOB_INTERVAL: u64 = 120;
// Buffer time (in secs) for removing an expired secret
pub const SECRET_EXPIRATION_BUFFER: u64 = 2;

pub const SECRET_STORE_REGISTERED_EVENT: &str = "SecretStoreRegistered(address,address,uint256)";
pub const SECRET_STORE_DEREGISTERED_EVENT: &str = "SecretStoreDeregistered(address)";
pub const SECRET_CREATED_EVENT: &str =
    "SecretCreated(uint256,address,uint256,uint256,uint256,address[])";
pub const SECRET_STORE_ACKNOWLEDGEMENT_SUCCESS_EVENT: &str =
    "SecretStoreAcknowledgementSuccess(uint256,address)";
pub const SECRET_STORE_ACKNOWLEDGEMENT_FAILED_EVENT: &str =
    "SecretStoreAcknowledgementFailed(uint256)";
pub const SECRET_TERMINATED_EVENT: &str = "SecretTerminated(uint256,uint256)";
pub const SECRET_REMOVED_EVENT: &str = "SecretRemoved(uint256)";
pub const SECRET_STORE_REPLACED_EVENT: &str = "SecretStoreReplaced(uint256,address,address,bool)";
pub const SECRET_END_TIMESTAMP_UPDATED_EVENT: &str = "SecretEndTimestampUpdated(uint256,uint256)";

// Domain separator constant for SecretManager Transactions
pub const DOMAIN_SEPARATOR: Lazy<FixedBytes<32>> = Lazy::new(|| {
    keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
            DynSolValue::FixedBytes(keccak256("marlin.oyster.SecretManager"), 32),
            DynSolValue::FixedBytes(keccak256("1"), 32),
        ])
        .abi_encode(),
    )
});

pub struct ConfigManager {
    pub path: String,
}

// Config struct containing the secret store configuration parameters
#[derive(Debug, Deserialize)]
pub struct Config {
    pub secret_store_path: String,
    pub common_chain_id: u64,
    pub http_rpc_url: String,
    pub web_socket_url: String,
    pub secret_store_contract_addr: Address,
    pub secret_manager_contract_addr: Address,
    pub num_selected_stores: u8,
    pub enclave_signer_file: String,
    pub acknowledgement_timeout: u64,
    pub mark_alive_timeout: u64,
}

// App data struct containing the necessary fields to run the secret store
#[derive(Debug)]
pub struct AppState {
    pub secret_store_path: String,
    pub common_chain_id: u64,
    pub http_rpc_url: String,
    pub web_socket_url: String,
    pub secret_store_contract_addr: Address,
    pub secret_manager_contract_addr: Address,
    pub secret_manager_contract_instance: SecretManagerAbi,
    pub num_selected_stores: u8,
    pub enclave_address: Address,
    pub enclave_signer: SigningKey,
    pub immutable_params_injected: Mutex<bool>,
    pub mutable_params_injected: Mutex<bool>,
    pub enclave_owner: Mutex<Address>,
    pub gas_wallet: Arc<RwLock<String>>,
    pub http_rpc_txn_manager: Mutex<Option<Arc<TxnManager>>>,
    pub enclave_registered: AtomicBool,
    pub events_listener_active: Mutex<bool>,
    pub last_block_seen: AtomicU64,
    pub acknowledgement_timeout: u64,
    pub mark_alive_timeout: u64,
    pub secrets_awaiting_acknowledgement: Mutex<HashMap<U256, u8>>,
    pub secrets_created: Mutex<HashMap<U256, SecretCreatedMetadata>>,
    pub secrets_stored: Mutex<HashMap<U256, SecretMetadata>>,
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
pub struct CreateSecret {
    pub secret_id: U256,
    pub encrypted_secret_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone)]
pub struct SecretMetadata {
    pub owner: Address,
    pub size_limit: U256,
    pub end_timestamp: U256,
}

#[derive(Debug, Clone)]
pub struct SecretCreatedMetadata {
    pub secret_metadata: SecretMetadata,
    pub acknowledgement_deadline: Instant,
}

pub fn verify_rpc_url(rpc_url: &str) -> Result<()> {
    let url = Url::parse(rpc_url).context(format!("Failed to parse the RPC {:?}", rpc_url))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(anyhow!(
            "Invalid RPC URL: {:?}. URL must start with http or https",
            rpc_url
        ));
    }
    Ok(())
}

// Create and write secret to a file location asynchronously with retries
pub async fn create_and_populate_file(path: String, data: &[u8]) -> Result<()> {
    Ok(Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            // Create or open the file at the specified path
            let mut file = File::create(&path).await?;

            // Write the secret data as bytes to the file
            file.write_all(data).await?;

            Ok::<(), Error>(())
        },
    )
    .await?)
}

// Open and read secret from the file location asynchronously with retries
pub async fn open_and_read_file(path: String) -> Result<Vec<u8>> {
    Ok(Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            // Open the file at the provided location
            let mut file = File::open(&path).await?;

            // Read and copy the file contents as bytes
            let mut secret = Vec::new();
            file.read_to_end(&mut secret).await?;

            Ok::<Vec<u8>, Error>(secret)
        },
    )
    .await?)
}

// Delete a secret at a file location asynchronously if it exists there with retries
pub async fn check_and_delete_file(path: String) -> Result<()> {
    Ok(Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            match fs::remove_file(&path).await {
                Ok(_) => Ok(()),
                Err(err) => {
                    // No need to delete if the file doesn't exist
                    if err.kind() == ErrorKind::NotFound {
                        return Ok(());
                    }

                    Err(err)
                }
            }
        },
    )
    .await?)
}

// Conversion function for B256 type to Address type
pub fn b256_to_address(hash: B256) -> Address {
    Address::from_slice(&hash.0[12..]) // Extract last 20 bytes
}

pub fn timestamp_to_instant(timestamp: u64) -> Result<Instant> {
    // Get the SystemTime for the given timestamp
    let block_time = UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(timestamp))
        .ok_or_else(|| anyhow!("Invalid timestamp value"))?;

    // Get the current SystemTime and calculate the difference
    let now = SystemTime::now();
    match block_time.duration_since(now) {
        Ok(duration_from_now) => Ok(Instant::now() + duration_from_now),
        Err(duration_since_past) => Ok(Instant::now() - duration_since_past.duration()),
    }
}
