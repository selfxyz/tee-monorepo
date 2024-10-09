use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use actix_web::web::Data;
use anyhow::{Context, Error, Result};
use ethers::abi::{encode, encode_packed, Abi, Token};
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::LocalWallet;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Eip1559TransactionRequest, H160, H256, U256};
use ethers::utils::keccak256;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

// TODO: add support for automatically determining enclave storage capacity based on system config
pub const SECRET_STORAGE_CAPACITY: usize = 100000000; // this is roughly 95 MB

// Retry interval (in milliseconds) for HTTP requests
pub const HTTP_CALL_RETRY_DELAY: u64 = 10;
// Fixed buffer to add to the estimated gas for setting gas limit
pub const GAS_LIMIT_BUFFER: u64 = 200000;
// Gas price increment percent while resending pending/dropped txns
pub const RESEND_GAS_PRICE_INCREMENT_PERCENT: u64 = 10;
// Interval (in secs) in which to confirm/resend pending/dropped txns
pub const RESEND_TXN_INTERVAL: u64 = 5;
// Deadline (in secs) for resending pending/dropped acknowledgement timeout txns
pub const ACKNOWLEDGEMENT_TIMEOUT_TXN_RESEND_DEADLINE: u64 = 20;
// Domain separator constant for SecretManager Transactions
pub const DOMAIN_SEPARATOR: Lazy<[u8; 32]> = Lazy::new(|| {
    keccak256(encode(&[
        Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
        Token::FixedBytes(keccak256("marlin.oyster.SecretManager").to_vec()),
        Token::FixedBytes(keccak256("1").to_vec()),
    ]))
});

pub type HttpSignerProvider = SignerMiddleware<Provider<Http>, LocalWallet>;

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
    pub secret_store_contract_addr: H160,
    pub secret_manager_contract_addr: H160,
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
    pub num_selected_stores: u8,
    pub enclave_address: H160,
    pub enclave_signer: SigningKey,
    pub immutable_params_injected: Mutex<bool>,
    pub mutable_params_injected: Mutex<bool>,
    pub enclave_owner: Mutex<H160>,
    pub http_rpc_client: Mutex<Option<HttpSignerProvider>>,
    pub secret_manager_contract_abi: Abi,
    pub nonce_to_send: Mutex<U256>,
    pub enclave_registered: AtomicBool,
    pub events_listener_active: Mutex<bool>,
    pub last_block_seen: AtomicU64,
    pub acknowledgement_timeout: u64,
    pub mark_alive_timeout: u64,
    pub secrets_awaiting_acknowledgement: Mutex<HashMap<U256, u8>>,
    pub secrets_created: Mutex<HashMap<U256, SecretCreatedMetadata>>,
    pub secrets_stored: Mutex<HashMap<U256, SecretStoredMetadata>>,
    pub secrets_txn_sender_channel: Mutex<Option<Sender<SecretsTxnMetadata>>>,
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
    pub acknowledgement_deadline: SystemTime,
}

#[derive(Debug, Clone)]
pub struct SecretStoredMetadata {
    pub secret_metadata: SecretMetadata,
    pub last_alive_time: SystemTime,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SecretsTxnType {
    Acknowledgement,
    AcknowledgementTimeout,
    MarkStoreAlive,
}

impl SecretsTxnType {
    pub fn as_str(&self) -> &str {
        match self {
            SecretsTxnType::Acknowledgement => "acknowledgement",
            SecretsTxnType::AcknowledgementTimeout => "acknowledgement timeout",
            SecretsTxnType::MarkStoreAlive => "mark alive",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretsTxnMetadata {
    pub txn_type: SecretsTxnType,
    pub secret_id: U256,
    pub retry_deadline: SystemTime,
}

#[derive(Debug, Clone)]
pub struct PendingTxnData {
    pub txn_hash: H256,
    pub txn_data: SecretsTxnMetadata,
    pub http_rpc_client: HttpSignerProvider,
    pub nonce: U256,
    pub gas_limit: U256,
    pub gas_price: U256,
    pub last_monitor_instant: SystemTime,
}

pub enum RpcTxnSendError {
    NonceTooLow,
    NonceTooHigh,
    OutOfGas,
    GasTooHigh,
    GasPriceLow,
    ContractExecution,
    NetworkConnectivity,
    OtherRetryable,
}

// Returns the 'SecretManager' Contract Abi object for encoding transaction data, takes the JSON ABI from 'SecretManager.json' file
pub fn load_abi_from_file() -> Result<Abi> {
    let abi_json = include_str!("../SecretManager.json");
    let contract: Abi = from_str(&abi_json).context(
        "Failed to deserialize 'SecretManager' contract ABI from the Json file SecretManager.json",
    )?;

    Ok(contract)
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

// Function to return the 'SecretManager' txn data based on the txn type received, using the contract Abi object
pub fn generate_txn(
    app_state: Data<AppState>,
    secrets_txn_metadata: &SecretsTxnMetadata,
) -> Result<TypedTransaction> {
    let txn_data = match secrets_txn_metadata.txn_type {
        SecretsTxnType::Acknowledgement => {
            // Initialize the current sign timestamp and update the last alive time for the secret ID
            let sign_timestamp = SystemTime::now();
            app_state
                .secrets_stored
                .lock()
                .unwrap()
                .entry(secrets_txn_metadata.secret_id)
                .and_modify(|secret| secret.last_alive_time = sign_timestamp);
            let sign_timestamp = sign_timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs();

            // Encode and hash the acknowledgement of storing the secret following EIP712 format
            let acknowledge_typehash =
                keccak256("Acknowledge(uint256 secretId,uint256 signTimestamp)");

            let hash_struct = keccak256(encode(&[
                Token::FixedBytes(acknowledge_typehash.to_vec()),
                Token::Uint(secrets_txn_metadata.secret_id),
                Token::Uint(sign_timestamp.into()),
            ]));

            // Create the digest
            let digest = keccak256(
                encode_packed(&[
                    Token::String("\x19\x01".to_string()),
                    Token::FixedBytes(DOMAIN_SEPARATOR.to_vec()),
                    Token::FixedBytes(hash_struct.to_vec()),
                ])
                .context("Failed to encode the acknowledgement message for signing")?,
            );

            // Sign the digest using enclave key
            let (rs, v) = app_state
                .enclave_signer
                .sign_prehash_recoverable(&digest)
                .context("Failed to sign the acknowledgement message using enclave key")?;
            let signature = rs.to_bytes().append(27 + v.to_byte()).to_vec();

            // Get the encoding 'Function' object for acknowledgeStore transaction
            let acknowledge_store = app_state
                .secret_manager_contract_abi
                .function("acknowledgeStore")?;
            let params = vec![
                Token::Uint(secrets_txn_metadata.secret_id),
                Token::Uint(sign_timestamp.into()),
                Token::Bytes(signature.into()),
            ];

            acknowledge_store.encode_input(&params)?
        }
        SecretsTxnType::AcknowledgementTimeout => {
            // Get the encoding 'Function' object for acknowledgeStoreFailed transaction
            let acknowledge_store_failed = app_state
                .secret_manager_contract_abi
                .function("acknowledgeStoreFailed")?;
            let params = vec![Token::Uint(secrets_txn_metadata.secret_id)];

            acknowledge_store_failed.encode_input(&params)?
        }
        SecretsTxnType::MarkStoreAlive => {
            // Get the current sign timestamp and update the last alive time for the secret ID
            let sign_timestamp = SystemTime::now();
            app_state
                .secrets_stored
                .lock()
                .unwrap()
                .entry(secrets_txn_metadata.secret_id)
                .and_modify(|secret| secret.last_alive_time = sign_timestamp);
            let sign_timestamp = sign_timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs();

            // Encode and hash the mark store alive message for the secret following EIP712 format
            let alive_typehash = keccak256("Alive(uint256 secretId,uint256 signTimestamp)");

            let hash_struct = keccak256(encode(&[
                Token::FixedBytes(alive_typehash.to_vec()),
                Token::Uint(secrets_txn_metadata.secret_id),
                Token::Uint(sign_timestamp.into()),
            ]));

            // Create the digest
            let digest = keccak256(
                encode_packed(&[
                    Token::String("\x19\x01".to_string()),
                    Token::FixedBytes(DOMAIN_SEPARATOR.to_vec()),
                    Token::FixedBytes(hash_struct.to_vec()),
                ])
                .context("Failed to encode the alive message for signing")?,
            );

            // Sign the digest using enclave key
            let (rs, v) = app_state
                .enclave_signer
                .sign_prehash_recoverable(&digest)
                .context("Failed to sign the alive message using enclave key")?;
            let signature = rs.to_bytes().append(27 + v.to_byte()).to_vec();

            // Get the encoding 'Function' object for markStoreAlive transaction
            let mark_store_alive = app_state
                .secret_manager_contract_abi
                .function("markStoreAlive")?;
            let params = vec![
                Token::Uint(secrets_txn_metadata.secret_id),
                Token::Uint(sign_timestamp.into()),
                Token::Bytes(signature.into()),
            ];

            mark_store_alive.encode_input(&params)?
        }
    };

    // Return the TransactionRequest object using the encoded data and 'SecretManager' contract address
    Ok(TypedTransaction::Eip1559(Eip1559TransactionRequest {
        to: Some(app_state.secret_manager_contract_addr.into()),
        data: Some(txn_data.into()),
        ..Default::default()
    }))
}

// Function to categorize the rpc send txn errors into relevant enums
// TODO: Add reference to the errors thrown by the rpc while sending a transaction to the network
pub fn parse_send_error(error: String) -> RpcTxnSendError {
    if error.contains("nonce too low") {
        return RpcTxnSendError::NonceTooLow;
    }

    if error.contains("nonce too high") || error.contains("too many pending transactions") {
        return RpcTxnSendError::NonceTooHigh;
    }

    if error.contains("out of gas") {
        return RpcTxnSendError::OutOfGas;
    }

    if error.contains("gas limit too high") || error.contains("transaction exceeds block gas limit")
    {
        return RpcTxnSendError::GasTooHigh;
    }

    if error.contains("gas price too low") || error.contains("transaction underpriced") {
        return RpcTxnSendError::GasPriceLow;
    }

    if error.contains("connection") || error.contains("network") {
        return RpcTxnSendError::NetworkConnectivity;
    }

    if error.contains("reverted") || error.contains("failed") {
        return RpcTxnSendError::ContractExecution;
    }

    return RpcTxnSendError::OtherRetryable;
}

// Function to retrieve the estimated gas required for a txn and the current gas price
// of the network under the retry deadline for the txn, returns `(estimated_gas, gas_price)`
pub async fn estimate_gas_and_price(
    http_rpc_client: HttpSignerProvider,
    txn: &TypedTransaction,
    deadline: SystemTime,
) -> Option<(U256, U256)> {
    let mut gas_price = U256::zero();

    while deadline.duration_since(SystemTime::now()).is_ok() {
        // Request the current gas price for the common chain from the rpc, retry otherwise
        let price = http_rpc_client.get_gas_price().await;
        let Ok(price) = price else {
            eprintln!(
                "Failed to get gas price from the rpc for the network: {:?}",
                price.unwrap_err()
            );

            sleep(Duration::from_millis(HTTP_CALL_RETRY_DELAY)).await;
            continue;
        };

        gas_price = price;
        break;
    }

    if gas_price.is_zero() {
        return None;
    }

    while deadline.duration_since(SystemTime::now()).is_ok() {
        // Estimate the gas required for the TransactionRequest from the rpc, retry otherwise
        let estimated_gas = http_rpc_client.estimate_gas(txn, None).await;
        let Ok(estimated_gas) = estimated_gas else {
            let error_string = format!("{:?}", estimated_gas.unwrap_err());
            eprintln!(
                "Failed to estimate gas from the rpc for sending a 'SecretManager' transaction: {:?}",
                error_string
            );

            match parse_send_error(error_string.to_lowercase()) {
                // Break in case the contract execution is failing for this txn or the gas required is way high compared to block gas limit
                RpcTxnSendError::GasTooHigh | RpcTxnSendError::ContractExecution => break,
                _ => {
                    sleep(Duration::from_millis(HTTP_CALL_RETRY_DELAY)).await;
                    continue;
                }
            }
        };

        return Some((estimated_gas, gas_price));
    }

    return None;
}

// Conversion function for H256 TxHash type to Address type
pub fn h256_to_address(hash: H256) -> Address {
    Address::from_slice(&hash.as_bytes()[12..]) // Extract last 20 bytes
}
