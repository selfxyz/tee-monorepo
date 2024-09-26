use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use actix_web::web::Bytes;
use anyhow::{Context, Result};
use ethers::abi::{Abi, Token};
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::LocalWallet;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Eip1559TransactionRequest, H160, H256, U256};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

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
    pub enclave_store_contract_addr: H160,
    pub secret_store_contract_addr: H160,
    pub num_selected_stores: u8,
    pub enclave_signer_file: String,
    pub acknowledgement_timeout: U256,
}

// App data struct containing the necessary fields to run the secret store
#[derive(Debug)]
pub struct AppState {
    pub secret_store_path: String,
    pub common_chain_id: u64,
    pub http_rpc_url: String,
    pub web_socket_url: String,
    pub enclave_store_contract_addr: Address,
    pub secret_store_contract_addr: Address,
    pub num_selected_stores: u8,
    pub enclave_address: H160,
    pub enclave_signer: SigningKey,
    pub immutable_params_injected: Mutex<bool>,
    pub mutable_params_injected: Mutex<bool>,
    pub enclave_owner: Mutex<H160>,
    pub http_rpc_client: Mutex<Option<HttpSignerProvider>>,
    pub secret_storage_contract_abi: Abi,
    pub nonce_to_send: Mutex<U256>,
    pub enclave_registered: AtomicBool,
    pub events_listener_active: Mutex<bool>,
    pub last_block_seen: AtomicU64,
    pub acknowledgement_timeout: U256,
    pub secrets_awaiting_acknowledgement: Mutex<HashMap<U256, u8>>,
    pub secrets_created: Mutex<HashMap<U256, SecretCreatedMetadata>>,
    pub secrets_stored: Mutex<HashMap<U256, SecretMetadata>>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageProof {
    pub secret_id: U256,
}

#[derive(Debug, Clone)]
pub struct SecretMetadata {
    pub owner: Address,
    pub size_limit: U256,
    pub end_timestamp_millis: U256,
}

#[derive(Debug, Clone)]
pub struct SecretCreatedMetadata {
    pub secret_metadata: SecretMetadata,
    pub acknowledgement_deadline: Instant,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SecretsTxnType {
    ACKNOWLEDGEMENT,
    AcknowledgementTimeout,
}

impl SecretsTxnType {
    pub fn as_str(&self) -> &str {
        match self {
            SecretsTxnType::ACKNOWLEDGEMENT => "acknowledgement",
            SecretsTxnType::AcknowledgementTimeout => "acknowledgement timeout",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretsTxnMetadata {
    pub txn_type: SecretsTxnType,
    pub secret_id: U256,
    pub sign_timestamp: Option<U256>,
    pub signature: Option<Bytes>,
    pub retry_deadline: Instant,
}

#[derive(Debug, Clone)]
pub struct PendingTxnData {
    pub txn_hash: H256,
    pub txn_data: SecretsTxnMetadata,
    pub http_rpc_client: HttpSignerProvider,
    pub nonce: U256,
    pub gas_limit: U256,
    pub gas_price: U256,
    pub last_monitor_instant: Instant,
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

// Returns the 'SecretStore' Contract Abi object for encoding transaction data, takes the JSON ABI from 'SecretStore.json' file
pub fn load_abi_from_file() -> Result<Abi> {
    let abi_json = include_str!("../SecretStore.json");
    let contract: Abi = from_str(&abi_json).context(
        "Failed to deserialize 'SecretStore' contract ABI from the Json file SecretStore.json",
    )?;

    Ok(contract)
}

// Create and write secret to a file location asynchronously
pub async fn create_and_populate_file(path: String, data: &[u8]) -> Result<()> {
    let mut file = File::create(&path).await?;

    file.write_all(data).await?;

    Ok(())
}

// Open and read secret from the file location asynchronously
pub async fn open_and_read_file(path: String) -> Result<Vec<u8>> {
    let mut file = File::open(path).await?;

    let mut secret = Vec::new();

    file.read_to_end(&mut secret).await?;

    Ok(secret)
}

// Function to return the 'SecretStore' txn data based on the txn type received, using the contract Abi object
pub fn generate_txn(
    secret_storage_contract_abi: &Abi,
    secret_storage_contract_addr: Address,
    secrets_txn_metadata: &SecretsTxnMetadata,
) -> Result<TypedTransaction> {
    let txn_data = match secrets_txn_metadata.txn_type {
        SecretsTxnType::ACKNOWLEDGEMENT => {
            // Get the encoding 'Function' object for acknowledgeStore transaction
            let acknowledge_store = secret_storage_contract_abi.function("acknowledgeStore")?;
            let params = vec![
                Token::Uint(secrets_txn_metadata.secret_id),
                Token::Uint(secrets_txn_metadata.sign_timestamp.clone().unwrap()),
                Token::Bytes(secrets_txn_metadata.signature.clone().unwrap().into()),
            ];

            acknowledge_store.encode_input(&params)?
        }
        SecretsTxnType::AcknowledgementTimeout => {
            // Get the encoding 'Function' object for acknowledgeStoreFailed transaction
            let acknowledge_store_failed =
                secret_storage_contract_abi.function("acknowledgeStoreFailed")?;
            let params = vec![Token::Uint(secrets_txn_metadata.secret_id)];

            acknowledge_store_failed.encode_input(&params)?
        }
    };

    // Return the TransactionRequest object using the encoded data and 'SecretStore' contract address
    Ok(TypedTransaction::Eip1559(Eip1559TransactionRequest {
        to: Some(secret_storage_contract_addr.into()),
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
    deadline: Instant,
) -> Option<(U256, U256)> {
    let mut gas_price = U256::zero();

    while Instant::now() < deadline {
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

    while Instant::now() < deadline {
        // Estimate the gas required for the TransactionRequest from the rpc, retry otherwise
        let estimated_gas = http_rpc_client.estimate_gas(txn, None).await;
        let Ok(estimated_gas) = estimated_gas else {
            let error_string = format!("{:?}", estimated_gas.unwrap_err());
            eprintln!(
                "Failed to estimate gas from the rpc for sending a 'SecretStore' transaction: {:?}",
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

// Conversion function using pre-built `Address::from_slice`
pub fn h256_to_address(hash: H256) -> Address {
    Address::from_slice(&hash.as_bytes()[12..]) // Extract last 20 bytes
}
