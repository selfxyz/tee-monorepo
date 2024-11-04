use alloy::dyn_abi::DynSolValue;
use alloy::eips::eip4844::builder;
use alloy::hex::FromHex;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::k256::elliptic_curve::generic_array::sequence::Lengthen;
use alloy::signers::{local::PrivateKeySigner, Signer};
use alloy::sol;
use anyhow::Context;
use rand::Rng;
use reqwest::Url;
use serde_json::json;
use std::fs;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use transaction::TxnManager;
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    GatewayJobsContract,
    "./GatewayJobs.json"
);

#[derive(Debug, Clone, PartialEq)]
pub enum GatewayJobType {
    JobRelay,
    SlashGatewayJob,
    JobResponded,
    // SlashGatewayResponse,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JobMode {
    Once,
    Subscription,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Job {
    pub job_id: U256,
    pub request_chain_id: u64,
    pub tx_hash: FixedBytes<32>,
    pub code_input: Bytes,
    pub user_timeout: U256,
    pub starttime: U256,
    pub job_owner: Address,
    pub job_type: GatewayJobType,
    pub sequence_number: u8,
    pub gateway_address: Option<Address>,
    pub job_mode: JobMode,
    pub env: u8,
}

pub async fn sign_relay_job_request(
    signer_key: &SigningKey,
    job_id: U256,
    codehash: &FixedBytes<32>,
    code_inputs: &Bytes,
    user_timeout: U256,
    job_start_time: U256,
    sequence_number: u8,
    job_owner: &Address,
    env: u8,
) -> Option<(String, u64)> {
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let relay_job_typehash = keccak256(
            "RelayJob(uint256 jobId,bytes32 codeHash,bytes codeInputs,uint256 deadline,uint256 jobRequestTimestamp,uint8 sequenceId,address jobOwner,uint8 env,uint256 signTimestamp)"
        );

    let code_inputs_hash = keccak256(code_inputs);

    let token_list = DynSolValue::Tuple(vec![
        DynSolValue::FixedBytes(relay_job_typehash, 32),
        DynSolValue::Uint(job_id, 256),
        DynSolValue::FixedBytes(*codehash, 32),
        DynSolValue::FixedBytes(code_inputs_hash, 32),
        DynSolValue::Uint(user_timeout, 256),
        DynSolValue::Uint(job_start_time, 256),
        DynSolValue::Uint(U256::from(sequence_number), 8),
        DynSolValue::Address(*job_owner),
        DynSolValue::Uint(U256::from(env), 8),
        DynSolValue::Uint(U256::from(sign_timestamp), 256),
    ]);

    let hash_struct = keccak256(token_list.abi_encode());

    let gateway_jobs_domain_separator = keccak256(
        DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(keccak256("EIP712Domain(string name,string version)"), 32),
            DynSolValue::FixedBytes(keccak256("marlin.oyster.GatewayJobs"), 32),
            DynSolValue::FixedBytes(keccak256("1"), 32),
        ])
        .abi_encode(),
    );

    let digest = DynSolValue::Tuple(vec![
        DynSolValue::String("\x19\x01".to_string()),
        DynSolValue::FixedBytes(gateway_jobs_domain_separator, 32),
        DynSolValue::FixedBytes(hash_struct, 32),
    ])
    .abi_encode_packed();

    let digest = keccak256(digest);

    // Sign the digest using enclave key
    let sig = signer_key.sign_prehash_recoverable(&digest.to_vec());
    let Ok((rs, v)) = sig else {
        eprintln!("Failed to sign the digest: {:#?}", sig.err());
        return None;
    };

    Some((
        hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
        sign_timestamp,
    ))
}
