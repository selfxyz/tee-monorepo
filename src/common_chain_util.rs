use anyhow::{anyhow, Result};
use ethers::abi::FixedBytes;
use ethers::prelude::*;
use ethers::types::{Address, U256};
use ethers::utils::keccak256;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tiny_keccak::{Hasher, Keccak};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct BlockData {
    pub number: u64,
    pub timestamp: u64,
}

pub async fn prune_old_blocks(recent_blocks: &Arc<RwLock<BTreeMap<u64, BlockData>>>) {
    // Define the cutoff time
    let oldest_valid_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        - 120; // 2 minutes data retention

    // scope for the write lock
    {
        // Remove entries older than the cutoff time
        recent_blocks
            .write()
            .await
            .retain(|timestamp, _| timestamp > &oldest_valid_timestamp);
    }
}

pub async fn get_next_block_number(
    recent_blocks: &Arc<RwLock<BTreeMap<u64, BlockData>>>,
    timestamp: u64,
) -> Option<u64> {
    let mut block_number: Option<u64> = None;
    while block_number.is_none() {
        // scope for the read lock
        {
            let recent_blocks_state = recent_blocks.read().await;
            for (&_block_timestamp, block_data) in recent_blocks_state.range((
                std::ops::Bound::Excluded(timestamp),
                std::ops::Bound::Unbounded,
            )) {
                block_number = Some(block_data.number);
            }
        }
        // TODO: Use a subsription mechanism to avoid polling for future dev.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    block_number
}

pub fn pub_key_to_address(pub_key: &[u8]) -> Result<Address> {
    if pub_key.len() != 64 {
        return Err(anyhow!("Invalid public key length"));
    }

    let hash = keccak256(pub_key);
    let addr_bytes: [u8; 20] = hash[12..].try_into()?;
    Ok(Address::from_slice(&addr_bytes))
}

pub async fn sign_relay_job_response(
    signer_key: &SigningKey,
    job_id: U256,
    req_chain_id: U256,
    codehash: &FixedBytes,
    code_inputs: &Bytes,
    deadline: u64,
    job_owner: &Address,
    retry_number: u8,
) -> Option<String> {
    let mut job_id_bytes = [0u8; 32];
    job_id.to_big_endian(&mut job_id_bytes);

    let mut req_chain_id_bytes = [0u8; 32];
    req_chain_id.to_big_endian(&mut req_chain_id_bytes);

    let mut hasher = Keccak::v256();
    hasher.update(b"|jobId|");
    hasher.update(&job_id_bytes);
    hasher.update(b"|chainId|");
    hasher.update(&req_chain_id_bytes);
    hasher.update(b"|codehash|");
    hasher.update(codehash);
    hasher.update(b"|codeInputs|");
    hasher.update(code_inputs);
    hasher.update(b"|deadline|");
    hasher.update(&deadline.to_be_bytes());
    hasher.update(b"|jobOwner|");
    hasher.update(job_owner.as_bytes());
    hasher.update(b"|retryNumber|");
    hasher.update(&retry_number.to_be_bytes());

    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    let Ok((rs, v)) = signer_key.sign_prehash_recoverable(&hash).map_err(|err| {
        eprintln!("Failed to sign the response: {}", err);
        err
    }) else {
        return None;
    };

    Some(hex::encode(rs.to_bytes().append(27 + v.to_byte())))
}

pub async fn sign_reassign_gateway_relay_response(
    signer_key: &SigningKey,
    job_id: U256,
    gateway_operator_old: &Address,
) -> Option<String> {
    let mut job_id_bytes = [0u8; 32];
    job_id.to_big_endian(&mut job_id_bytes);

    let mut hasher = Keccak::v256();
    hasher.update(b"|jobId|");
    hasher.update(&job_id_bytes);
    hasher.update(b"|gatewayOperatorOld|");
    hasher.update(gateway_operator_old.as_bytes());

    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    let Ok((rs, v)) = signer_key.sign_prehash_recoverable(&hash).map_err(|err| {
        eprintln!("Failed to sign the response: {}", err);
        err
    }) else {
        return None;
    };

    Some(hex::encode(rs.to_bytes().append(27 + v.to_byte())))
}
