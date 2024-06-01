use anyhow::{anyhow, Result};
use ethers::abi::{encode_packed, FixedBytes, Token};
use ethers::prelude::*;
use ethers::types::{Address, U256};
use ethers::utils::keccak256;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use log::{error, info};
use std::future::Future;
use std::sync::Arc;
use tokio::time;

use crate::constant::WAIT_BEFORE_CHECKING_BLOCK;
use crate::model::{Job, RequestChainClient};
use crate::HttpProvider;

pub trait LogsProvider {
    fn common_chain_jobs<'a>(
        &'a self,
    ) -> impl Future<Output = Result<SubscriptionStream<'a, Ws, Log>>>;

    fn req_chain_jobs<'a>(
        &'a self,
        req_chain_ws_client: &'a Provider<Ws>,
        req_chain_client: &'a RequestChainClient,
    ) -> impl Future<Output = Result<SubscriptionStream<'a, Ws, Log>>>;

    fn common_chain_job_relayed_logs<'a>(
        &'a self,
        job: Job,
    ) -> impl Future<Output = Result<Vec<Log>>>;
}

pub async fn get_block_number_by_timestamp(
    provider: &Arc<HttpProvider>,
    target_timestamp: u64,
) -> Option<u64> {
    let mut block_number: u64 = 0;
    for _ in 0..20 {
        let get_block_number_result = provider.get_block_number().await;

        if get_block_number_result.is_err() {
            error!(
                "Failed to fetch block number. Error: {:#?}",
                get_block_number_result.err()
            );
            time::sleep(time::Duration::from_secs(WAIT_BEFORE_CHECKING_BLOCK)).await;
            continue;
        }

        block_number = get_block_number_result.unwrap().as_u64();
        break;
    }

    if block_number == 0 {
        error!("Failed to fetch block number");
        return None;
    }

    let mut count = 0;
    let mut block_rate_per_second: u64;
    let mut latest_block_timestamp = 0;

    'less_than_block_number: while block_number > 0 {
        let block = provider.get_block(block_number).await.unwrap().unwrap();
        // target_timestamp (the end bound of the interval) is excluded from the search
        if block.timestamp < U256::from(target_timestamp) {
            // Fetch the next block to confirm this is the latest block with timestamp < target_timestamp
            let next_block_number = block_number + 1;
            'next_block_check: loop {
                let next_block_result = provider.get_block(next_block_number).await;

                match next_block_result {
                    Ok(Some(block)) => {
                        // next_block exists
                        if block.timestamp >= U256::from(target_timestamp) {
                            // The next block's timestamp is greater than or equal to the target timestamp,
                            // so return the current block number
                            return Some(block_number);
                        }
                        block_number += 1;
                        continue 'less_than_block_number;
                    }
                    Ok(None) => {
                        // The next block does not exist.
                        // Wait for the next block to be created to be sure that
                        // the current block_number is the required block_number
                        time::sleep(time::Duration::from_secs(WAIT_BEFORE_CHECKING_BLOCK)).await;
                        continue 'next_block_check;
                    }
                    Err(_) => {
                        error!("Failed to fetch block number {}", next_block_number);
                        return None;
                    }
                }
            }
        } else {
            count += 1;
            if latest_block_timestamp == 0 {
                latest_block_timestamp = block.timestamp.as_u64();
            }
            // Calculate the block rate per second using the last 15 blocks
            if count > 15 {
                block_rate_per_second = count / (latest_block_timestamp - block.timestamp.as_u64());
                info!("Block rate per second: {}", block_rate_per_second);
                count = 0;
                latest_block_timestamp = 0;

                block_number = block_number
                    - ((block.timestamp.as_u64() - target_timestamp) * block_rate_per_second)
                    + 1;
            }
        }
        block_number -= 1;
    }
    None
}

pub fn pub_key_to_address(pub_key: &[u8]) -> Result<Address> {
    if pub_key.len() != 64 {
        return Err(anyhow!("Invalid public key length"));
    }

    let hash = keccak256(pub_key);
    let addr_bytes: [u8; 20] = hash[12..].try_into()?;
    Ok(Address::from_slice(&addr_bytes))
}

pub async fn get_key_for_job_id(job_id: U256, req_chain_id: u64) -> U256 {
    let req_chain_id = U256::from(req_chain_id);
    let hash = keccak256(format!("{}-{}", job_id, req_chain_id));
    U256::from_big_endian(&hash)
}

pub async fn sign_relay_job_response(
    signer_key: &SigningKey,
    job_id: U256,
    req_chain_id: U256,
    codehash: &FixedBytes,
    code_inputs: &Bytes,
    deadline: U256,
    job_owner: &Address,
    sequence_number: u8,
    job_start_time: U256,
) -> Option<String> {
    let token_list = [
        Token::Array(vec![Token::Uint(job_id), Token::Uint(req_chain_id)]),
        Token::FixedBytes(codehash.clone()),
        Token::Bytes(code_inputs.to_vec()),
        Token::Array(vec![Token::Uint(deadline), Token::Uint(job_start_time)]),
        Token::FixedBytes(vec![sequence_number]),
        Token::Address(*job_owner),
    ];
    let encoded_args = encode_packed(&token_list).unwrap();
    let hash = keccak256(&encoded_args);
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
    let token_list = [
        Token::Array(vec![Token::Uint(job_id)]),
        Token::Address(*gateway_operator_old),
    ];

    let encoded_args = encode_packed(&token_list).unwrap();
    let hash = keccak256(&encoded_args);

    let Ok((rs, v)) = signer_key.sign_prehash_recoverable(&hash).map_err(|err| {
        eprintln!("Failed to sign the response: {}", err);
        err
    }) else {
        return None;
    };

    Some(hex::encode(rs.to_bytes().append(27 + v.to_byte())))
}

pub async fn sign_job_response_response(
    signer_key: &SigningKey,
    job_id: U256,
    output: Bytes,
    total_time: U256,
    error_code: u8,
) -> Option<String> {
    let token_list = [
        Token::Array(vec![Token::Uint(job_id)]),
        Token::Bytes(output.to_vec()),
        Token::Array(vec![Token::Uint(total_time)]),
        Token::FixedBytes(vec![error_code]),
    ];

    let encoded_args = encode_packed(&token_list).unwrap();
    let hash = keccak256(&encoded_args);

    let Ok((rs, v)) = signer_key.sign_prehash_recoverable(&hash).map_err(|err| {
        eprintln!("Failed to sign the response: {}", err);
        err
    }) else {
        return None;
    };

    Some(hex::encode(rs.to_bytes().append(27 + v.to_byte())))
}
