use abi::encode;
use anyhow::Result;
use ethers::abi::{encode_packed, FixedBytes, Token};
use ethers::prelude::*;
use ethers::types::{Address, U256};
use ethers::utils::keccak256;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use log::{error, info};
use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time;

use crate::constant::WAIT_BEFORE_CHECKING_BLOCK;
use crate::model::{Job, RequestChainClient};
use crate::HttpProvider;

pub trait LogsProvider {
    fn common_chain_jobs<'a>(
        &'a self,
        common_chain_ws_client: &'a Provider<Ws>,
    ) -> impl Future<Output = Result<SubscriptionStream<'a, Ws, Log>>>;

    fn req_chain_jobs<'a>(
        &'a self,
        req_chain_ws_client: &'a Provider<Ws>,
        req_chain_client: &'a RequestChainClient,
    ) -> impl Future<Output = Result<SubscriptionStream<'a, Ws, Log>>>;

    fn gateways_job_relayed_logs<'a>(
        &'a self,
        job: Job,
        common_chain_ws_client: &'a Arc<HttpProvider>,
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
    let mut block_rate_per_second: f64;
    let mut latest_block_timestamp = 0;

    'less_than_block_number: while block_number > 0 {
        let block = provider.get_block(block_number).await;
        if block.is_err() {
            error!(
                "Failed to fetch block number {}. Error: {:#?}",
                block_number,
                block.err()
            );
            continue;
        }
        let block = block.unwrap();
        if block.is_none() {
            continue;
        }
        let block = block.unwrap();

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
            // Calculate the block rate per second using the last 15 or greater blocks
            // Check if the block rate per second can be calculated using latest block timestamp and block timestamp
            if count > 15 && latest_block_timestamp - block.timestamp.as_u64() != 0 {
                block_rate_per_second = (count as f64
                    / (latest_block_timestamp as f64 - block.timestamp.as_u64() as f64))
                    as f64;
                info!("Block rate per second: {}", block_rate_per_second);
                count = 0;
                latest_block_timestamp = 0;

                block_number = block_number
                    - ((block.timestamp.as_u64() - target_timestamp) as f64 * block_rate_per_second)
                        as u64
                    + 1;
            }
        }
        block_number -= 1;
    }
    None
}

pub async fn sign_relay_job_request(
    signer_key: &SigningKey,
    job_id: U256,
    codehash: &FixedBytes,
    code_inputs: &Bytes,
    user_timeout: U256,
    job_start_time: U256,
    sequence_number: u8,
    job_owner: &Address,
) -> Option<(String, u64)> {
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let relay_job_typehash = keccak256(
            "RelayJob(uint256 jobId,bytes32 codeHash,bytes codeInputs,uint256 deadline,uint256 jobRequestTimestamp,uint8 sequenceId,address jobOwner,uint256 signTimestamp)"
        );

    let code_inputs_hash = keccak256(code_inputs);

    let token_list = [
        Token::FixedBytes(relay_job_typehash.to_vec()),
        Token::Uint(job_id),
        Token::FixedBytes(codehash.clone()),
        Token::FixedBytes(code_inputs_hash.to_vec()),
        Token::Uint(user_timeout),
        Token::Uint(job_start_time),
        Token::Uint(sequence_number.into()),
        Token::Address(*job_owner),
        Token::Uint(sign_timestamp.into()),
    ];

    let hash_struct = keccak256(encode(&token_list));

    let gateway_jobs_domain_separator = keccak256(encode(&[
        Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
        Token::FixedBytes(keccak256("marlin.oyster.GatewayJobs").to_vec()),
        Token::FixedBytes(keccak256("1").to_vec()),
    ]));

    let digest = encode_packed(&[
        Token::String("\x19\x01".to_string()),
        Token::FixedBytes(gateway_jobs_domain_separator.to_vec()),
        Token::FixedBytes(hash_struct.to_vec()),
    ]);

    let Ok(digest) = digest else {
        eprintln!("Failed to encode the digest: {:#?}", digest.err());
        return None;
    };
    let digest = keccak256(digest);

    // Sign the digest using enclave key
    let sig = signer_key.sign_prehash_recoverable(&digest);
    let Ok((rs, v)) = sig else {
        eprintln!("Failed to sign the digest: {:#?}", sig.err());
        return None;
    };

    Some((
        hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
        sign_timestamp,
    ))
}

pub async fn sign_reassign_gateway_relay_request(
    signer_key: &SigningKey,
    job_id: U256,
    gateway_operator_old: &Address,
    job_owner: &Address,
    sequence_number: u8,
    job_start_time: U256,
) -> Option<(String, u64)> {
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let reassign_gateway_relay_typehash = keccak256(
            "ReassignGateway(uint256 jobId,address gatewayOld,address jobOwner,uint8 sequenceId,uint256 jobRequestTimestamp,uint256 signTimestamp)"
        );

    let token_list = [
        Token::FixedBytes(reassign_gateway_relay_typehash.to_vec()),
        Token::Uint(job_id),
        Token::Address(*gateway_operator_old),
        Token::Address(*job_owner),
        Token::Uint(sequence_number.into()),
        Token::Uint(job_start_time),
        Token::Uint(sign_timestamp.into()),
    ];

    let hash_struct = keccak256(encode(&token_list));

    let gateway_jobs_domain_separator = keccak256(encode(&[
        Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
        Token::FixedBytes(keccak256("marlin.oyster.GatewayJobs").to_vec()),
        Token::FixedBytes(keccak256("1").to_vec()),
    ]));

    let digest = encode_packed(&[
        Token::String("\x19\x01".to_string()),
        Token::FixedBytes(gateway_jobs_domain_separator.to_vec()),
        Token::FixedBytes(hash_struct.to_vec()),
    ]);

    let Ok(digest) = digest else {
        eprintln!("Failed to encode the digest: {:#?}", digest.err());
        return None;
    };
    let digest = keccak256(digest);

    // Sign the digest using enclave key
    let sig = signer_key.sign_prehash_recoverable(&digest);
    let Ok((rs, v)) = sig else {
        eprintln!("Failed to sign the digest: {:#?}", sig.err());
        return None;
    };

    Some((
        hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
        sign_timestamp,
    ))
}

pub async fn sign_job_response_request(
    signer_key: &SigningKey,
    job_id: U256,
    output: Bytes,
    total_time: U256,
    error_code: u8,
) -> Option<(String, u64)> {
    let sign_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let job_response_typehash = keccak256(
        "JobResponse(uint256 jobId,bytes output,uint256 totalTime,uint8 errorCode,uint256 signTimestamp)"
    );

    let output_hash = keccak256(output);

    let token_list = [
        Token::FixedBytes(job_response_typehash.to_vec()),
        Token::Uint(job_id),
        Token::FixedBytes(output_hash.to_vec()),
        Token::Uint(total_time),
        Token::Uint(error_code.into()),
        Token::Uint(sign_timestamp.into()),
    ];

    let hash_struct = keccak256(encode(&token_list));

    let gateway_jobs_domain_separator = keccak256(encode(&[
        Token::FixedBytes(keccak256("EIP712Domain(string name,string version)").to_vec()),
        Token::FixedBytes(keccak256("marlin.oyster.Relay").to_vec()),
        Token::FixedBytes(keccak256("1").to_vec()),
    ]));

    let digest = encode_packed(&[
        Token::String("\x19\x01".to_string()),
        Token::FixedBytes(gateway_jobs_domain_separator.to_vec()),
        Token::FixedBytes(hash_struct.to_vec()),
    ]);

    let Ok(digest) = digest else {
        eprintln!("Failed to encode the digest: {:#?}", digest.err());
        return None;
    };
    let digest = keccak256(digest);

    // Sign the digest using enclave key
    let sig = signer_key.sign_prehash_recoverable(&digest);
    let Ok((rs, v)) = sig else {
        eprintln!("Failed to sign the digest: {:#?}", sig.err());
        return None;
    };

    Some((
        hex::encode(rs.to_bytes().append(27 + v.to_byte()).to_vec()),
        sign_timestamp,
    ))
}
