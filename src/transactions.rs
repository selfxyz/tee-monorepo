use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::BlockTransactionsKind;
use alloy::transports::http::reqwest::Url;
use anyhow::{anyhow, Context, Result};

use crate::secret_manager::SecretManagerContract;
use crate::utils::{timestamp_to_instant, SecretCreatedMetadata, SecretMetadata};

pub async fn get_latest_block_number(http_rpc_url: &String) -> Result<u64> {
    let http_rpc_client = ProviderBuilder::new().on_http(Url::parse(http_rpc_url)?);

    http_rpc_client
        .get_block_number()
        .await
        .context("Failed to get a response from the rpc server")
}

pub async fn get_block_timestamp(http_rpc_url: &String, block_number: u64) -> Result<u64> {
    let http_rpc_client = ProviderBuilder::new().on_http(Url::parse(http_rpc_url)?);

    let Some(block_response) = http_rpc_client
        .get_block(block_number.into(), BlockTransactionsKind::Hashes)
        .await
        .context("Failed to get block response from rpc server")?
    else {
        return Err(anyhow!(
            "Timestamp not available for the block number: {}",
            block_number
        ));
    };

    Ok(block_response.header.timestamp)
}

pub async fn get_secret_metadata(
    http_rpc_url: &String,
    contract_addr: Address,
    secret_id: U256,
    acknowledgement_deadline: u64,
) -> Result<SecretCreatedMetadata> {
    let http_rpc_client = ProviderBuilder::new()
        .on_http(Url::parse(http_rpc_url).context("Failed to parse the RPC URL")?);
    let contract = SecretManagerContract::new(contract_addr, http_rpc_client);
    let user_storage = contract
        .userStorage(secret_id)
        .call()
        .await
        .context("Failed to get a response from the RPC server")?;

    let start_timestamp = timestamp_to_instant(user_storage.startTimestamp.to::<u64>()).unwrap();

    Ok(SecretCreatedMetadata {
        secret_metadata: SecretMetadata {
            owner: user_storage.owner,
            size_limit: user_storage.sizeLimit,
            end_timestamp: user_storage.endTimestamp,
        },
        acknowledgement_deadline: start_timestamp + Duration::from_secs(acknowledgement_deadline),
    })
}
