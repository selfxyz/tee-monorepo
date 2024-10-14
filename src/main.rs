use alloy::dyn_abi::abi::encode;
use alloy::network::{EthereumWallet, NetworkWallet};
use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::{local::PrivateKeySigner, Signer};
use alloy::sol;
use anyhow::Context;
use reqwest::Url;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;

// use multi_block_txns::transaction::call_contract_function;

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

    let token_list = [
        relay_job_typehash.to_vec(),
        job_id.to_be_bytes_vec(),
        codehash.clone().to_vec(),
        code_inputs_hash.to_vec(),
        user_timeout.to_be_bytes_vec(),
        job_start_time.to_be_bytes_vec(),
        sequence_number.to_be_bytes().to_vec(),
        (*job_owner).to_vec(),
        env.to_be_bytes().to_vec(),
        sign_timestamp.to_be_bytes().to_vec(),
    ];

    let hash_struct = keccak256(&encode(&token_list));

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

#[tokio::main]
pub async fn main() {
    let gas_key_hex = "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
    let common_chain_id = 31337;
    let common_chain_http_url = "http://localhost:8545";
    let contract_address: Address = "0x322813Fd9A801c5507c9de605d63CEA4f2CE6c44"
        .parse()
        .unwrap();

    // Initialize the provider and wallet
    let signer: PrivateKeySigner = gas_key_hex.parse().unwrap();
    let signer = signer.with_chain_id(Some(common_chain_id));
    let signer_wallet = EthereumWallet::from(signer);
    // let gas_wallet = gas_wallet.with_chain_id(common_chain_id);

    // let signer_wallet = gas_wallet.clone().with_chain_id(common_chain_id);
    let signer_address = signer_wallet.default_signer_address();

    let common_chain_http_rpc_client = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(signer_wallet)
        .on_http(Url::parse(common_chain_http_url).unwrap());

    // let common_chain_http_rpc_client = Arc::new(
    //     common_chain_http_rpc_client
    //         .with_signer(signer_wallet.clone())
    //         .nonce_manager(signer_address),
    // );

    // Load the contract
    let gateway_jobs_contract =
        GatewayJobsContract::new(contract_address, common_chain_http_rpc_client);

    let job = Job {
        job_id: U256::from(1),
        request_chain_id: common_chain_id,
        tx_hash: FixedBytes::from(
            &hex::decode(
                "9468bb6a8e85ed11e292c8cac0c1539df691c8d8ec62e7dbfa9f1bd7f504e46e".to_owned(),
            )
            .unwrap(),
        ),
        code_input: serde_json::to_vec(&json!({
            "num": 10
        }))
        .unwrap()
        .into(),
        user_timeout: U256::from(2000),
        starttime: U256::from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ),
        job_owner: contract_address,
        job_type: GatewayJobType::JobRelay,
        sequence_number: 1 as u8,
        gateway_address: None,
        job_mode: JobMode::Once,
        env: 1u8,
    };

    // Define the function name and parameters
    let enclave_signer_key = SigningKey::from_slice(
        fs::read("./enclave_secret_key")
            .await
            .context("Failed to read the enclave signer key")
            .unwrap()
            .as_slice(),
    )
    .context("Invalid enclave signer key")
    .unwrap();
    let (signature, sign_timestamp) = sign_relay_job_request(
        &enclave_signer_key,
        job.job_id,
        &job.tx_hash,
        &job.code_input,
        job.user_timeout,
        job.starttime,
        job.sequence_number,
        &job.job_owner,
        job.env,
    )
    .await
    .unwrap();
    let Ok(signature) = Bytes::from_hex(signature) else {
        return;
    };
    let function_name = "relayJob";
    let params = vec![
        ("Bytes", &signature as &dyn std::any::Any),
        ("Uint", &job.job_id as &dyn std::any::Any),
        ("Bytes", &job.tx_hash.to_vec() as &dyn std::any::Any),
        ("Bytes", &job.code_input as &dyn std::any::Any),
        ("Uint", &job.user_timeout as &dyn std::any::Any),
        ("Uint", &job.starttime as &dyn std::any::Any),
        ("Uint", &job.sequence_number as &dyn std::any::Any),
        ("Address", &job.job_owner as &dyn std::any::Any),
        ("Uint", &job.env.into() as &dyn std::any::Any),
        ("Uint", &sign_timestamp.into() as &dyn std::any::Any),
    ];

    // Call the contract function
    // call_contract_function(gateway_jobs_contract, function_name, params)
    //     .await
    //     .unwrap();

    // Ok(())
}
