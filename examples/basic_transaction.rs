use alloy::dyn_abi::DynSolValue;
use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, U256};
use alloy::signers::local::PrivateKeySigner;
use multi_block_txns::{TxnManager, TxnStatus};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    let rpc_url = "https://sepolia-rollup.arbitrum.io/rpc/";
    let chain_id = 421614;
    let private_signer = Arc::new(RwLock::new(
        "a8b743563462eb4b943e3de02ce7fcdfde6ca255b2f6850f34d47c1a9824b2f8"
            .parse::<PrivateKeySigner>()
            .unwrap(),
    ));

    let txn_manager = TxnManager::new(
        rpc_url.to_string(),
        chain_id,
        private_signer,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();

    txn_manager.run().await;

    let contract_address: Address = "0x53cb6487dd9766170824d4a66df5a0240b7f5f0b"
        .parse()
        .unwrap();
    let timeout = Instant::now() + Duration::from_secs(8);

    let function_selector = &keccak256(
        "relayJob(bytes,uint256,bytes32,bytes,uint256,uint256,uint8,address,uint8,uint256)"
            .as_bytes(),
    );
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&function_selector[..4]);

    let signature = Bytes::from_str(
        "a8e62e1471d896e95546ea39a0fe5b3b8cb4822c0e6474170ed02d9c65fcb75d5b47c846f85004421b4fa5dec8d79a81716179b27d503c6e2c42b842929596d51c"
    ).unwrap();
    let signature_timestamp = 1732651667;
    let job_id = U256::from(1);
    let code_hash: FixedBytes<32> =
        "0x6516be2032b475da2a96df1eefeb1679a8032faa434f8311a1441e92f2058fe5"
            .parse()
            .unwrap();
    let user_timeout: U256 = U256::from(2000);
    let start_timestamp = U256::from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 10,
    );
    let env = 1;
    let enclave_address = Address::from_str("0xF90e66D1452Be040Ca3A82387Bf6AD0c472f29Dd").unwrap();

    let token = DynSolValue::Tuple(vec![
        DynSolValue::Bytes(signature.to_vec()),
        DynSolValue::Uint(job_id, 256),
        DynSolValue::FixedBytes(code_hash, 32),
        DynSolValue::Bytes(vec![]),
        DynSolValue::Uint(user_timeout, 256),
        DynSolValue::Uint(start_timestamp, 256),
        DynSolValue::Uint(U256::from(1), 8),
        DynSolValue::Address(enclave_address),
        DynSolValue::Uint(U256::from(env), 8),
        DynSolValue::Uint(U256::from(signature_timestamp), 256),
    ])
    .abi_encode();

    // let mut cd = alloy::hex::decode(selector).unwrap();
    let mut cd = selector.to_vec();
    cd.extend(token[32..].to_vec());
    // let encoded_tokens = token.abi_encode();

    let data = Bytes::from(cd);

    let res = txn_manager
        .clone()
        .call_contract_function(contract_address, data, timeout)
        .await;

    if let Err(e) = res {
        println!("Error: {:#?}", e);
        return;
    }

    let res = res.unwrap();

    loop {
        sleep(Duration::from_secs(1)).await;

        let status = txn_manager
            .clone()
            .get_transaction_status(res.clone())
            .await;
        println!("Status: {:#?}", status);

        if status.unwrap() == TxnStatus::Confirmed {
            break;
        }
    }
}
