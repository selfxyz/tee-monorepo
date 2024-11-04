use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::RwLock, time::sleep};

use alloy::primitives::{Address, Bytes};
use models::TxnManager;

mod constants;
mod errors;
mod models;
mod transaction;
mod utils;

#[tokio::main]
async fn main() {
    let gas_key_hex = "af6ecabcdbbfb2aefa8248b19d811234cd95caa51b8e59b6ffd3d4bbc2a6be4c";
    let chain_id = 31337;
    let rpc_url = "http://localhost:8545";
    let gas_key_hex = Arc::new(RwLock::new(gas_key_hex.to_string()));

    let txn_manager = TxnManager::new(rpc_url.to_string(), chain_id, gas_key_hex, None, None)
        .await
        .unwrap();

    let contract_address: Address = "0xD4A1E660C916855229e1712090CcfD8a424A2E33"
        .parse()
        .unwrap();

    let data = Bytes::from(vec![0]);

    let timeout = Instant::now() + Duration::from_secs(8);

    let txn_ids = Arc::new(RwLock::new(vec![]));

    // run test parallely 3 times
    let mut tasks = vec![];
    for _ in 0..3 {
        let txn_manager_clone = txn_manager.clone();
        let contract_address = contract_address.clone();
        let data = data.clone();
        let txn_ids_clone = txn_ids.clone();
        tasks.push(tokio::spawn(async move {
            let res = txn_manager_clone
                .call_contract_function(contract_address, data, timeout)
                .await;
            let txn_id = match res {
                Ok(txn_id) => txn_id,
                Err(e) => {
                    println!("Error: {:#?}", e);
                    return;
                }
            };

            println!("Txn ID: {:#?}", txn_id);

            txn_ids_clone.write().await.push(txn_id);
        }));
    }

    println!("Waiting for tasks to complete");

    for task in tasks {
        let _ = task.await;
    }

    let txn_ids_clone = txn_ids.read().await.clone();

    loop {
        sleep(Duration::from_secs(1)).await;

        for txn_id in txn_ids_clone.iter() {
            let status = txn_manager
                .clone()
                .get_transaction_status(txn_id.clone())
                .await;
            println!("Txn ID: {:#?}, Status: {:#?}", txn_id, status);
        }
    }
}
