use alloy::dyn_abi::DynSolValue;
use alloy::primitives::{keccak256, Address, Bytes, U256};
use clap::Parser;
use multi_block_txns::{TxnManager, TxnStatus};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(long, value_parser)]
    private_key: String,
}

#[tokio::main]
async fn main() {
    let rpc_url = "https://sepolia-rollup.arbitrum.io/rpc/";
    let chain_id = 421614;
    let private_signer = Cli::parse().private_key;

    let txn_manager = TxnManager::new(
        rpc_url.to_string(),
        chain_id,
        private_signer,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    txn_manager.run().await;

    let contract_address: Address = "0x186A361FF2361BAbEE9344A2FeC1941d80a7a49C"
        .parse()
        .unwrap();
    let timeout = Instant::now() + Duration::from_secs(8);

    let function_selector = &keccak256("approve(address,uint256)".as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&function_selector[..4]);

    let address = Address::from_str("0x56EC16763Ec62f4EAF9C7Cfa09E29DC557e97006").unwrap();
    let amount = U256::from(1_000_000_000);

    let token = DynSolValue::Tuple(vec![
        DynSolValue::Address(address),
        DynSolValue::Uint(amount, 256),
    ])
    .abi_encode();

    let mut cd = selector.to_vec();
    cd.extend(token.to_vec());

    let data = Bytes::from(cd);

    let res = txn_manager
        .call_contract_function(contract_address, data, timeout)
        .await;

    if let Err(e) = res {
        println!("Error: {:#?}", e);
        return;
    }

    let res = res.unwrap();

    loop {
        sleep(Duration::from_secs(1)).await;

        let status = txn_manager.clone().get_transaction_status(res.clone());
        println!("Status: {:#?}", status);

        if status.unwrap() == TxnStatus::Confirmed {
            break;
        }
    }
}
