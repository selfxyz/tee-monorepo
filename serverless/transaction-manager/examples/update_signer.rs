use clap::Parser;
use multi_block_txns::TxnManager;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(long, value_parser)]
    private_key: String,
    #[clap(long, value_parser)]
    new_private_key: String,
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

    let private_signer = txn_manager.get_private_signer();
    println!("Private signer: {:?}", private_signer);

    let new_private_signer = Cli::parse().new_private_key;

    let _ = txn_manager.update_private_signer(new_private_signer.to_string());

    let private_signer = txn_manager.get_private_signer();
    println!("Private signer: {:?}", private_signer);
}
