pub async fn test() {
    let gas_key_hex = "af6ecabcdbbfb2aefa8248b19d811234cd95caa51b8e59b6ffd3d4bbc2a6be4c";
    let common_chain_id = 31337;
    let common_chain_http_url = "http://localhost:8545";
    let contract_address: Address = "0xD4A1E660C916855229e1712090CcfD8a424A2E33"
        .parse()
        .unwrap();

    // Initialize the provider and wallet
    let signer: PrivateKeySigner = gas_key_hex.parse().unwrap();
    let signer = signer.with_chain_id(Some(common_chain_id));
    let signer_wallet = EthereumWallet::from(signer.clone());

    let common_chain_http_rpc_client = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(signer_wallet)
        .on_http(Url::parse(common_chain_http_url).unwrap());

    let nonce = common_chain_http_rpc_client
        .get_transaction_count(signer.address())
        .await
        .unwrap();

    println!("Nonce: {:#?}", nonce);

    let tx = TransactionRequest::default()
        .with_to(signer.address())
        .with_input(Bytes::from(vec![rand::thread_rng().gen_range(1..=10)]));

    println!("Sending transaction");
    let builder = common_chain_http_rpc_client
        .send_transaction(tx)
        .await
        .unwrap();
    let txn_hash = *builder.tx_hash();
    println!("Transaction hash: {:#?}", txn_hash);

    // Instant + 1 second
    let timeout = Duration::from_secs(8);
    println!("Starting watch");
    let receipt = builder
        .with_required_confirmations(1)
        .with_timeout(Some(timeout))
        .watch()
        .await
        .unwrap();

    println!("Transaction receipt: {:#?}", receipt);
}
