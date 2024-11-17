use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    RelayContract,
    "./Relay.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    RelaySubscriptionsContract,
    "./RelaySubscriptions.json"
);
