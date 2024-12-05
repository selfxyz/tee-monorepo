use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SecretManagerContract,
    "./SecretManager.json"
);
