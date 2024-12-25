use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    GatewaysContract,
    "./Gateways.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    GatewayJobsContract,
    "./GatewayJobs.json"
);
