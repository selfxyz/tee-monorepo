use ethers::contract::abigen;

abigen!(GatewaysContract, "./Gateways.json",);
abigen!(RelayContract, "./Relay.json",);
abigen!(GatewayJobsContract, "./GatewayJobs.json",);
abigen!(RelaySubscriptionsContract, "./RelaySubscriptions.json");
