use ethers::contract::abigen;

abigen!(CommonChainGatewayContract, "./CommonChainGateway.json",);
abigen!(RequestChainContract, "./RequestChainContract.json",);
abigen!(CommonChainJobsContract, "./CommonChainJobs.json",);
