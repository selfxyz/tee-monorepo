import { getBytes, Wallet } from "ethers";
import { ethers, upgrades } from "hardhat";

async function main() {
    //Create Enclave Image object
    const img = {
        PCR0 : getBytes("0xcfa7554f87ba13620037695d62a381a2d876b74c2e1b435584fe5c02c53393ac1c5cd5a8b6f92e866f9a65af751e0462"),
        PCR1 : getBytes("0xbcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f"),
        PCR2 : getBytes("0x20caae8a6a69d9b1aecdf01a0b9c5f3eafd1f06cb51892bf47cef476935bfe77b5b75714b68a69146d650683a217c5b3"),
    };

    let wallet = walletForIndex(0);
    console.log("Attestation Verifer Enclave Private Key: ", wallet.signingKey.privateKey);
    let enclavePubKey = normalize(wallet.signingKey.publicKey);

    // Admin address
    let signers = await ethers.getSigners();
    let admin_addr = await signers[0].getAddress();

    // Deploy POND Token Contract
    console.log("Deploying Pond");
    const Pond = await ethers.getContractFactory("Pond");
    let staking_token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
        kind: "uups",
    });
    let staking_token_addr = staking_token.target;
    console.log("Pond Deployed address: ", staking_token_addr);

    // Deploy USDC Token Contract
    console.log("Deploying USDCoin...");
    const USDCoin = await ethers.getContractFactory("USDCoin");
    let usdc_token = await upgrades.deployProxy(USDCoin, [admin_addr], {
        kind: "uups",
    });

    let usdc_token_addr = usdc_token.target;
    console.log("USDCoin Deployed address: ", usdc_token_addr);

    const executorFeePerMs = 1; // 0.001 usd per ms
    const stakingRewardPerMs = 1; // 0.001 usd per ms
    const executionFeePerMs = executorFeePerMs + stakingRewardPerMs;
    const gatewayFee = 100; // 0.1 usd
    const stakingPaymentPoolAddress = await signers[1].getAddress();
    const usdcPaymentPoolAddress = await signers[1].getAddress();
    const signMaxAge = 600;

    // Attestation Verifier
    const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
    console.log("Deploying AttestationVerifier")
    let attestationverifier = await upgrades.deployProxy(
        AttestationVerifier,
        [
            [img],
            [enclavePubKey],
            admin_addr
        ],
        {
            kind : "uups"
        });
    let av_addr = attestationverifier.target;
    console.log("AttestationVerifier Deployed address: ", av_addr);

    // Request Chain Relay Contract
    let overallTimeout = 120;
    let minUserDeadline = 1000;
    let maxUserDeadline = 50000;
    const Relay = await ethers.getContractFactory("Relay");
    console.log("Deploying Relay...")
    let relay = await upgrades.deployProxy(
        Relay,
        [
            admin_addr,
            [img]
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs : [
                av_addr,
                signMaxAge,
                usdc_token_addr,
                minUserDeadline,
                maxUserDeadline,
                overallTimeout,
                executionFeePerMs,
                gatewayFee
            ]
        });
    let relay_addr = relay.target;
    console.log("Relay Deployed address: ", relay_addr);

    // Common Chain Gateways Contract
    let epochInterval = 600;
    const Gateways = await ethers.getContractFactory("Gateways");
    console.log("Deploying Gateways...")
    let gatewaysContract = await upgrades.deployProxy(
        Gateways,
        [
            admin_addr,
            [img]
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs : [
                av_addr,
                signMaxAge,
                staking_token_addr,
                epochInterval + overallTimeout,
                100, // 0.01 %
                1000000
            ]
        });

    let gatewaysAddress = gatewaysContract.target;
    console.log("Gateways Deployed address: ", gatewaysAddress);

    // Common Chain Executors Contract
    let minStake = 10n**18n;
    const Executors = await ethers.getContractFactory("Executors");
    console.log("Deploying Executors...")
    let executorsContract = await upgrades.deployProxy(
        Executors,
        [
            admin_addr,
            [img]
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs : [
                av_addr,
                signMaxAge,
                staking_token_addr,
                minStake,
                100, // 0.01 %
                1000000
            ]
        });
    let executorsAddress = executorsContract.target;
    console.log("Executors Deployed address: ", executorsAddress);

    let executionBufferTime = 60,
        noOfNodesToSelect = 3;
    // Common Chain Jobs Contract
    const Jobs = await ethers.getContractFactory("Jobs");
    console.log("Deploying Jobs...")
    let jobsContract = await upgrades.deployProxy(
        Jobs,
        [
            admin_addr,
        ],
        {
            initializer : "initialize",
            kind : "uups",
            constructorArgs: [
                staking_token_addr,
                usdc_token_addr,
                signMaxAge,
                executionBufferTime,
                noOfNodesToSelect,
                1,
                1,
                stakingPaymentPoolAddress,
                usdcPaymentPoolAddress,
                executorsAddress
            ]
        });
    let jobsAddress = jobsContract.target;
    console.log("Jobs Deployed address: ", jobsAddress);
    await executorsContract.grantRole(await executorsContract.JOBS_ROLE(), jobsAddress);

     // Common Chain Gateway Jobs Contract
     let relayBufferTime = 120;
     const GatewayJobs = await ethers.getContractFactory("GatewayJobs");
     console.log("Deploying GatewayJobs...")
     let gatewayJobs = await upgrades.deployProxy(
         GatewayJobs,
         [
             admin_addr
         ],
         {
             initializer : "initialize",
             kind : "uups",
             constructorArgs : [
                 staking_token_addr,
                 usdc_token_addr,
                 signMaxAge,
                 relayBufferTime,
                 executionFeePerMs,
                 10n**16n, // 0.01 POND
                 10n**16n, // 0.01 POND
                 jobsAddress,
                 gatewaysAddress,
                 stakingPaymentPoolAddress
             ]
         });
    let gatewayJobsAddress = gatewayJobs.target;
    console.log("GatewayJobs Deployed address: ", gatewayJobsAddress);
    await gatewaysContract.grantRole(await gatewaysContract.GATEWAY_JOBS_ROLE(), gatewayJobsAddress);
}

function normalize(key: string): string {
	return '0x' + key.substring(4);
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
