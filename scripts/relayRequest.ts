import { arrayify } from "@ethersproject/bytes";
import { ethers, upgrades } from "hardhat";

async function main() {
    //Create Enclave Image object
    const img = {
        PCR0 : arrayify("0xcfa7554f87ba13620037695d62a381a2d876b74c2e1b435584fe5c02c53393ac1c5cd5a8b6f92e866f9a65af751e0462"),
        PCR1 : arrayify("0xbcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f"),
        PCR2 : arrayify("0x20caae8a6a69d9b1aecdf01a0b9c5f3eafd1f06cb51892bf47cef476935bfe77b5b75714b68a69146d650683a217c5b3"),
    };
    let enclavePubKey = "0x8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed753547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5";
    // Admin address
    let admin_addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    // Deploy Token Contract
    let token_addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

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
    const ServerlessRelay = await ethers.getContractFactory("RequestChainContract");
    console.log("Deploying RequestChainContract...")
    let serverlessrelay = await upgrades.deployProxy(
        ServerlessRelay,
        [
            admin_addr,
            [img]
        ],
        {
            initializer : "__RequestChainContract_init",
            kind : "uups",
            constructorArgs : [
                av_addr,
                1000,
                token_addr,
                1000,
                10000,
                20000
            ]
        });
    let svls_addr = serverlessrelay.target;
    console.log("ServerlessRelay Deployed address: ", svls_addr);

    // Common Chain Gateways Contract
    const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
    console.log("Deploying CommonChainGateways...")
    let gatewaysContract = await upgrades.deployProxy(
        CommonChainGateways,
        [
            admin_addr,
            [img]
        ],
        {
            initializer : "__CommonChainGateways_init",
            kind : "uups",
            constructorArgs : [
                av_addr,
                1000,
                token_addr
            ]
        });
    let gatewaysAddress = gatewaysContract.target;
    console.log("CommonChainGateways Deployed address: ", gatewaysAddress);

    // Common Chain Executors Contract
    const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
    console.log("Deploying CommonChainExecutors...")
    let executorsContract = await upgrades.deployProxy(
        CommonChainExecutors,
        [
            admin_addr,
            [img]
        ],
        {
            initializer : "__CommonChainExecutors_init",
            kind : "uups",
            constructorArgs : [
                av_addr,
                1000,
                token_addr
            ]
        });
    let executorsAddress = executorsContract.target;
    console.log("CommonChainExecutors Deployed address: ", executorsAddress);

    let relayBufferTime = 100,
        executionBufferTime = 100,
        noOfNodesToSelect = 3;
    // Common Chain Jobs Contract
    const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
    console.log("Deploying CommonChainJobs...")
    let jobsContract = await upgrades.deployProxy(
        CommonChainJobs,
        [
            admin_addr,
            gatewaysAddress,
            executorsAddress,
        ],
        {
            initializer : "__CommonChainJobs_init",
            kind : "uups",
            constructorArgs: [
                token_addr,
                relayBufferTime,
                executionBufferTime,
                noOfNodesToSelect
            ]
        });
    let jobsAddress = jobsContract.target;
    console.log("CommonChainJobs Deployed address: ", jobsAddress);

    await executorsContract.setJobsContract(jobsAddress);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
