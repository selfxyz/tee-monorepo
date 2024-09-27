import { getBytes } from "ethers";
import { ethers, upgrades } from "hardhat";

async function main() {
    //Create Enclave Image object
    const img = {
        PCR0 : getBytes("0xcfa7554f87ba13620037695d62a381a2d876b74c2e1b435584fe5c02c53393ac1c5cd5a8b6f92e866f9a65af751e0462"),
        PCR1 : getBytes("0xbcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f"),
        PCR2 : getBytes("0x20caae8a6a69d9b1aecdf01a0b9c5f3eafd1f06cb51892bf47cef476935bfe77b5b75714b68a69146d650683a217c5b3"),
    };

    // Admin address
    let signers = await ethers.getSigners();
    let adminAddress = await signers[0].getAddress();
    let attestationVerifier = "0x73B7154EdBc562D4cCbdB43D515eB1C2dF46A718",
        maxAge = 600,
        stakingToken = "0x0DA917048bfF8fc8fe5647509FB8F8049E2E7B87",
        minStakeAmount = 10n**18n,
        slashPercentInBips = 100,
        slashMaxBips = 1000000,
        env = 1;

    const SecretStore = await ethers.getContractFactory("SecretStore");
    const secretStore = await upgrades.deployProxy(
        SecretStore,
        [
            adminAddress,
            [img]
        ],
        {
            kind: 'uups',
            constructorArgs: [
                attestationVerifier,
                maxAge,
                stakingToken,
                minStakeAmount,
                slashPercentInBips,
                slashMaxBips,
                env
            ]
        }
    );
    console.log("SecretStore: ", secretStore.target);
    
    let usdcToken = "0x186A361FF2361BAbEE9344A2FeC1941d80a7a49C",
        noOfNodesToSelect = 3,
        globalMaxStoreSize = 1e7,
        globalMinStoreDuration = 10,
        globalMaxStoreDuration = 10000,
        acknowledgementTimeout = 120,
        markAliveTimeout = 600,
        secretStoreFeeRate = 100,
        stakingPaymentPool = adminAddress,
        secretStoreAddress = secretStore.target;

    const SecretManager = await ethers.getContractFactory("SecretManager");
    const secretManager = await upgrades.deployProxy(
        SecretManager,
        [
            adminAddress
        ],
        {
            kind: 'uups',
            constructorArgs: [
                usdcToken,
                noOfNodesToSelect,
                globalMaxStoreSize,
                globalMinStoreDuration,
                globalMaxStoreDuration,
                acknowledgementTimeout,
                markAliveTimeout,
                secretStoreFeeRate,
                stakingPaymentPool,
                secretStoreAddress
            ]
        }
    );
    console.log("SecretManager: ", secretManager.target);
}

main();