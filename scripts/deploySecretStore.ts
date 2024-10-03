import { getBytes, keccak256, Wallet } from "ethers";
import { ethers, upgrades } from "hardhat";

async function main() {
    //Create Enclave Image object
    const img = {
        PCR0: getBytes("0xcfa7554f87ba13620037695d62a381a2d876b74c2e1b435584fe5c02c53393ac1c5cd5a8b6f92e866f9a65af751e0462"),
        PCR1: getBytes("0xbcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f"),
        PCR2: getBytes("0x20caae8a6a69d9b1aecdf01a0b9c5f3eafd1f06cb51892bf47cef476935bfe77b5b75714b68a69146d650683a217c5b3"),
    };

    let wallet = walletForIndex(0);
    let enclavePubKey = normalize(wallet.signingKey.publicKey);

    // Admin address
    let signers = await ethers.getSigners();
    let adminAddress = await signers[0].getAddress();

    const Pond = await ethers.getContractFactory("Pond");
    let stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
        kind: "uups",
    });
    let stakingTokenAddr = stakingToken.target;
    console.log("Pond: ", stakingTokenAddr);

    const USDCoin = await ethers.getContractFactory("USDCoin");
    let usdcToken = await upgrades.deployProxy(USDCoin, [adminAddress], {
        kind: "uups",
    });
    let usdcTokenAddr = usdcToken.target;
    console.log("USDCoin: ", usdcTokenAddr);

    const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
    let attestationVerifier = await upgrades.deployProxy(
        AttestationVerifier,
        [
            [img],
            [enclavePubKey],
            adminAddress
        ],
        {
            kind: "uups"
        });
    let attestationVerifierAddr = attestationVerifier.target;
    console.log("AttestationVerifier: ", attestationVerifierAddr);

    let maxAge = 600,
        minStakeAmount = 10n ** 18n,
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
                attestationVerifierAddr,
                maxAge,
                stakingTokenAddr,
                minStakeAmount,
                slashPercentInBips,
                slashMaxBips,
                env
            ]
        }
    );
    console.log("SecretStore: ", secretStore.target);

    let noOfNodesToSelect = 3,
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
                usdcTokenAddr,
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

    await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("SECRET_MANAGER_ROLE")), secretManager.target);
    console.log("Role granted");
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
