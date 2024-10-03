import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, ZeroHash, keccak256, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, Pond, SecretStore } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { testERC165 } from '../helpers/erc165';

const image1: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48))
};

const image2: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48))
};

const image3: AttestationAutherUpgradeable.EnclaveImageStruct = {
    PCR0: ethers.hexlify(ethers.randomBytes(48)),
    PCR1: ethers.hexlify(ethers.randomBytes(48)),
    PCR2: ethers.hexlify(ethers.randomBytes(48))
};

function getImageId(image: AttestationAutherUpgradeable.EnclaveImageStruct): string {
    return keccak256(solidityPacked(["bytes", "bytes", "bytes"], [image.PCR0, image.PCR1, image.PCR2]));
}

describe("SecretStore - Init", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let token: string;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[13]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        token = addrs[1];
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("deploys with initialization disabled", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        const secretStore = await SecretStore.deploy(
            attestationVerifier.target,
            600,
            token,
            10 ** 10,
            10 ** 2,
            10 ** 6,
            1
        );

        expect(await secretStore.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
        expect(await secretStore.ATTESTATION_MAX_AGE()).to.equal(600);
        expect(await secretStore.STAKING_TOKEN()).to.equal(token);
        expect(await secretStore.MIN_STAKE_AMOUNT()).to.equal(10 ** 10);
        expect(await secretStore.SLASH_PERCENT_IN_BIPS()).to.equal(10 ** 2);
        expect(await secretStore.SLASH_MAX_BIPS()).to.equal(10 ** 6);
        expect(await secretStore.ENV()).to.equal(1);

        await expect(
            secretStore.initialize(addrs[0], []),
        ).to.be.revertedWithCustomError(secretStore, "InvalidInitialization");

        await expect(
            secretStore.initialize(addrs[0], [image1, image2]),
        ).to.be.revertedWithCustomError(secretStore, "InvalidInitialization");
    });

    it("deploys as proxy and initializes", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        const secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0], [image1]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token,
                    10 ** 10,
                    10 ** 2,
                    10 ** 6,
                    1
                ]
            },
        );

        expect(await secretStore.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
        expect(await secretStore.ATTESTATION_MAX_AGE()).to.equal(600);
        expect(await secretStore.STAKING_TOKEN()).to.equal(token);
        expect(await secretStore.MIN_STAKE_AMOUNT()).to.equal(10 ** 10);
        expect(await secretStore.SLASH_PERCENT_IN_BIPS()).to.equal(10 ** 2);
        expect(await secretStore.SLASH_MAX_BIPS()).to.equal(10 ** 6);
        expect(await secretStore.ENV()).to.equal(1);

        expect(await secretStore.hasRole(await secretStore.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        {
            const { PCR0, PCR1, PCR2 } = await secretStore.getWhitelistedImage(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }
    });

    it("cannot initialize with zero address as admin", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        await expect(
            upgrades.deployProxy(
                SecretStore,
                [ZeroAddress, [image1, image2, image3]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        attestationVerifier.target,
                        600,
                        token,
                        10 ** 10,
                        10 ** 2,
                        10 ** 6,
                        1
                    ]
                },
            )
        ).to.be.revertedWithCustomError(SecretStore, "SecretStoreZeroAddressAdmin");
    });

    it("cannot initialize with zero address as staking token", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        await expect(
            upgrades.deployProxy(
                SecretStore,
                [addrs[0], [image1, image2, image3]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        attestationVerifier.target,
                        600,
                        ZeroAddress,
                        10 ** 10,
                        10 ** 2,
                        10 ** 6,
                        1
                    ]
                },
            )
        ).to.be.revertedWithCustomError(SecretStore, "SecretStoreZeroAddressStakingToken");
    });

    it("cannot initialize with zero minimum stakes", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        await expect(
            upgrades.deployProxy(
                SecretStore,
                [addrs[0], [image1, image2, image3]],
                {
                    kind: "uups",
                    initializer: "initialize",
                    constructorArgs: [
                        attestationVerifier.target,
                        600,
                        token,
                        0,
                        10 ** 2,
                        10 ** 6,
                        1
                    ]
                },
            )
        ).to.be.revertedWithCustomError(SecretStore, "SecretStoreZeroMinStakeAmount");
    });

    it("upgrades", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        const secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0], [image1, image2, image3]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token,
                    10 ** 10,
                    10 ** 2,
                    10 ** 6,
                    1
                ]
            },
        );
        // Deploy new attestation verifier
        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        const attestationVerifier2 = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        const token2 = addrs[2];

        await upgrades.upgradeProxy(
            secretStore.target,
            SecretStore,
            {
                kind: "uups",
                constructorArgs: [
                    attestationVerifier2.target,
                    100,
                    token2,
                    10,
                    10,
                    1000,
                    2
                ]
            }
        );

        expect(await secretStore.ATTESTATION_VERIFIER()).to.equal(attestationVerifier2.target);
        expect(await secretStore.ATTESTATION_MAX_AGE()).to.equal(100);
        expect(await secretStore.STAKING_TOKEN()).to.equal(token2);
        expect(await secretStore.MIN_STAKE_AMOUNT()).to.equal(10);
        expect(await secretStore.SLASH_PERCENT_IN_BIPS()).to.equal(10);
        expect(await secretStore.SLASH_MAX_BIPS()).to.equal(1000);
        expect(await secretStore.ENV()).to.equal(2);

        expect(await secretStore.hasRole(await secretStore.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
        {
            const { PCR0, PCR1, PCR2 } = await secretStore.getWhitelistedImage(getImageId(image1));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
        }
        {
            const { PCR0, PCR1, PCR2 } = await secretStore.getWhitelistedImage(getImageId(image2));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
        }
        {
            const { PCR0, PCR1, PCR2 } = await secretStore.getWhitelistedImage(getImageId(image3));
            expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
        }
    });

    it("does not upgrade without admin", async function () {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        const secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0], [image1, image2, image3]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token,
                    10 ** 10,
                    10 ** 2,
                    10 ** 6,
                    1
                ]
            },
        );

        await expect(
            upgrades.upgradeProxy(secretStore.target, SecretStore.connect(signers[1]), {
                kind: "uups",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token,
                    10 ** 10,
                    10 ** 2,
                    10 ** 6,
                    1
                ],
            }),
        ).to.be.revertedWithCustomError(secretStore, "AccessControlUnauthorizedAccount");
    });
});

testERC165(
    "SecretStore - ERC165",
    async function (_signers: Signer[], addrs: string[]) {
        const SecretStore = await ethers.getContractFactory("SecretStore");
        const secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0], [image1]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    addrs[1],
                    600,
                    addrs[2],
                    10 ** 10,
                    10 ** 2,
                    10 ** 6,
                    1
                ]
            },
        );
        return secretStore;
    },
    {
        IAccessControl: [
            "hasRole(bytes32,address)",
            "getRoleAdmin(bytes32)",
            "grantRole(bytes32,address)",
            "revokeRole(bytes32,address)",
            "renounceRole(bytes32,address)",
        ],
    },
);

describe("SecretStore - Whitelist/Revoke enclave images", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let attestationVerifier: AttestationVerifier;
    let token: string;
    let secretStore: SecretStore;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        token = addrs[1];

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0], [image2, image3]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token,
                    10 ** 10,
                    10 ** 2,
                    10 ** 6,
                    1
                ]
            },
        ) as unknown as SecretStore;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can whitelist enclave image with admin account", async function () {
        await expect(secretStore.connect(signers[0]).whitelistEnclaveImage(image1.PCR0, image1.PCR1, image1.PCR2))
            .to.emit(secretStore, "EnclaveImageWhitelisted").withArgs(getImageId(image1), image1.PCR0, image1.PCR1, image1.PCR2);

        const { PCR0, PCR1, PCR2 } = await secretStore.getWhitelistedImage(getImageId(image1));
        expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
    });

    it("cannot whitelist enclave image without admin account", async function () {
        await expect(secretStore.connect(signers[1]).whitelistEnclaveImage(image1.PCR0, image1.PCR1, image1.PCR2))
            .to.be.revertedWithCustomError(secretStore, "AccessControlUnauthorizedAccount");
    });

    it("can revoke enclave image with admin account", async function () {
        await expect(secretStore.connect(signers[0]).revokeEnclaveImage(getImageId(image2)))
            .to.emit(secretStore, "EnclaveImageRevoked").withArgs(getImageId(image2));

        const { PCR0 } = await secretStore.getWhitelistedImage(getImageId(image2));
        expect(PCR0).to.equal("0x");
    });

    it("cannot revoke enclave image without admin account", async function () {
        await expect(secretStore.connect(signers[1]).revokeEnclaveImage(getImageId(image2)))
            .to.be.revertedWithCustomError(secretStore, "AccessControlUnauthorizedAccount");
    });
});

describe("SecretStore - Register/Deregister secret store", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let secretStore: SecretStore;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        const Pond = await ethers.getContractFactory("Pond");
        token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0], [image2, image3]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token.target,
                    10,
                    10 ** 2,
                    10 ** 6,
                    1
                ]
            },
        ) as unknown as SecretStore;
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can register secret store", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let storageCapacity = 1e9;
        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[15]);

        await expect(secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            0
        )).to.emit(secretStore, "EnclaveKeyVerified").withArgs(addrs[15], getImageId(image2), pubkeys[15]);
        expect(await secretStore.getVerifiedKey(addrs[15])).to.equal(getImageId(image2));
        expect(await secretStore.getSecretStoreOwner(addrs[15])).to.eq(addrs[1]);
        expect(await secretStore.allowOnlyVerified(addrs[15])).to.be.not.reverted;
        await expect(secretStore.allowOnlyVerified(addrs[16]))
            .to.be.revertedWithCustomError(secretStore, "AttestationAutherKeyNotVerified");
    });

    it("cannot register secret store with old signature timestamp", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 700;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let storageCapacity = 1e9;
        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[15]);

        await expect(secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            0
        )).to.revertedWithCustomError(secretStore, "SecretStoreSignatureTooOld");
    });

    it("cannot register secret store with different attestation pubkey and digest signing key", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let storageCapacity = 1e9;
        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[16]);

        await expect(secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            0
        )).to.revertedWithCustomError(secretStore, "SecretStoreInvalidSigner");
    });

    it("cannot register secret store with same enclave key twice", async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let storageCapacity = 1e9;
        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[15]);
        await secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            0
        )
        await expect(secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            0
        )).to.revertedWithCustomError(secretStore, "SecretStoreEnclaveAlreadyExists");
    });

    // drain then deregister with no occupied storage
    it('can deregister secret store without occupied storage', async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let storageCapacity = 1e9;
        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[15]);

        await secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            0
        );

        await secretStore.connect(signers[1]).drainSecretStore(addrs[15]);
        await expect(secretStore.connect(signers[1]).deregisterSecretStore(addrs[15]))
            .to.emit(secretStore, "SecretStoreDeregistered").withArgs(addrs[15]);
        expect(await secretStore.getVerifiedKey(addrs[15])).to.equal(ZeroHash);
        expect((await secretStore.secretStorage(addrs[15])).owner).to.be.eq(ZeroAddress);
    });

    // fail to deregister if no draining
    it('Failed deregistration without draining', async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let storageCapacity = 1e9;
        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[15]);


        await secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            0
        );

        await expect(secretStore.connect(signers[1]).deregisterSecretStore(addrs[15]))
            .to.revertedWithCustomError(secretStore, "SecretStoreEnclaveNotDraining");
    });

    // drain then deregister failed with active jobs != 0
    it('cannot deregister secret store with occupied storage', async function () {
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("SECRET_MANAGER_ROLE")), addrs[0]);

        await token.transfer(addrs[1], 10n ** 19n);
        await token.connect(signers[1]).approve(secretStore.target, 10n ** 19n);

        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let storageCapacity = 1e9;
        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[15]);

        // register a enclave
        await secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            10n ** 19n
        )

        // select nodes
        await secretStore.connect(signers[0]).selectEnclaves(1, 100);
        // drain
        await secretStore.connect(signers[1]).drainSecretStore(addrs[15]);
        // deregister
        await expect(secretStore.connect(signers[1]).deregisterSecretStore(addrs[15]))
            .to.revertedWithCustomError(secretStore, "SecretStoreEnclaveNotEmpty");
    });

    it('cannot deregister secret store without the owner account', async function () {
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let storageCapacity = 20;
        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[15]);

        // register a enclave
        await secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            0
        );
        // deregister with signer 0
        await expect(secretStore.deregisterSecretStore(addrs[15]))
            .to.revertedWithCustomError(secretStore, "SecretStoreInvalidEnclaveOwner");
    });

});

describe("SecretStore - Staking/Unstaking", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let secretStore: SecretStore;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        const Pond = await ethers.getContractFactory("Pond");
        token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0], [image2, image3]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token.target,
                    10,
                    10 ** 2,
                    10 ** 6,
                    1
                ]
            },
        ) as unknown as SecretStore;

        await token.transfer(addrs[1], 100000);
        await token.connect(signers[1]).approve(secretStore.target, 10000);
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );

        let storageCapacity = 1e9,
            stakeAmount = 10;
        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[15]);

        await secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            stakeAmount
        );
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("can stake", async function () {
        let amount = 20;
        await expect(secretStore.connect(signers[1]).addSecretStoreStake(addrs[15], amount))
            .to.emit(secretStore, "SecretStoreStakeAdded");

        let secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.stakeAmount).to.be.eq(30);
        expect(await token.balanceOf(secretStore.target)).to.be.eq(30);
        expect(await token.balanceOf(addrs[1])).to.be.eq(99970);
    });

    it("can stake if draining", async function () {
        await secretStore.connect(signers[1]).drainSecretStore(addrs[15]);

        let amount = 20;
        await expect(secretStore.connect(signers[1]).addSecretStoreStake(addrs[15], amount))
            .to.emit(secretStore, "SecretStoreStakeAdded");

        let secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.stakeAmount).to.be.eq(30);
        expect(await token.balanceOf(secretStore.target)).to.be.eq(30);
        expect(await token.balanceOf(addrs[1])).to.be.eq(99970);
    });

    it("cannot stake without secret store owner", async function () {
        let amount = 20;
        await expect(secretStore.addSecretStoreStake(addrs[15], amount))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreInvalidEnclaveOwner");
    });

    it("can unstake with draining if no occupied storage", async function () {
        let amount = 10;
        await secretStore.connect(signers[1]).drainSecretStore(addrs[15]);
        await expect(secretStore.connect(signers[1]).removeSecretStoreStake(addrs[15], amount))
            .to.emit(secretStore, "SecretStoreStakeRemoved");

        let secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.stakeAmount).to.be.eq(0);
        expect(await token.balanceOf(secretStore.target)).to.be.eq(0);
        expect(await token.balanceOf(addrs[1])).to.be.eq(100000);
    });

    it("Failed to unstake without draining", async function () {
        let amount = 0;
        await expect(secretStore.connect(signers[1]).removeSecretStoreStake(addrs[15], amount))
            .to.revertedWithCustomError(secretStore, "SecretStoreEnclaveNotDraining");
    });

    it("cannot unstake without secret store operator", async function () {
        let amount = 10;
        await expect(secretStore.removeSecretStoreStake(addrs[15], amount))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreInvalidEnclaveOwner");
    });

    it('cannot unstake with occupied storage after draining started', async function () {
        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("SECRET_MANAGER_ROLE")), addrs[0]);

        await token.transfer(addrs[1], 10n ** 19n);
        await token.connect(signers[1]).approve(secretStore.target, 10n ** 19n);

        // add stake to get node added to tree
        await secretStore.connect(signers[1]).addSecretStoreStake(addrs[15], 10n ** 19n);
        // select nodes
        await secretStore.connect(signers[0]).selectEnclaves(1, 100);
        // drain
        await secretStore.connect(signers[1]).drainSecretStore(addrs[15]);

        let amount = 5;
        await expect(secretStore.connect(signers[1]).removeSecretStoreStake(addrs[15], amount))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreEnclaveNotEmpty");

    });
});

describe("SecretStore - Drain/Revive secret store", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let secretStore: SecretStore;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        const Pond = await ethers.getContractFactory("Pond");
        token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0], [image2, image3]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token.target,
                    10,
                    10 ** 2,
                    10 ** 6,
                    1
                ]
            },
        ) as unknown as SecretStore;

        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("SECRET_MANAGER_ROLE")), addrs[0]);

        await token.transfer(addrs[1], 10n ** 19n);
        await token.connect(signers[1]).approve(secretStore.target, 10n ** 19n);
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        let storageCapacity = 100,
            stakeAmount = 10n ** 19n;
        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[15]);
        await secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            stakeAmount
        );
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it('can drain secret store', async function () {
        await expect(secretStore.connect(signers[1]).drainSecretStore(addrs[15]))
            .to.emit(secretStore, "SecretStoreDrained").withArgs(addrs[15]);

        expect((await secretStore.secretStorage(addrs[15])).draining).to.be.eq(true);
    });

    it("cannot drain without secret store owner", async function () {
        await expect(secretStore.drainSecretStore(addrs[15]))
            .to.be.revertedWithCustomError(secretStore, "SecretStoreInvalidEnclaveOwner");
    });

    it('cannot drain secret store twice consecutively', async function () {
        await secretStore.connect(signers[1]).drainSecretStore(addrs[15]);
        await expect(secretStore.connect(signers[1]).drainSecretStore(addrs[15]))
            .to.revertedWithCustomError(secretStore, "SecretStoreEnclaveAlreadyDraining");
    });

    it("can revive secret store after draining", async function () {
        // Drain secret store
        await secretStore.connect(signers[1]).drainSecretStore(addrs[15]);

        // Try to select one enclave
        await secretStore.selectEnclaves(1, 100);

        // No enclave should be selected
        let secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(0);
        expect(secretStorage.draining).to.be.true;

        // Case 1: Enclave should get selected for job after revival because it has capacity available and
        // minimum stake
        await expect(secretStore.connect(signers[1]).reviveSecretStore(addrs[15]))
            .to.emit(secretStore, "SecretStoreRevived").withArgs(addrs[15]);

        // check enclave can be selected again
        await secretStore.selectEnclaves(1, 100);
        secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.draining).to.be.false;
        expect(secretStorage.storageOccupied).to.be.eq(100);

        // drain enclave again
        await secretStore.connect(signers[1]).drainSecretStore(addrs[15]);

        // Case 2: Enclave should not get selected for job after revival because it has no capacity available
        // Revive enclave
        await secretStore.connect(signers[1]).reviveSecretStore(addrs[15]);

        // select one enclave
        await secretStore.selectEnclaves(1, 100);

        // No enclave should be selected
        secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(100);

        // release enclave
        await secretStore.releaseEnclave(addrs[15], 100);

        // check occupied storage to be 0
        secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(0);

        // Drain enclave
        await secretStore.connect(signers[1]).drainSecretStore(addrs[15]);

        // Remove stake
        await secretStore.connect(signers[1]).removeSecretStoreStake(addrs[15], 10n ** 19n);

        // Case 3: Enclave should not get selected for job after revival because it has no minimum stake
        // Revive enclave
        await secretStore.connect(signers[1]).reviveSecretStore(addrs[15]);

        // enclave should not be added to the tree because it dosent have minimum stake
        // select one enclave
        await secretStore.selectEnclaves(1, 100);

        // No enclave should be selected
        secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(0);
    });

    it("cannot revive secret store without draining", async function () {
        await expect(secretStore.connect(signers[1]).reviveSecretStore(addrs[15]))
            .to.revertedWithCustomError(secretStore, "SecretStoreEnclaveAlreadyRevived");
    });

    it("cannot revive secret store without secret store owner", async function () {
        await expect(secretStore.reviveSecretStore(addrs[15]))
            .to.revertedWithCustomError(secretStore, "SecretStoreInvalidEnclaveOwner");
    });
});

describe("SecretStore - Select/Release/Slash", function () {
    let signers: Signer[];
    let addrs: string[];
    let wallets: Wallet[];
    let pubkeys: string[];
    let token: Pond;
    let attestationVerifier: AttestationVerifier;
    let secretStore: SecretStore;

    before(async function () {
        signers = await ethers.getSigners();
        addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
        pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

        const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
        attestationVerifier = await upgrades.deployProxy(
            AttestationVerifier,
            [[image1], [pubkeys[14]], addrs[0]],
            { kind: "uups" },
        ) as unknown as AttestationVerifier;

        const Pond = await ethers.getContractFactory("Pond");
        token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

        const SecretStore = await ethers.getContractFactory("SecretStore");
        secretStore = await upgrades.deployProxy(
            SecretStore,
            [addrs[0], [image2, image3]],
            {
                kind: "uups",
                initializer: "initialize",
                constructorArgs: [
                    attestationVerifier.target,
                    600,
                    token.target,
                    10,
                    10 ** 6,
                    10 ** 6,
                    1
                ]
            },
        ) as unknown as SecretStore;

        await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("SECRET_MANAGER_ROLE")), addrs[0]);

        await token.transfer(addrs[1], 10n ** 19n);
        await token.connect(signers[1]).approve(secretStore.target, 10n ** 19n);
        const timestamp = await time.latest() * 1000;
        let signTimestamp = await time.latest() - 540;
        let [attestationSign, attestation] = await createAttestation(
            pubkeys[15],
            image2,
            wallets[14],
            timestamp - 540000
        );
        let storageCapacity = 100,
            stakeAmount = 10n ** 19n;
        let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
            wallets[15]);
        await secretStore.connect(signers[1]).registerSecretStore(
            attestationSign,
            attestation,
            storageCapacity,
            signTimestamp,
            signedDigest,
            stakeAmount
        );
    });

    takeSnapshotBeforeAndAfterEveryTest(async () => { });

    it("select secret store after releasing", async function () {
        // Select one enclave
        await secretStore.selectEnclaves(1, 100);

        // Check occupied storage to be max(=100)
        let secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(100);

        // Release enclave
        await secretStore.releaseEnclave(addrs[15], 100);

        // Check occupied storage to be 0
        secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(0);

        // Select one enclave
        await secretStore.selectEnclaves(1, 100);

        // Check occupied storage to be max(=100)
        secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(100);
    });

    it("releasing while draining secret store", async function () {
        // Select one enclave
        await secretStore.selectEnclaves(1, 100);

        // Check storage occupied to be max(=100)
        let secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(100);

        // Drain enclave
        await secretStore.connect(signers[1]).drainSecretStore(addrs[15]);

        // Release enclave
        await secretStore.releaseEnclave(addrs[15], 100);

        // Check occupied storage to be 0
        secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(0);

        // Select one enclave
        await secretStore.selectEnclaves(1, 100);

        // Check storage occupied to be 0
        secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(0);
    });

    it("low stakes while releasing secret store", async function () {
        // Select one enclave
        await secretStore.selectEnclaves(1, 100);

        // Check storage occpied to be max(=100)
        let secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(100);

        // Slash Enclave (enclave will be released within slashEnclave)
        await secretStore.connect(signers[0]).slashEnclave(addrs[15], 100, addrs[2]);

        // Check storage occupied to be 0
        secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(0);

        // Select one enclave
        await secretStore.selectEnclaves(1, 100);

        // Check storage occupied to be 0
        secretStorage = await secretStore.secretStorage(addrs[15]);
        expect(secretStorage.storageOccupied).to.be.eq(0);
    });

    it("cannot release secret store without SECRET_MANAGER_ROLE", async function () {
        await expect(secretStore.connect(signers[1]).releaseEnclave(addrs[15], 100))
            .to.revertedWithCustomError(secretStore, "AccessControlUnauthorizedAccount");
    });

    it("cannot select secret store without SECRET_MANAGER_ROLE", async function () {
        await expect(secretStore.connect(signers[1]).selectEnclaves(1, 100))
            .to.revertedWithCustomError(secretStore, "AccessControlUnauthorizedAccount");
    });

    it("cannot slash secret store without SECRET_MANAGER_ROLE", async function () {
        await expect(secretStore.connect(signers[1]).slashEnclave(addrs[15], 100, addrs[2]))
            .to.revertedWithCustomError(secretStore, "AccessControlUnauthorizedAccount");
    });
});

function normalize(key: string): string {
    return '0x' + key.substring(4);
}

type Attestation = {
    enclavePubKey: string,
    PCR0: BytesLike,
    PCR1: BytesLike,
    PCR2: BytesLike,
    timestampInMilliseconds: number,
}

async function createAttestation(
    enclaveKey: string,
    image: AttestationVerifier.EnclaveImageStruct,
    sourceEnclaveKey: Wallet,
    timestamp: number,
): Promise<[string, Attestation]> {
    const domain = {
        name: 'marlin.oyster.AttestationVerifier',
        version: '1',
    };

    const types = {
        Attestation: [
            { name: 'enclavePubKey', type: 'bytes' },
            { name: 'PCR0', type: 'bytes' },
            { name: 'PCR1', type: 'bytes' },
            { name: 'PCR2', type: 'bytes' },
            { name: 'timestampInMilliseconds', type: 'uint256' },
        ]
    }

    const sign = await sourceEnclaveKey.signTypedData(domain, types, {
        enclavePubKey: enclaveKey,
        PCR0: image.PCR0,
        PCR1: image.PCR1,
        PCR2: image.PCR2,
        timestampInMilliseconds: timestamp,
    });
    return [ethers.Signature.from(sign).serialized, {
        enclavePubKey: enclaveKey,
        PCR0: image.PCR0,
        PCR1: image.PCR1,
        PCR2: image.PCR2,
        timestampInMilliseconds: timestamp,
    }];
}

async function createSecretStoreSignature(
    owner: string,
    storageCapacity: number,
    signTimestamp: number,
    sourceEnclaveWallet: Wallet
): Promise<string> {
    const domain = {
        name: 'marlin.oyster.SecretStore',
        version: '1',
    };

    const types = {
        Register: [
            { name: 'owner', type: 'address' },
            { name: 'storageCapacity', type: 'uint256' },
            { name: 'signTimestamp', type: 'uint256' }
        ]
    };

    const value = {
        owner,
        storageCapacity,
        signTimestamp
    };

    const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
    return ethers.Signature.from(sign).serialized;
}

function walletForIndex(idx: number): Wallet {
    let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

    return new Wallet(wallet.privateKey);
}