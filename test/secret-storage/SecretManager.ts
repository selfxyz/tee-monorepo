import { BytesLike, keccak256, parseUnits, Signer, solidityPacked, Wallet, ZeroAddress } from "ethers";
import { AttestationAutherUpgradeable, AttestationVerifier, Pond, SecretManager, SecretStore, USDCoin } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { ethers, upgrades } from "hardhat";
import { expect } from "chai";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { testERC165 } from "../helpers/erc165";

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

describe("SecretManager - Init", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let token: string;
	let noOfNodesToSelect: number;
	let globalMaxStoreSize: number;
	let globalMinStoreDuration: number;
	let globalMaxStoreDuration: number;
	let acknowledgementTimeout: number;
	let markAliveTimeout: number;
	let secretStoreFeeRate: number;
	let stakingPaymentPool: string;
	let secretStoreAddress: string;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));

		token = addrs[1],
		noOfNodesToSelect = 3,
		globalMaxStoreSize = 1e6,
		globalMinStoreDuration = 10,
		globalMaxStoreDuration = 1e6,
		acknowledgementTimeout = 120,
		markAliveTimeout = 900,
		secretStoreFeeRate = 10,
		stakingPaymentPool = addrs[2],
		secretStoreAddress = addrs[3];
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("deploys with initialization disabled", async function () {
		const SecretManager = await ethers.getContractFactory("SecretManager");
		const secretManager = await SecretManager.deploy(
			token,
			noOfNodesToSelect,
			globalMaxStoreSize,
			globalMinStoreDuration,
			globalMaxStoreDuration,
			acknowledgementTimeout,
			markAliveTimeout,
			secretStoreFeeRate,
			stakingPaymentPool,
			secretStoreAddress
		) as unknown as SecretManager;

		expect(await secretManager.USDC_TOKEN()).to.equal(token);
		expect(await secretManager.NO_OF_NODES_TO_SELECT()).to.equal(noOfNodesToSelect);
		expect(await secretManager.GLOBAL_MAX_STORE_SIZE()).to.equal(globalMaxStoreSize);
		expect(await secretManager.GLOBAL_MIN_STORE_DURATION()).to.equal(globalMinStoreDuration);
		expect(await secretManager.GLOBAL_MAX_STORE_DURATION()).to.equal(globalMaxStoreDuration);
        expect(await secretManager.ACKNOWLEDGEMENT_TIMEOUT()).to.equal(acknowledgementTimeout);
		expect(await secretManager.MARK_ALIVE_TIMEOUT()).to.equal(markAliveTimeout);
		expect(await secretManager.SECRET_STORE_FEE_RATE()).to.equal(secretStoreFeeRate);
        expect(await secretManager.STAKING_PAYMENT_POOL()).to.equal(stakingPaymentPool);
        expect(await secretManager.SECRET_STORE()).to.equal(secretStoreAddress);

		await expect(
			secretManager.initialize(addrs[0]),
		).to.be.revertedWithCustomError(secretManager, "InvalidInitialization");

		await expect(
			secretManager.initialize(addrs[0]),
		).to.be.revertedWithCustomError(secretManager, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function () {
		const SecretManager = await ethers.getContractFactory("SecretManager");
		const secretManager = await upgrades.deployProxy(
			SecretManager,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					token,
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
			},
		);

		expect(await secretManager.USDC_TOKEN()).to.equal(token);
		expect(await secretManager.NO_OF_NODES_TO_SELECT()).to.equal(noOfNodesToSelect);
		expect(await secretManager.GLOBAL_MAX_STORE_SIZE()).to.equal(globalMaxStoreSize);
		expect(await secretManager.GLOBAL_MIN_STORE_DURATION()).to.equal(globalMinStoreDuration);
		expect(await secretManager.GLOBAL_MAX_STORE_DURATION()).to.equal(globalMaxStoreDuration);
        expect(await secretManager.ACKNOWLEDGEMENT_TIMEOUT()).to.equal(acknowledgementTimeout);
		expect(await secretManager.MARK_ALIVE_TIMEOUT()).to.equal(markAliveTimeout);
		expect(await secretManager.SECRET_STORE_FEE_RATE()).to.equal(secretStoreFeeRate);
        expect(await secretManager.STAKING_PAYMENT_POOL()).to.equal(stakingPaymentPool);
        expect(await secretManager.SECRET_STORE()).to.equal(secretStoreAddress);

		expect(await secretManager.hasRole(await secretManager.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
	});

	it("cannot initialize with zero address as admin", async function () {
		const SecretManager = await ethers.getContractFactory("SecretManager");
		await expect(
			upgrades.deployProxy(
				SecretManager,
				[ZeroAddress],
				{
					kind: "uups",
					initializer: "initialize",
					constructorArgs: [
						token,
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
				},
			)
		).to.be.revertedWithCustomError(SecretManager, "SecretManagerZeroAddressAdmin");
	});

	it("cannot initialize with zero address as usdc token", async function () {
		const SecretManager = await ethers.getContractFactory("SecretManager");
		await expect(
			upgrades.deployProxy(
				SecretManager,
				[addrs[0]],
				{
					kind: "uups",
					initializer: "initialize",
					constructorArgs: [
						ZeroAddress,
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
				},
			)
		).to.be.revertedWithCustomError(SecretManager, "SecretManagerZeroAddressUsdcToken");
	});

	it("upgrades", async function () {
		const SecretManager = await ethers.getContractFactory("SecretManager");
		const secretManager = await upgrades.deployProxy(
			SecretManager,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					token,
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
			},
		);

		const token2 = addrs[2],
			noOfNodesToSelect2 = 4,
			globalMaxStoreSize2 = 100,
			globalMinStoreDuration2 = 1,
			globalMaxStoreDuration2 = 10,
			acknowledgementTimeout2 = 10,
			markAliveTimeout2 = 10,
			secretStoreFeeRate2 = 20,
			stakingPaymentPool2 = addrs[3],
			secretStoreAddress2 = addrs[4];

		await upgrades.upgradeProxy(
			secretManager.target,
			SecretManager,
			{
				kind: "uups",
				constructorArgs: [
					token2,
					noOfNodesToSelect2,
					globalMaxStoreSize2,
					globalMinStoreDuration2,
					globalMaxStoreDuration2,
					acknowledgementTimeout2,
					markAliveTimeout2,
					secretStoreFeeRate2,
					stakingPaymentPool2,
					secretStoreAddress2
				]
			}
		);

		expect(await secretManager.USDC_TOKEN()).to.equal(token2);
		expect(await secretManager.NO_OF_NODES_TO_SELECT()).to.equal(noOfNodesToSelect2);
		expect(await secretManager.GLOBAL_MAX_STORE_SIZE()).to.equal(globalMaxStoreSize2);
		expect(await secretManager.GLOBAL_MIN_STORE_DURATION()).to.equal(globalMinStoreDuration2);
		expect(await secretManager.GLOBAL_MAX_STORE_DURATION()).to.equal(globalMaxStoreDuration2);
        expect(await secretManager.ACKNOWLEDGEMENT_TIMEOUT()).to.equal(acknowledgementTimeout2);
		expect(await secretManager.MARK_ALIVE_TIMEOUT()).to.equal(markAliveTimeout2);
		expect(await secretManager.SECRET_STORE_FEE_RATE()).to.equal(secretStoreFeeRate2);
        expect(await secretManager.STAKING_PAYMENT_POOL()).to.equal(stakingPaymentPool2);
        expect(await secretManager.SECRET_STORE()).to.equal(secretStoreAddress2);

		expect(await secretManager.hasRole(await secretManager.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
	});

	it("does not upgrade without admin", async function () {
		const SecretManager = await ethers.getContractFactory("SecretManager");
		const secretManager = await upgrades.deployProxy(
			SecretManager,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					token,
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
			},
		);

		await expect(
			upgrades.upgradeProxy(secretManager.target, SecretManager.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [
					token,
					noOfNodesToSelect,
					globalMaxStoreSize,
					globalMinStoreDuration,
					globalMaxStoreDuration,
					acknowledgementTimeout,
					markAliveTimeout,
					secretStoreFeeRate,
					stakingPaymentPool,
					secretStoreAddress
				],
			}),
		).to.be.revertedWithCustomError(secretManager, "AccessControlUnauthorizedAccount");
	});
});

testERC165(
	"SecretManager - ERC165",
	async function(_signers: Signer[], addrs: string[]) {
		let usdcToken = addrs[1],
			noOfNodesToSelect = 3,
			globalMaxStoreSize = 1e6,
			globalMinStoreDuration = 10,
			globalMaxStoreDuration = 1e6,
			acknowledgementTimeout = 120,
			markAliveTimeout = 900,
			secretStoreFeeRate = 10,
			stakingPaymentPool = addrs[2],
			secretStore = addrs[3];

		const SecretManager = await ethers.getContractFactory("SecretManager");
		const secretManager = await upgrades.deployProxy(
			SecretManager,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
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
					secretStore
				]
			},
		);
		return secretManager;
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

describe("SecretManager - Create secret", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let usdcToken: USDCoin;
	let secretStore: SecretStore;
	let secretManager: SecretManager;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifier = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		) as unknown as AttestationVerifier;

		const Pond = await ethers.getContractFactory("Pond");
        const stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

		const USDCoin = await ethers.getContractFactory("USDCoin");
		usdcToken = await upgrades.deployProxy(
			USDCoin,
			[addrs[0]],
			{
				kind: "uups",
			}
		) as unknown as USDCoin;

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
					stakingToken.target,
					10,
					10**2,
					10**6,
                    1
				]
			},
		) as unknown as SecretStore;

		let noOfNodesToSelect = 3,
			globalMaxStoreSize = 1e6,
			globalMinStoreDuration = 10,
			globalMaxStoreDuration = 1e6,
			acknowledgementTimeout = 120,
			markAliveTimeout = 900,
			secretStoreFeeRate = 10,
			stakingPaymentPool = addrs[2];

		const SecretManager = await ethers.getContractFactory("SecretManager");
		secretManager = await upgrades.deployProxy(
			SecretManager,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					usdcToken.target,
					noOfNodesToSelect,
					globalMaxStoreSize,
					globalMinStoreDuration,
					globalMaxStoreDuration,
					acknowledgementTimeout,
					markAliveTimeout,
					secretStoreFeeRate,
					stakingPaymentPool,
					secretStore.target
				]
			},
		) as unknown as SecretManager;

		await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("SECRET_MANAGER_ROLE")), secretManager.target);
		await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

		await stakingToken.transfer(addrs[1], 10n**20n);
		await stakingToken.connect(signers[1]).approve(secretStore.target, 10n**20n);

		const timestamp = await time.latest() * 1000;
		let signTimestamp = await time.latest() - 540;
		let storageCapacity = 1e9,
			stakeAmount = parseUnits("10");	// 10 POND
		for (let index = 0; index < 4; index++) {
			let [attestationSign, attestation] = await createAttestation(
				pubkeys[17 + index],
				image2,
				wallets[14],
				timestamp - 540000
			);

			let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
															wallets[17 + index]);

			await secretStore.connect(signers[1]).registerSecretStore(
				attestationSign,
				attestation,
				storageCapacity,
				signTimestamp,
				signedDigest,
				stakeAmount
			);
		}
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can create secret", async function() {
		let sizeLimit = 1000,
			endTimestamp = await time.latest() + 1000,
			usdcDeposit = parseUnits("30", 6);

		await expect(secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit))
			.to.emit(secretManager, "SecretCreated");
	});

	it("cannot create secret with invalid size limit", async function() {
		let sizeLimit = 0,
			endTimestamp = await time.latest() + 1000,
			usdcDeposit = parseUnits("30", 6);

		await expect(secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidSizeLimit");

		sizeLimit = 1e7;
		await expect(secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidSizeLimit");
	});

	it("cannot create secret with invalid end timestamp", async function() {
		let sizeLimit = 1000,
			endTimestamp = await time.latest(),
			usdcDeposit = parseUnits("30", 6);

		await expect(secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidEndTimestamp");

			endTimestamp = await time.latest() + 1e7;
		await expect(secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidEndTimestamp");
	});

	it("cannot create secret with insufficient usdc deposit", async function() {
		let sizeLimit = 1000,
			endTimestamp = await time.latest() + 1000,
			usdcDeposit = 10;

		await expect(secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerInsufficientUsdcDeposit");
	});

	it("cannot create secret when resources are unavailable", async function() {
		await secretStore.connect(signers[1]).drainSecretStore(addrs[17]);
		await secretStore.connect(signers[1]).drainSecretStore(addrs[18]);

		await secretStore.connect(signers[1]).deregisterSecretStore(addrs[17]);
		await secretStore.connect(signers[1]).deregisterSecretStore(addrs[18]);

		let sizeLimit = 1000,
			endTimestamp = await time.latest() + 1000,
			usdcDeposit = parseUnits("30", 6);

		await expect(secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerUnavailableResources");
	});

});

describe("SecretManager - Acknowledge secret", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let usdcToken: USDCoin;
	let secretStore: SecretStore;
	let secretManager: SecretManager;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifier = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		) as unknown as AttestationVerifier;

		const Pond = await ethers.getContractFactory("Pond");
        const stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

		const USDCoin = await ethers.getContractFactory("USDCoin");
		usdcToken = await upgrades.deployProxy(
			USDCoin,
			[addrs[0]],
			{
				kind: "uups",
			}
		) as unknown as USDCoin;

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
					stakingToken.target,
					10,
					10**2,
					10**6,
                    1
				]
			},
		) as unknown as SecretStore;

		let noOfNodesToSelect = 3,
			globalMaxStoreSize = 1e6,
			globalMinStoreDuration = 10,
			globalMaxStoreDuration = 1e6,
			acknowledgementTimeout = 120,
			markAliveTimeout = 900,
			secretStoreFeeRate = 10,
			stakingPaymentPool = addrs[2];

		const SecretManager = await ethers.getContractFactory("SecretManager");
		secretManager = await upgrades.deployProxy(
			SecretManager,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					usdcToken.target,
					noOfNodesToSelect,
					globalMaxStoreSize,
					globalMinStoreDuration,
					globalMaxStoreDuration,
					acknowledgementTimeout,
					markAliveTimeout,
					secretStoreFeeRate,
					stakingPaymentPool,
					secretStore.target
				]
			},
		) as unknown as SecretManager;

		await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("SECRET_MANAGER_ROLE")), secretManager.target);
		await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

		await stakingToken.transfer(addrs[1], 10n**20n);
		await stakingToken.connect(signers[1]).approve(secretStore.target, 10n**20n);

		// REGISTER SECRET STORE ENCLAVES
		const timestamp = await time.latest() * 1000;
		let signTimestamp = await time.latest() - 540;
		let storageCapacity = 1e9,
			stakeAmount = parseUnits("10");	// 10 POND
		for (let index = 0; index < 3; index++) {
			let [attestationSign, attestation] = await createAttestation(
				pubkeys[17 + index],
				image2,
				wallets[14],
				timestamp - 540000
			);

			let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
															wallets[17 + index]);

			await secretStore.connect(signers[1]).registerSecretStore(
				attestationSign,
				attestation,
				storageCapacity,
				signTimestamp,
				signedDigest,
				stakeAmount
			);
		}

		// CREATE SECRET
		let sizeLimit = 1000,
			endTimestamp = await time.latest() + 1000,
			usdcDeposit = parseUnits("30", 6);
		await secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can acknowledge secret", async function() {
		let secretId = 1,
			signTimestamp = await time.latest() - 540,
			signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);

		await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
			.to.emit(secretManager, "SecretStoreAcknowledgementSuccess")
			.withArgs(secretId, addrs[17]);
	});

	it("cannot acknowledge secret after acknowledgement timeout", async function() {
		let secretId = 1,
			signTimestamp = await time.latest(),
			signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);

		await time.increase(150);
		await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerAcknowledgementTimeOver")
	});

	it("cannot acknowledge secret after signature expired", async function() {
		let secretId = 1,
		signTimestamp = await time.latest() - 610,
		signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);

		await expect(secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerSignatureTooOld")
	});

	it("can mark acknowledgement failed", async function() {
		let secretId = 1;
		await time.increase(150);

		await expect(secretManager.acknowledgeStoreFailed(secretId))
			.to.emit(secretManager, "SecretStoreAcknowledgementFailed")
			.withArgs(secretId);
	});

	it("cannot mark acknowledgement failed if acknowledgement timeout is pending", async function() {
		let secretId = 1;
		await expect(secretManager.acknowledgeStoreFailed(secretId))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerAcknowledgementTimeoutPending");
	});

	it("cannot mark acknowledgement failed if secret has been already acknowledged", async function() {
		let secretId = 1,
			signTimestamp = await time.latest() - 540;
		for (let index = 0; index < 3; index++) {
			let signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17 + index]);
			await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
		}

		await time.increase(150);
		await expect(secretManager.acknowledgeStoreFailed(secretId))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerAcknowledgedAlready");
	});
});

describe("SecretManager - Alive checks for secret", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let usdcToken: USDCoin;
	let secretStore: SecretStore;
	let secretManager: SecretManager;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifier = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		) as unknown as AttestationVerifier;

		const Pond = await ethers.getContractFactory("Pond");
        const stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

		const USDCoin = await ethers.getContractFactory("USDCoin");
		usdcToken = await upgrades.deployProxy(
			USDCoin,
			[addrs[0]],
			{
				kind: "uups",
			}
		) as unknown as USDCoin;

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
					stakingToken.target,
					10,
					10**2,
					10**6,
                    1
				]
			},
		) as unknown as SecretStore;

		let noOfNodesToSelect = 3,
			globalMaxStoreSize = 1e6,
			globalMinStoreDuration = 10,
			globalMaxStoreDuration = 1e6,
			acknowledgementTimeout = 120,
			markAliveTimeout = 900,
			secretStoreFeeRate = 10,
			stakingPaymentPool = addrs[2];

		const SecretManager = await ethers.getContractFactory("SecretManager");
		secretManager = await upgrades.deployProxy(
			SecretManager,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					usdcToken.target,
					noOfNodesToSelect,
					globalMaxStoreSize,
					globalMinStoreDuration,
					globalMaxStoreDuration,
					acknowledgementTimeout,
					markAliveTimeout,
					secretStoreFeeRate,
					stakingPaymentPool,
					secretStore.target
				]
			},
		) as unknown as SecretManager;

		await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("SECRET_MANAGER_ROLE")), secretManager.target);
		await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

		await stakingToken.transfer(addrs[1], 10n**20n);
		await stakingToken.connect(signers[1]).approve(secretStore.target, 10n**20n);

		// REGISTER SECRET STORE ENCLAVES
		const timestamp = await time.latest() * 1000;
		let signTimestamp = await time.latest();
		let storageCapacity = 1e9,
			stakeAmount = parseUnits("10");	// 10 POND
		for (let index = 0; index < 3; index++) {
			let [attestationSign, attestation] = await createAttestation(
				pubkeys[17 + index],
				image2,
				wallets[14],
				timestamp - 540000
			);

			let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
															wallets[17 + index]);

			await secretStore.connect(signers[1]).registerSecretStore(
				attestationSign,
				attestation,
				storageCapacity,
				signTimestamp,
				signedDigest,
				stakeAmount
			);
		}

		// CREATE SECRET
		let sizeLimit = 1000,
			endTimestamp = await time.latest() + 800,
			usdcDeposit = parseUnits("30", 6);
		await secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit);

		let secretId = 1,
			signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
		await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can submit alive check", async function() {
		let secretId = 1,
			signTimestamp = await time.latest(),
			signedDigest = await createAliveSignature(secretId, signTimestamp, wallets[17]);

		await expect(secretManager.markStoreAlive(secretId, signTimestamp, signedDigest))
			.to.emit(secretManager, "SecretStoreAlive")
			.withArgs(secretId, addrs[17]);
	});

	it("cannot submit alive check with expired signature", async function() {
		let secretId = 1,
			signTimestamp = await time.latest() - 610,
			signedDigest = await createAliveSignature(secretId, signTimestamp, wallets[17]);

		await expect(secretManager.markStoreAlive(secretId, signTimestamp, signedDigest))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerSignatureTooOld")
	});

	it("cannot submit alive check before acknowledgement", async function() {
		let secretId = 1,
			signTimestamp = await time.latest(),
			signedDigest = await createAliveSignature(secretId, signTimestamp, wallets[18]);

		await expect(secretManager.markStoreAlive(secretId, signTimestamp, signedDigest))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerUnacknowledged")
	});

	it("cannot submit alive check after alive timeout", async function() {
		await time.increase(1000);
		let secretId = 1,
			signTimestamp = await time.latest(),
			signedDigest = await createAliveSignature(secretId, signTimestamp, wallets[17]);

		await expect(secretManager.markStoreAlive(secretId, signTimestamp, signedDigest))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerMarkAliveTimeoutOver")
	});

	it("can submit alive check after end timestamp, and delete the secret data", async function() {
		let secretId = 1,
			signTimestamp = await time.latest(),
			signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[18]);
		await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

		signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[19]);
		await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

		await time.increase(850);
		signTimestamp = await time.latest();
		for (let index = 0; index < 3; index++) {
			signedDigest = await createAliveSignature(secretId, signTimestamp, wallets[17 + index]);
			await secretManager.markStoreAlive(secretId, signTimestamp, signedDigest);
		}

		const userStorage = await secretManager.userStorage(secretId);
		expect(userStorage.owner).to.eq(ZeroAddress);
	});

	// it("can mark secret store dead", async function () {
	// 	let secretId = 1,
	// 		signTimestamp = await time.latest(),
	// 		signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[18]);
	// 	await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);

	// 	await time.increase(910);
	// 	// let secretId = 1;
	// 	await expect(secretManager.markStoreDead(secretId))
	// 		// .to.emit(secretManager, "SecretResourceUnavailable").withArgs(secretId);

	// 	const selectedEnclaves = await secretManager.getSelectedEnclaves(secretId);
	// 	console.log("selectedEnclaves: ", selectedEnclaves, selectedEnclaves.length);
	// 	// expect(selectedEnclaves.length).to.eq(2);
	// });
});

describe("SecretManager - Update end timestamp of secret", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let usdcToken: USDCoin;
	let secretStore: SecretStore;
	let secretManager: SecretManager;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifier = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		) as unknown as AttestationVerifier;

		const Pond = await ethers.getContractFactory("Pond");
        const stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

		const USDCoin = await ethers.getContractFactory("USDCoin");
		usdcToken = await upgrades.deployProxy(
			USDCoin,
			[addrs[0]],
			{
				kind: "uups",
			}
		) as unknown as USDCoin;

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
					stakingToken.target,
					10,
					10**2,
					10**6,
                    1
				]
			},
		) as unknown as SecretStore;

		let noOfNodesToSelect = 3,
			globalMaxStoreSize = 1e6,
			globalMinStoreDuration = 10,
			globalMaxStoreDuration = 1e6,
			acknowledgementTimeout = 120,
			markAliveTimeout = 900,
			secretStoreFeeRate = 10,
			stakingPaymentPool = addrs[2];

		const SecretManager = await ethers.getContractFactory("SecretManager");
		secretManager = await upgrades.deployProxy(
			SecretManager,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					usdcToken.target,
					noOfNodesToSelect,
					globalMaxStoreSize,
					globalMinStoreDuration,
					globalMaxStoreDuration,
					acknowledgementTimeout,
					markAliveTimeout,
					secretStoreFeeRate,
					stakingPaymentPool,
					secretStore.target
				]
			},
		) as unknown as SecretManager;

		await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("SECRET_MANAGER_ROLE")), secretManager.target);
		await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

		await stakingToken.transfer(addrs[1], 10n**20n);
		await stakingToken.connect(signers[1]).approve(secretStore.target, 10n**20n);

		// REGISTER SECRET STORE ENCLAVES
		const timestamp = await time.latest() * 1000;
		let signTimestamp = await time.latest();
		let storageCapacity = 1e9,
			stakeAmount = parseUnits("10");	// 10 POND
		for (let index = 0; index < 3; index++) {
			let [attestationSign, attestation] = await createAttestation(
				pubkeys[17 + index],
				image2,
				wallets[14],
				timestamp - 540000
			);

			let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
															wallets[17 + index]);

			await secretStore.connect(signers[1]).registerSecretStore(
				attestationSign,
				attestation,
				storageCapacity,
				signTimestamp,
				signedDigest,
				stakeAmount
			);
		}

		// CREATE SECRET
		let sizeLimit = 1000,
			endTimestamp = await time.latest() + 800,
			usdcDeposit = parseUnits("30", 6);
		await secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit);

		let secretId = 1,
			signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
		await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can increase end timestamp", async function() {
		let secretId = 1,
			endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp + 100n,
			usdcDeposit = parseUnits("3", 6);

		await expect(secretManager.updateSecretEndTimestamp(secretId, endTimestamp, usdcDeposit))
			.to.emit(secretManager, "SecretEndTimestampUpdated")
			.withArgs(secretId, endTimestamp);
	});

	it("can decrease end timestamp", async function() {
		let secretId = 1,
			endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp - 100n,
			usdcDeposit = 0;

		await expect(secretManager.updateSecretEndTimestamp(secretId, endTimestamp, usdcDeposit))
			.to.emit(secretManager, "SecretEndTimestampUpdated")
			.withArgs(secretId, endTimestamp);
	});

	it("cannot update end timestamp without secret owner", async function() {
		let secretId = 1,
			endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp - 100n,
			usdcDeposit = 0;

		await expect(secretManager.connect(signers[1]).updateSecretEndTimestamp(secretId, endTimestamp, usdcDeposit))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerNotUserStoreOwner");
	});

	it("cannot update end timestamp to earlier than the current timestamp", async function() {
		let secretId = 1,
			endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp - 1000n,
			usdcDeposit = 0;

		await expect(secretManager.updateSecretEndTimestamp(secretId, endTimestamp, usdcDeposit))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerInvalidEndTimestamp");
	});

	it("cannot update end timestamp after the secret is terminated", async function() {
		await time.increase(1000);
		let secretId = 1,
			endTimestamp = (await secretManager.userStorage(secretId)).endTimestamp + 400n,
			usdcDeposit = parseUnits("1", 6);

		await expect(secretManager.updateSecretEndTimestamp(secretId, endTimestamp, usdcDeposit))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerAlreadyTerminated");
	});
});

describe("SecretManager - Update end timestamp of secret", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let usdcToken: USDCoin;
	let secretStore: SecretStore;
	let secretManager: SecretManager;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifier = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		) as unknown as AttestationVerifier;

		const Pond = await ethers.getContractFactory("Pond");
        const stakingToken = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        }) as unknown as Pond;

		const USDCoin = await ethers.getContractFactory("USDCoin");
		usdcToken = await upgrades.deployProxy(
			USDCoin,
			[addrs[0]],
			{
				kind: "uups",
			}
		) as unknown as USDCoin;

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
					stakingToken.target,
					10,
					10**2,
					10**6,
                    1
				]
			},
		) as unknown as SecretStore;

		let noOfNodesToSelect = 3,
			globalMaxStoreSize = 1e6,
			globalMinStoreDuration = 10,
			globalMaxStoreDuration = 1e6,
			acknowledgementTimeout = 120,
			markAliveTimeout = 900,
			secretStoreFeeRate = 10,
			stakingPaymentPool = addrs[2];

		const SecretManager = await ethers.getContractFactory("SecretManager");
		secretManager = await upgrades.deployProxy(
			SecretManager,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					usdcToken.target,
					noOfNodesToSelect,
					globalMaxStoreSize,
					globalMinStoreDuration,
					globalMaxStoreDuration,
					acknowledgementTimeout,
					markAliveTimeout,
					secretStoreFeeRate,
					stakingPaymentPool,
					secretStore.target
				]
			},
		) as unknown as SecretManager;

		await secretStore.grantRole(keccak256(ethers.toUtf8Bytes("SECRET_MANAGER_ROLE")), secretManager.target);
		await usdcToken.approve(secretManager.target, parseUnits("10000", 6));

		await stakingToken.transfer(addrs[1], 10n**20n);
		await stakingToken.connect(signers[1]).approve(secretStore.target, 10n**20n);

		// REGISTER SECRET STORE ENCLAVES
		const timestamp = await time.latest() * 1000;
		let signTimestamp = await time.latest();
		let storageCapacity = 1e9,
			stakeAmount = parseUnits("10");	// 10 POND
		for (let index = 0; index < 3; index++) {
			let [attestationSign, attestation] = await createAttestation(
				pubkeys[17 + index],
				image2,
				wallets[14],
				timestamp - 540000
			);

			let signedDigest = await createSecretStoreSignature(addrs[1], storageCapacity, signTimestamp,
															wallets[17 + index]);

			await secretStore.connect(signers[1]).registerSecretStore(
				attestationSign,
				attestation,
				storageCapacity,
				signTimestamp,
				signedDigest,
				stakeAmount
			);
		}

		// CREATE SECRET
		let sizeLimit = 1000,
			endTimestamp = await time.latest() + 800,
			usdcDeposit = parseUnits("30", 6);
		await secretManager.createSecret(sizeLimit, endTimestamp, usdcDeposit);

		let secretId = 1,
			signedDigest = await createAcknowledgeSignature(secretId, signTimestamp, wallets[17]);
		await secretManager.acknowledgeStore(secretId, signTimestamp, signedDigest);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can terminate the secret before end timestamp", async function() {
		let secretId = 1;
		await expect(secretManager.terminateSecret(secretId))
			.to.emit(secretManager, "SecretTerminated").withArgs(secretId);
	});

	it("cannot update end timestamp without secret owner", async function() {
		let secretId = 1;
		await expect(secretManager.connect(signers[1]).terminateSecret(secretId))
			.to.be.revertedWithCustomError(secretManager, "SecretManagerNotUserStoreOwner");
	});
});

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

async function createAcknowledgeSignature(
	secretId: number,
	signTimestamp: number,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const domain = {
		name: 'marlin.oyster.SecretManager',
		version: '1',
	};

	const types = {
		Acknowledge: [
			{ name: 'secretId', type: 'uint256' },
			{ name: 'signTimestamp', type: 'uint256' }
		]
	};

	const value = {
		secretId,
		signTimestamp
	};

	const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
	return ethers.Signature.from(sign).serialized;
}

async function createAliveSignature(
	secretId: number,
	signTimestamp: number,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const domain = {
		name: 'marlin.oyster.SecretManager',
		version: '1',
	};

	const types = {
		Alive: [
			{ name: 'secretId', type: 'uint256' },
			{ name: 'signTimestamp', type: 'uint256' }
		]
	};

	const value = {
		secretId,
		signTimestamp
	};

	const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
	return ethers.Signature.from(sign).serialized;
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
}

function normalize(key: string): string {
	return '0x' + key.substring(4);
}