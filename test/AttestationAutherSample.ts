import { expect } from "chai";
import { Signer, Wallet } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationVerifier, AttestationAutherUpgradeable, AttestationAutherSample } from "../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../utils/testSuite";
import { keccak256, solidityPacked } from "ethers";
import { testERC165 } from "./helpers/erc165";
import { testAdminRole } from "./helpers/rbac";
import { time } from '@nomicfoundation/hardhat-network-helpers';


const image1: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: ethers.hexlify(ethers.randomBytes(48)),
	PCR1: ethers.hexlify(ethers.randomBytes(48)),
	PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

const image2: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: ethers.hexlify(ethers.randomBytes(48)),
	PCR1: ethers.hexlify(ethers.randomBytes(48)),
	PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

const image3: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: ethers.hexlify(ethers.randomBytes(48)),
	PCR1: ethers.hexlify(ethers.randomBytes(48)),
	PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

function getImageId(image: AttestationAutherUpgradeable.EnclaveImageStruct): string {
	return keccak256(solidityPacked(["bytes", "bytes", "bytes"], [image.PCR0, image.PCR1, image.PCR2]));
}

describe("AttestationAutherSample - Init", function() {
	let signers: Signer[];
	let addrs: string[];

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("deploys with initialization disabled", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		await expect(
			attestationAutherSample.initialize([], addrs[0]),
		).to.be.revertedWithCustomError(attestationAutherSample, "InvalidInitialization");

		await expect(
			attestationAutherSample.initialize([image1, image2], addrs[0]),
		).to.be.revertedWithCustomError(attestationAutherSample, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
	});

	it("deploys as proxy and initializes with multiple images", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image2));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
		}
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}
	});

	it("cannot initialize with no whitelisted images", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		await expect(
			upgrades.deployProxy(
				AttestationAutherSample,
				[[], addrs[0]],
				{ kind: "uups", constructorArgs: [addrs[10], 600] },
			)
		).to.be.revertedWithCustomError(AttestationAutherSample, "AttestationAutherSampleNoImageProvided");
	});

	it("cannot initialize with zero address as admin", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		await expect(
			upgrades.deployProxy(
				AttestationAutherSample,
				[[image1, image2, image3], ethers.ZeroAddress],
				{ kind: "uups", constructorArgs: [addrs[10], 600] },
			)
		).to.be.revertedWithCustomError(AttestationAutherSample, "AttestationAutherSampleInvalidAdmin");
	});

	it("upgrades", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);
		await upgrades.upgradeProxy(await attestationAutherSample.getAddress(), AttestationAutherSample, { kind: "uups", constructorArgs: [addrs[10], 600] });

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image2));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
		}
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}
	});

	it("does not upgrade without admin", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);

		await expect(
			upgrades.upgradeProxy(await attestationAutherSample.getAddress(), AttestationAutherSample.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [addrs[10], 600],
			}),
		).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});
});

testERC165(
	"AttestationAutherSample - ERC165",
	async function(_signers: Signer[], addrs: string[]) {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		);
		return attestationAutherSample;
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

testAdminRole("AttestationAutherSample - Admin", async function(_signers: Signer[], addrs: string[]) {
	const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
	const attestationAutherSample = await upgrades.deployProxy(
		AttestationAutherSample,
		[[image1, image2, image3], addrs[0]],
		{ kind: "uups", constructorArgs: [addrs[10], 600] },
	);
	return attestationAutherSample;
});

describe("AttestationAutherSample - Whitelist image", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSample;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		) as unknown as AttestationAutherSample;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot whitelist image", async function() {
		await expect(attestationAutherSample.connect(signers[1]).whitelistEnclaveImage(image3.PCR0, image3.PCR1, image3.PCR2)).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can whitelist image", async function() {
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image3));
			expect([PCR0, PCR1, PCR2]).to.deep.equal(["0x", "0x", "0x"]);
		}

		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, image3.PCR1, image3.PCR2))
			.to.emit(attestationAutherSample, "EnclaveImageWhitelisted").withArgs(getImageId(image3), image3.PCR0, image3.PCR1, image3.PCR2);
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}
	});

	it("admin cannot whitelist image with empty PCRs", async function() {
		await expect(attestationAutherSample.whitelistEnclaveImage("0x", "0x", "0x")).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherPCRsInvalid");
	});

	it("admin cannot whitelist image with invalid PCRs", async function() {
		await expect(attestationAutherSample.whitelistEnclaveImage("0x1111111111", image3.PCR1, image3.PCR2)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherPCRsInvalid");
		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, "0x1111111111", image3.PCR2)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherPCRsInvalid");
		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, image3.PCR1, "0x1111111111")).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherPCRsInvalid");
	});

	it("admin cannot rewhitelist image", async function() {
		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, image3.PCR1, image3.PCR2))
			.to.emit(attestationAutherSample, "EnclaveImageWhitelisted").withArgs(getImageId(image3), image3.PCR0, image3.PCR1, image3.PCR2);
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}

		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, image3.PCR1, image3.PCR2)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageAlreadyWhitelisted");
	});
});

describe("AttestationAutherSample - Revoke image", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSample;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		) as unknown as AttestationAutherSample;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot revoke image", async function() {
		await expect(attestationAutherSample.connect(signers[1]).revokeEnclaveImage(getImageId(image1))).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can revoke image", async function() {
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}

		await expect(attestationAutherSample.revokeEnclaveImage(getImageId(image1)))
			.to.emit(attestationAutherSample, "EnclaveImageRevoked").withArgs(getImageId(image1));
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect([PCR0, PCR1, PCR2]).to.deep.equal(["0x", "0x", "0x"]);
		}
	});

	it("admin cannot revoke unwhitelisted image", async function() {
		await expect(attestationAutherSample.revokeEnclaveImage(getImageId(image3))).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});
});

describe("AttestationAutherSample - Whitelist enclave", function() {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];

	let attestationAutherSample: AttestationAutherSample;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		) as unknown as AttestationAutherSample;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot whitelist enclave", async function() {
		await expect(attestationAutherSample.connect(signers[1]).whitelistEnclaveKey(pubkeys[15], getImageId(image1))).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can whitelist enclave", async function() {
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(ethers.ZeroHash);

		await expect(attestationAutherSample.whitelistEnclaveKey(pubkeys[15], getImageId(image1)))
			.to.emit(attestationAutherSample, "EnclaveKeyWhitelisted").withArgs(pubkeys[15], getImageId(image1));
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(getImageId(image1));
	});

	it("admin cannot whitelist enclave with unwhitelisted image", async function() {
		await expect(attestationAutherSample.whitelistEnclaveKey(pubkeys[15], getImageId(image3))).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("admin cannot rewhitelist enclave", async function() {
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(ethers.ZeroHash);

		await expect(attestationAutherSample.whitelistEnclaveKey(pubkeys[15], getImageId(image1)))
			.to.emit(attestationAutherSample, "EnclaveKeyWhitelisted").withArgs(pubkeys[15], getImageId(image1));
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(getImageId(image1));

		await expect(attestationAutherSample.whitelistEnclaveKey(pubkeys[15], getImageId(image1))).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyAlreadyVerified");
	});
});

describe("AttestationAutherSample - Revoke enclave", function() {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];

	let attestationAutherSample: AttestationAutherSample;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image1, image2], addrs[0]],
			{ kind: "uups", constructorArgs: [addrs[10], 600] },
		) as unknown as AttestationAutherSample;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot revoke enclave", async function() {
		await expect(attestationAutherSample.connect(signers[1]).revokeEnclaveKey(normalize(wallets[14].signingKey.publicKey))).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can revoke enclave", async function() {
		await attestationAutherSample.whitelistEnclaveKey(normalize(wallets[14].signingKey.publicKey), getImageId(image2));
		expect(await attestationAutherSample.getVerifiedKey(addrs[14])).to.equal(getImageId(image2));

		await expect(attestationAutherSample.revokeEnclaveKey(normalize(wallets[14].signingKey.publicKey)))
			.to.emit(attestationAutherSample, "EnclaveKeyRevoked").withArgs(normalize(wallets[14].signingKey.publicKey));
		expect(await attestationAutherSample.getVerifiedKey(addrs[14])).to.equal(ethers.ZeroHash);
	});

	it("admin cannot revoke unwhitelisted enclave", async function() {
		await expect(attestationAutherSample.revokeEnclaveKey(pubkeys[15])).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});
});

describe("AttestationAutherSample - Verify enclave key", function() {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];

	let attestationAutherSample: AttestationAutherSample;
	let attestationVerifier: AttestationVerifier;

	before(async function() {
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

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [await attestationVerifier.getAddress(), 600] },
		) as unknown as AttestationAutherSample;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	function normalize(key: string): string {
		return '0x' + key.substring(4);
	}

	it("can verify enclave key", async function() {
		const timestamp = await time.latest() * 1000;
		let attestation = createAttestation(pubkeys[15], image3, wallets[14], 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 2, 4096, timestamp - 540000))
			.to.emit(attestationAutherSample, "EnclaveKeyVerified").withArgs(pubkeys[15], getImageId(image3));
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(getImageId(image3));
	});

	it("cannot verify enclave key with too old attestation", async function() {
		const timestamp = await time.latest() * 1000;
		let attestation = createAttestation(pubkeys[15], image3, wallets[14], 2, 4096, timestamp - 660000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 2, 4096, timestamp - 660000))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherAttestationTooOld");
	});

	it("cannot verify enclave key with invalid data", async function() {
		const timestamp = await time.latest() * 1000;
		let attestation = createAttestation(pubkeys[15], image3, wallets[14], 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image2), 2, 4096, timestamp - 540000))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierDoesNotVerify");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 1, 4096, timestamp - 540000))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierDoesNotVerify");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 2, 4095, timestamp - 540000))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierDoesNotVerify");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, normalize(wallets[16].signingKey.publicKey), getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierDoesNotVerify");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 2, 4096, timestamp - 200000))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierDoesNotVerify");
	});

	it("cannot verify enclave key with invalid public key", async function() {
		const timestamp = await time.latest() * 1000;
		let attestation = createAttestation(ethers.ZeroAddress, image3, wallets[14], 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, ethers.ZeroAddress, getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherPubkeyLengthInvalid");
	});

	it("cannot verify enclave key with unwhitelisted image", async function() {
		const timestamp = await time.latest() * 1000;
		let attestation = createAttestation(pubkeys[15], image1, wallets[14], 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image1), 2, 4096, timestamp - 540000))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("cannot reverify enclave key", async function() {
		const timestamp = await time.latest() * 1000;
		let attestation = createAttestation(pubkeys[15], image3, wallets[14], 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 2, 4096, timestamp - 540000))
			.to.emit(attestationAutherSample, "EnclaveKeyVerified").withArgs(pubkeys[15], getImageId(image3));
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(getImageId(image3));

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyAlreadyVerified");
	});

	it("cannot verify enclave key with unwhitelisted key", async function() {
		const timestamp = await time.latest() * 1000;
		let attestation = createAttestation(pubkeys[15], image3, wallets[16], 2, 4096, timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierDoesNotVerify");
	});

	it("cannot verify enclave key with revoked key", async function() {
		const timestamp = await time.latest() * 1000;
		let attestation = createAttestation(pubkeys[15], image3, wallets[14], 2, 4096, timestamp - 540000);

		await attestationVerifier.revokeEnclaveKey(pubkeys[14]);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierDoesNotVerify");
	});

	it("cannot verify enclave key with revoked sample image", async function() {
		const timestamp = await time.latest() * 1000;
		let attestation = createAttestation(pubkeys[15], image3, wallets[14], 2, 4096, timestamp - 540000);

		await attestationAutherSample.revokeEnclaveImage(getImageId(image3));

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("cannot verify enclave key with revoked verifier image", async function() {
		const timestamp = await time.latest() * 1000;
		let attestation = createAttestation(pubkeys[15], image3, wallets[14], 2, 4096, timestamp - 540000);

		await attestationVerifier.revokeEnclaveImage(getImageId(image1));

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 2, 4096, timestamp - 540000))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierDoesNotVerify");
	});
});

describe("AttestationAutherSample - Safe verify with params", function() {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];

	let attestationAutherSample: AttestationAutherSample;
	let attestationVerifier: AttestationVerifier;

	before(async function() {
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

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		attestationAutherSample = await upgrades.deployProxy(
			AttestationAutherSample,
			[[image2, image3], addrs[0]],
			{ kind: "uups", constructorArgs: [await attestationVerifier.getAddress(), 600] },
		) as unknown as AttestationAutherSample;

		const timestamp = await time.latest() * 1000;
		let attestation = createAttestation(pubkeys[15], image3, wallets[14], 2, 4096, timestamp - 540000);

		await attestationAutherSample.connect(signers[1]).verifyEnclaveKey(attestation, pubkeys[15], getImageId(image3), 2, 4096, timestamp - 540000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify", async function() {
		let signature = createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(signature, "testmsg")).to.not.be.reverted;
	});

	it("cannot verify with invalid data", async function() {
		let signature = createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "randommsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with unwhitelisted key", async function() {
		let signature = createSignature("testmsg", wallets[14]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "randommsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with revoked key", async function() {
		let signature = createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveKey(pubkeys[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with revoked image", async function() {
		let signature = createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveImage(getImageId(image3));

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});
});

function normalize(key: string): string {
	return '0x' + key.substring(4);
}

function createAttestation(
	enclaveKey: string,
	image: AttestationAutherUpgradeable.EnclaveImageStruct,
	sourceEnclaveKey: Wallet,
	CPU: number,
	memory: number,
	timestamp: number,
): string {
	const ATTESTATION_PREFIX = "Enclave Attestation Verified";
	const message = ethers.AbiCoder.defaultAbiCoder().encode(
		["string", "bytes", "bytes", "bytes", "bytes", "uint256", "uint256", "uint256"],
		[ATTESTATION_PREFIX, enclaveKey, image.PCR0, image.PCR1, image.PCR2, CPU, memory, timestamp]
	);
	const digest = ethers.keccak256(message);
	const sign = sourceEnclaveKey.signingKey.sign(digest);
	return ethers.Signature.from(sign).serialized;
}

function createSignature(
	msg: string,
	sourceEnclaveKey: Wallet,
): string {
	const ATTESTATION_PREFIX = "attestation-auther-sample-";
	const message = solidityPacked(
		["string", "string"],
		[ATTESTATION_PREFIX, msg],
	);
	const digest = keccak256(message);
	const sign = sourceEnclaveKey.signingKey.sign(digest);
	return ethers.Signature.from(sign).serialized;
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
}
