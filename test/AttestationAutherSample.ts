import { expect } from "chai";
import { BytesLike, Signer, Wallet } from "ethers";
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

const FIRST_FAMILY = ethers.id("FIRST_FAMILY");
const SECOND_FAMILY = ethers.id("SECOND_FAMILY");
const THIRD_FAMILY = ethers.id("THIRD_FAMILY");

describe("AttestationAutherSample - Init", function() {
	let signers: Signer[];
	let addrs: string[];

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("deploys", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);
		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
	});

	it("deploys and initializes", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]);
		await attestationAutherSample.initialize([image1]);

		expect(await attestationAutherSample.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await attestationAutherSample.ATTESTATION_MAX_AGE()).to.equal(600);
		expect(await attestationAutherSample.hasRole(await attestationAutherSample.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;

		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
	});

	it("deploys and initializes with multiple images", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]);
		await attestationAutherSample.initialize([image1, image2, image3]);

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
		const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]);
		await expect(
			attestationAutherSample.initialize([])
		).to.be.revertedWithCustomError(AttestationAutherSample, "AttestationAutherSampleNoImageProvided");
	});

	it("deploys and initializes with families", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]);
		await attestationAutherSample.initializeWithFamilies([image1, image2, image3], [FIRST_FAMILY, SECOND_FAMILY, THIRD_FAMILY]);

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
		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), FIRST_FAMILY)).to.be.true;
		expect(await attestationAutherSample.isImageInFamily(getImageId(image2), FIRST_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(getImageId(image3), FIRST_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), SECOND_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(getImageId(image2), SECOND_FAMILY)).to.be.true;
		expect(await attestationAutherSample.isImageInFamily(getImageId(image3), SECOND_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), THIRD_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(getImageId(image2), THIRD_FAMILY)).to.be.false;
		expect(await attestationAutherSample.isImageInFamily(getImageId(image3), THIRD_FAMILY)).to.be.true;
	});

	it("cannot initialize with families with no whitelisted images", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]);
		await expect(
			attestationAutherSample.initializeWithFamilies([], [])
		).to.be.revertedWithCustomError(AttestationAutherSample, "AttestationAutherSampleNoImageProvided");
	});

	it("cannot initialize with families with mismatched lengths", async function() {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]);
		await expect(
			attestationAutherSample.initializeWithFamilies([image1, image2, image3], [FIRST_FAMILY, SECOND_FAMILY])
		).to.be.revertedWithCustomError(AttestationAutherSample, "AttestationAutherMismatchedLengths");
	});
});

testERC165(
	"AttestationAutherSample - ERC165",
	async function(_signers: Signer[], addrs: string[]) {
		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]);
		await attestationAutherSample.initialize([image1, image2, image3]);
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
	const attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]);
	await attestationAutherSample.initialize([image1, image2, image3]);
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
		attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]) as unknown as AttestationAutherSample;
		await attestationAutherSample.initialize([image1, image2]);
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

		expect(await attestationAutherSample.whitelistEnclaveImage.staticCall(image3.PCR0, image3.PCR1, image3.PCR2)).to.deep.equal([getImageId(image3), true]);
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

	it("admin can rewhitelist image", async function() {
		expect(await attestationAutherSample.whitelistEnclaveImage.staticCall(image3.PCR0, image3.PCR1, image3.PCR2)).to.deep.equal([getImageId(image3), true]);
		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, image3.PCR1, image3.PCR2))
			.to.emit(attestationAutherSample, "EnclaveImageWhitelisted").withArgs(getImageId(image3), image3.PCR0, image3.PCR1, image3.PCR2);
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}

		expect(await attestationAutherSample.whitelistEnclaveImage.staticCall(image3.PCR0, image3.PCR1, image3.PCR2)).to.deep.equal([getImageId(image3), false]);
		await expect(attestationAutherSample.whitelistEnclaveImage(image3.PCR0, image3.PCR1, image3.PCR2))
			.to.not.emit(attestationAutherSample, "EnclaveImageWhitelisted");
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
		attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]) as unknown as AttestationAutherSample;
		await attestationAutherSample.initialize([image1, image2]);
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

		expect(await attestationAutherSample.revokeEnclaveImage.staticCall(getImageId(image1))).to.be.true;
		await expect(attestationAutherSample.revokeEnclaveImage(getImageId(image1)))
			.to.emit(attestationAutherSample, "EnclaveImageRevoked").withArgs(getImageId(image1));
		{
			const { PCR0, PCR1, PCR2 } = await attestationAutherSample.getWhitelistedImage(getImageId(image1));
			expect([PCR0, PCR1, PCR2]).to.deep.equal(["0x", "0x", "0x"]);
		}
	});

	it("admin can revoke unwhitelisted image", async function() {
		expect(await attestationAutherSample.revokeEnclaveImage.staticCall(getImageId(image3))).to.be.false;
		await expect(attestationAutherSample.revokeEnclaveImage(getImageId(image3)))
			.to.not.emit(attestationAutherSample, "EnclaveImageRevoked");
	});
});

describe("AttestationAutherSample - Add image to family", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSample;
	const TEST_FAMILY = ethers.id("TEST_FAMILY");

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]) as unknown as AttestationAutherSample;
		await attestationAutherSample.initialize([image1, image2]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot add image to family", async function() {
		await expect(attestationAutherSample.connect(signers[1]).addEnclaveImageToFamily(getImageId(image1), TEST_FAMILY)).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can add image to family", async function() {
		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), TEST_FAMILY)).to.be.false;

		expect(await attestationAutherSample.addEnclaveImageToFamily.staticCall(getImageId(image1), TEST_FAMILY)).to.be.true;
		await expect(attestationAutherSample.addEnclaveImageToFamily(getImageId(image1), TEST_FAMILY))
			.to.emit(attestationAutherSample, "EnclaveImageAddedToFamily").withArgs(getImageId(image1), TEST_FAMILY);

		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), TEST_FAMILY)).to.be.true;
	});

	it("admin can readd image to family", async function() {
		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), TEST_FAMILY)).to.be.false;

		expect(await attestationAutherSample.addEnclaveImageToFamily.staticCall(getImageId(image1), TEST_FAMILY)).to.be.true;
		await expect(attestationAutherSample.addEnclaveImageToFamily(getImageId(image1), TEST_FAMILY))
			.to.emit(attestationAutherSample, "EnclaveImageAddedToFamily").withArgs(getImageId(image1), TEST_FAMILY);

		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), TEST_FAMILY)).to.be.true;

		expect(await attestationAutherSample.addEnclaveImageToFamily.staticCall(getImageId(image1), TEST_FAMILY)).to.be.false;
		await expect(attestationAutherSample.addEnclaveImageToFamily(getImageId(image1), TEST_FAMILY))
			.to.not.emit(attestationAutherSample, "EnclaveImageAddedToFamily");
	});
});

describe("AttestationAutherSample - Remove image from family", function() {
	let signers: Signer[];
	let addrs: string[];
	let attestationAutherSample: AttestationAutherSample;
	const TEST_FAMILY = ethers.id("TEST_FAMILY");

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const AttestationAutherSample = await ethers.getContractFactory("AttestationAutherSample");
		attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]) as unknown as AttestationAutherSample;
		await attestationAutherSample.initialize([image1, image2]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot add image to family", async function() {
		await attestationAutherSample.addEnclaveImageToFamily(getImageId(image1), TEST_FAMILY);
		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), TEST_FAMILY)).to.be.true;

		await expect(attestationAutherSample.connect(signers[1]).removeEnclaveImageFromFamily(getImageId(image1), TEST_FAMILY)).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can add image to family", async function() {
		await attestationAutherSample.addEnclaveImageToFamily(getImageId(image1), TEST_FAMILY);
		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), TEST_FAMILY)).to.be.true;

		expect(await attestationAutherSample.removeEnclaveImageFromFamily.staticCall(getImageId(image1), TEST_FAMILY)).to.be.true;
		await expect(attestationAutherSample.removeEnclaveImageFromFamily(getImageId(image1), TEST_FAMILY))
			.to.emit(attestationAutherSample, "EnclaveImageRemovedFromFamily").withArgs(getImageId(image1), TEST_FAMILY);

		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), TEST_FAMILY)).to.be.false;
	});

	it("admin can readd image to family", async function() {
		await attestationAutherSample.addEnclaveImageToFamily(getImageId(image1), TEST_FAMILY);
		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), TEST_FAMILY)).to.be.true;

		expect(await attestationAutherSample.removeEnclaveImageFromFamily.staticCall(getImageId(image1), TEST_FAMILY)).to.be.true;
		await expect(attestationAutherSample.removeEnclaveImageFromFamily(getImageId(image1), TEST_FAMILY))
			.to.emit(attestationAutherSample, "EnclaveImageRemovedFromFamily").withArgs(getImageId(image1), TEST_FAMILY);

		expect(await attestationAutherSample.isImageInFamily(getImageId(image1), TEST_FAMILY)).to.be.false;

		expect(await attestationAutherSample.removeEnclaveImageFromFamily.staticCall(getImageId(image1), TEST_FAMILY)).to.be.false;
		await expect(attestationAutherSample.removeEnclaveImageFromFamily(getImageId(image1), TEST_FAMILY))
			.to.not.emit(attestationAutherSample, "EnclaveImageRemovedFromFamily");
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
		attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]) as unknown as AttestationAutherSample;
		await attestationAutherSample.initialize([image1, image2]);
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

	it("admin can rewhitelist enclave", async function() {
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(ethers.ZeroHash);

		expect(await attestationAutherSample.whitelistEnclaveKey.staticCall(pubkeys[15], getImageId(image1))).to.be.true;
		await expect(attestationAutherSample.whitelistEnclaveKey(pubkeys[15], getImageId(image1)))
			.to.emit(attestationAutherSample, "EnclaveKeyWhitelisted").withArgs(pubkeys[15], getImageId(image1));
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(getImageId(image1));

		expect(await attestationAutherSample.whitelistEnclaveKey.staticCall(pubkeys[15], getImageId(image1))).to.be.false;
		await expect(attestationAutherSample.whitelistEnclaveKey(pubkeys[15], getImageId(image1)))
			.to.not.emit(attestationAutherSample, "EnclaveKeyWhitelisted");
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
		attestationAutherSample = await AttestationAutherSample.deploy(addrs[10], 600, addrs[0]) as unknown as AttestationAutherSample;
		await attestationAutherSample.initialize([image1, image2]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("non admin cannot revoke enclave", async function() {
		await expect(attestationAutherSample.connect(signers[1]).revokeEnclaveKey(pubkeys[14])).to.be.revertedWithCustomError(attestationAutherSample, "AccessControlUnauthorizedAccount");
	});

	it("admin can revoke enclave", async function() {
		await attestationAutherSample.whitelistEnclaveKey(pubkeys[14], getImageId(image2));
		expect(await attestationAutherSample.getVerifiedKey(addrs[14])).to.equal(getImageId(image2));

		expect(await attestationAutherSample.revokeEnclaveKey.staticCall(pubkeys[14])).to.be.true;
		await expect(attestationAutherSample.revokeEnclaveKey(pubkeys[14]))
			.to.emit(attestationAutherSample, "EnclaveKeyRevoked").withArgs(pubkeys[14]);
		expect(await attestationAutherSample.getVerifiedKey(addrs[14])).to.equal(ethers.ZeroHash);
	});

	it("admin can revoke unwhitelisted enclave", async function() {
		expect(await attestationAutherSample.revokeEnclaveKey.staticCall(pubkeys[15])).to.be.false;
		await expect(attestationAutherSample.revokeEnclaveKey(pubkeys[14]))
			.to.not.emit(attestationAutherSample, "EnclaveKeyRevoked");
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
		attestationAutherSample = await AttestationAutherSample.deploy(await attestationVerifier.getAddress(), 600, addrs[0]) as unknown as AttestationAutherSample;
		await attestationAutherSample.initialize([image2, image3]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify enclave key", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		expect(await attestationAutherSample.connect(signers[1]).verifyEnclaveKey.staticCall(signature, attestation)).to.be.true;
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.emit(attestationAutherSample, "EnclaveKeyVerified").withArgs(pubkeys[15], getImageId(image3));
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(getImageId(image3));
	});

	it("cannot verify enclave key with too old attestation", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 660000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherAttestationTooOld");
	});

	it("cannot verify enclave key with invalid data", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, enclavePubKey: pubkeys[16] }))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, PCR0: attestation.PCR1 }))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, PCR1: attestation.PCR0 }))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, PCR2: attestation.PCR0 }))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, PCR0: image2.PCR0, PCR1: image2.PCR1, PCR2: image2.PCR2 }))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, { ...attestation, timestampInMilliseconds: timestamp - 200000 }))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
	});

	it("cannot verify enclave key with invalid public key", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(ethers.ZeroAddress, image3, wallets[14], timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherPubkeyLengthInvalid");
	});

	it("cannot verify enclave key with unwhitelisted image", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image1, wallets[14], timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("can reverify enclave key", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		expect(await attestationAutherSample.connect(signers[1]).verifyEnclaveKey.staticCall(signature, attestation)).to.be.true;
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.emit(attestationAutherSample, "EnclaveKeyVerified").withArgs(pubkeys[15], getImageId(image3));
		expect(await attestationAutherSample.getVerifiedKey(addrs[15])).to.equal(getImageId(image3));

		expect(await attestationAutherSample.connect(signers[1]).verifyEnclaveKey.staticCall(signature, attestation)).to.be.false;
		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.not.emit(attestationAutherSample, "EnclaveKeyVerified");
	});

	it("cannot verify enclave key with unwhitelisted key", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[16], timestamp - 540000);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
	});

	it("cannot verify enclave key with revoked key", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await attestationVerifier.revokeEnclaveKey(pubkeys[14]);

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierKeyNotVerified");
	});

	it("cannot verify enclave key with revoked sample image", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await attestationAutherSample.revokeEnclaveImage(getImageId(image3));

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("cannot verify enclave key with revoked verifier image", async function() {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await attestationVerifier.revokeEnclaveImage(getImageId(image1));

		await expect(attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.be.revertedWithCustomError(attestationVerifier, "AttestationVerifierImageNotWhitelisted");
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
		attestationAutherSample = await AttestationAutherSample.deploy(await attestationVerifier.getAddress(), 600, addrs[0]) as unknown as AttestationAutherSample;
		await attestationAutherSample.initialize([image2, image3]);

		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(signature, "testmsg")).to.not.be.reverted;
	});

	it("cannot verify with invalid data", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "randommsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with unwhitelisted key", async function() {
		let signature = await createSignature("testmsg", wallets[14]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with revoked key", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveKey(pubkeys[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with revoked image", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveImage(getImageId(image3));

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});
});

describe("AttestationAutherSample - Verify with family", function() {
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
		attestationAutherSample = await AttestationAutherSample.deploy(await attestationVerifier.getAddress(), 600, addrs[0]) as unknown as AttestationAutherSample;
		await attestationAutherSample.initializeWithFamilies([image2, image3], [SECOND_FAMILY, THIRD_FAMILY]);

		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await attestationAutherSample.connect(signers[1]).verifyEnclaveKey(signature, attestation);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(signature, "testmsg")).to.not.be.reverted;
	});

	it("cannot verify with invalid data", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "randommsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with unwhitelisted key", async function() {
		let signature = await createSignature("testmsg", wallets[14]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with revoked key", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveKey(pubkeys[15]);

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify with revoked image", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveImage(getImageId(image3));

		await expect(attestationAutherSample.connect(signers[1]).verify(
			signature, "testmsg",
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("can verify family", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(signature, "testmsg", THIRD_FAMILY)).to.not.be.reverted;
	});

	it("cannot verify family with invalid data", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(
			signature, "randommsg", THIRD_FAMILY,
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify family with unwhitelisted key", async function() {
		let signature = await createSignature("testmsg", wallets[14]);

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(
			signature, "testmsg", THIRD_FAMILY,
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify family with revoked key", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveKey(pubkeys[15]);

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(
			signature, "testmsg", THIRD_FAMILY,
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherKeyNotVerified");
	});

	it("cannot verify family with revoked image", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await attestationAutherSample.revokeEnclaveImage(getImageId(image3));

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(
			signature, "testmsg", THIRD_FAMILY,
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotWhitelisted");
	});

	it("cannot verify family with wrong family", async function() {
		let signature = await createSignature("testmsg", wallets[15]);

		await expect(attestationAutherSample.connect(signers[1]).verifyFamily(
			signature, "testmsg", SECOND_FAMILY,
		)).to.be.revertedWithCustomError(attestationAutherSample, "AttestationAutherImageNotInFamily");
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

async function createSignature(
	msg: string,
	sourceEnclaveKey: Wallet,
): Promise<string> {
	const domain = {
		name: 'marlin.oyster.AttestationAutherSample',
		version: '1',
	};

	const types = {
		Message: [
			{ name: 'message', type: 'string' },
		]
	}

	const sign = await sourceEnclaveKey.signTypedData(domain, types, {
		message: msg,
	});
	return ethers.Signature.from(sign).serialized;
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
}
