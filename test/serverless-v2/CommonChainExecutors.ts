import { joinSignature } from "@ethersproject/bytes";
import { parseUnits } from '@ethersproject/units';
import { Wallet } from '@ethersproject/wallet';
import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, ZeroAddress, ZeroHash, keccak256, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationVerifier, CommonChainExecutors, Pond } from "../../typechain-types";
import { AttestationAutherUpgradeable } from "../../typechain-types/contracts/AttestationAutherSample";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { getAttestationVerifier, getCommonChainExecutors, getPond } from "../../utils/typechainConvertor";

const image1: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: parseUnits("1", 115).toHexString(),
	PCR1: parseUnits("2", 114).toHexString(),
	PCR2: parseUnits("3", 114).toHexString(),
};

const image2: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: parseUnits("4", 114).toHexString(),
	PCR1: parseUnits("5", 114).toHexString(),
	PCR2: parseUnits("6", 114).toHexString(),
};

const image3: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: parseUnits("7", 114).toHexString(),
	PCR1: parseUnits("8", 114).toHexString(),
	PCR2: parseUnits("9", 114).toHexString(),
};

function getImageId(image: AttestationAutherUpgradeable.EnclaveImageStruct): string {
	return keccak256(solidityPacked(["bytes", "bytes", "bytes"], [image.PCR0, image.PCR1, image.PCR2]));
}

describe("CommonChainExecutors - Init", function () {
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
		pubkeys = wallets.map((w) => normalize(w.publicKey));

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifierContract = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[13]], addrs[0]],
			{ kind: "uups" },
		);
		attestationVerifier = getAttestationVerifier(attestationVerifierContract.target as string, signers[0]);

		token = addrs[1];
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("deploys with initialization disabled", async function () {

		const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
		const commonChainExecutors = await CommonChainExecutors.deploy(addrs[10], 600);

		expect(await commonChainExecutors.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await commonChainExecutors.ATTESTATION_MAX_AGE()).to.equal(600);

		await expect(
			commonChainExecutors.__CommonChainExecutors_init(addrs[0], [], token),
		).to.be.revertedWithCustomError(commonChainExecutors, "InvalidInitialization");

		await expect(
			commonChainExecutors.__CommonChainExecutors_init(addrs[0], [image1, image2], token),
		).to.be.revertedWithCustomError(commonChainExecutors, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function () {
		const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
		const commonChainExecutors = await upgrades.deployProxy(
			CommonChainExecutors,
			[addrs[0], [image1], token],
			{
				kind: "uups",
				initializer: "__CommonChainExecutors_init",
				constructorArgs: [attestationVerifier.target, 600]
			},
		);

		expect(await commonChainExecutors.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
		expect(await commonChainExecutors.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await commonChainExecutors.hasRole(await commonChainExecutors.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		expect(await commonChainExecutors.getRoleMemberCount(await commonChainExecutors.DEFAULT_ADMIN_ROLE())).to.equal(1);
		{
			const { PCR0, PCR1, PCR2 } = await commonChainExecutors.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
	});

	it("cannot initialize with zero address as admin", async function () {
		const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
		await expect(
			upgrades.deployProxy(
				CommonChainExecutors,
				[ZeroAddress, [image1, image2, image3], token],
				{
					kind: "uups",
					initializer: "__CommonChainExecutors_init",
					constructorArgs: [attestationVerifier.target, 600]
				},
			)
		).to.be.revertedWith("ZERO_ADDRESS_ADMIN");
	});

	it("upgrades", async function () {
		const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
		const commonChainExecutors = await upgrades.deployProxy(
			CommonChainExecutors,
			[addrs[0], [image1, image2, image3], token],
			{
				kind: "uups",
				initializer: "__CommonChainExecutors_init",
				constructorArgs: [addrs[10], 600]
			},
		);
		await upgrades.upgradeProxy(
			commonChainExecutors.target,
			CommonChainExecutors,
			{
				kind: "uups",
				constructorArgs: [addrs[10], 600]
			}
		);

		expect(await commonChainExecutors.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await commonChainExecutors.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await commonChainExecutors.hasRole(await commonChainExecutors.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		expect(await commonChainExecutors.getRoleMemberCount(await commonChainExecutors.DEFAULT_ADMIN_ROLE())).to.equal(1);
		{
			const { PCR0, PCR1, PCR2 } = await commonChainExecutors.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
		{
			const { PCR0, PCR1, PCR2 } = await commonChainExecutors.getWhitelistedImage(getImageId(image2));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
		}
		{
			const { PCR0, PCR1, PCR2 } = await commonChainExecutors.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}
	});

	it("does not upgrade without admin", async function () {
		const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
		const commonChainExecutors = await upgrades.deployProxy(
			CommonChainExecutors,
			[addrs[0], [image1, image2, image3], token],
			{
				kind: "uups",
				initializer: "__CommonChainExecutors_init",
				constructorArgs: [addrs[10], 600]
			},
		);

		await expect(
			upgrades.upgradeProxy(commonChainExecutors.target, CommonChainExecutors.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [addrs[10], 600],
			}),
		).to.be.revertedWith("only admin");
	});
});

describe("CommonChainExecutors - Verify", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let token: string;
	let commonChainExecutors: CommonChainExecutors;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.publicKey));

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifierContract = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		);
		attestationVerifier = getAttestationVerifier(attestationVerifierContract.target as string, signers[0]);

		token = addrs[1];

		const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
		const commonChainExecutorsContract = await upgrades.deployProxy(
			CommonChainExecutors,
			[addrs[0], [image2, image3], token],
			{
				kind: "uups",
				initializer: "__CommonChainExecutors_init",
				constructorArgs: [attestationVerifier.target, 600]
			},
		);
		commonChainExecutors = getCommonChainExecutors(commonChainExecutorsContract.target as string, signers[0]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify enclave key", async function () {
		const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await expect(commonChainExecutors.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.emit(commonChainExecutors, "EnclaveKeyVerified").withArgs(pubkeys[15], getImageId(image3));
		expect(await commonChainExecutors.getVerifiedKey(addrs[15])).to.equal(getImageId(image3));
	});
});

describe("CommonChainExecutors - Register executor", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let token: Pond;
	let attestationVerifier: AttestationVerifier;
	let commonChainExecutors: CommonChainExecutors;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
        wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.publicKey));

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifierContract = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		);
		attestationVerifier = getAttestationVerifier(attestationVerifierContract.target as string, signers[0]);

		const Pond = await ethers.getContractFactory("Pond");
        const pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
            kind: "uups",
        });
        token = getPond(pondContract.target as string, signers[0]);

		const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
		const commonChainExecutorsContract = await upgrades.deployProxy(
			CommonChainExecutors,
			[addrs[0], [image2, image3], token.target],
			{
				kind: "uups",
				initializer: "__CommonChainExecutors_init",
				constructorArgs: [attestationVerifier.target, 600]
			},
		);
		commonChainExecutors = getCommonChainExecutors(commonChainExecutorsContract.target as string, signers[0]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can register executor", async function () {
		const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let jobCapacity = 20;
		const message = solidityPacked(
			["uint256"],
			[jobCapacity],
		);
		const digest = keccak256(message);
		let sign = wallets[15]._signingKey().signDigest(digest);
		let signedDigest = joinSignature(sign);

		await expect(commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, jobCapacity, signedDigest, 0))
			.to.emit(commonChainExecutors, "EnclaveKeyVerified").withArgs(pubkeys[15], getImageId(image2));
		expect(await commonChainExecutors.getVerifiedKey(addrs[15])).to.equal(getImageId(image2));

	});

	it('can deregister executor', async function () {
		const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let jobCapacity = 20;
		const message = solidityPacked(
			["uint256"],
			[jobCapacity],
		);
		const digest = keccak256(message);
		let sign = wallets[15]._signingKey().signDigest(digest);
		let signedDigest = joinSignature(sign);

		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, jobCapacity, signedDigest, 0);

		await expect(commonChainExecutors.connect(signers[1]).deregisterExecutor(pubkeys[15]))
			.to.emit(commonChainExecutors, "ExecutorDeregistered").withArgs(pubkeys[15]);

		expect(await commonChainExecutors.getVerifiedKey(addrs[15])).to.equal(ZeroHash);
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

	const sign = await sourceEnclaveKey._signTypedData(domain, types, {
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

function walletForIndex(idx: number): Wallet {
	let wallet = Wallet.fromMnemonic("test test test test test test test test test test test junk", "m/44'/60'/0'/0/" + idx.toString());

	return wallet;
}
