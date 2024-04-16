import { joinSignature } from "@ethersproject/bytes";
import { parseUnits } from '@ethersproject/units';
import { Wallet } from '@ethersproject/wallet';
import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, ZeroAddress, ZeroHash, keccak256, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationVerifier, CommonChainGateways, Pond } from "../../typechain-types";
import { AttestationAutherUpgradeable } from "../../typechain-types/contracts/AttestationAutherSample";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { getAttestationVerifier, getCommonChainGateways, getPond } from "../../utils/typechainConvertor";

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

describe("CommonChainGateways - Init", function () {
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
		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGateways = await CommonChainGateways.deploy(addrs[10], 600, token);

		expect(await commonChainGateways.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await commonChainGateways.ATTESTATION_MAX_AGE()).to.equal(600);

		await expect(
			commonChainGateways.__CommonChainGateways_init(addrs[0], []),
		).to.be.revertedWithCustomError(commonChainGateways, "InvalidInitialization");

		await expect(
			commonChainGateways.__CommonChainGateways_init(addrs[0], [image1, image2]),
		).to.be.revertedWithCustomError(commonChainGateways, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function () {
		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGateways = await upgrades.deployProxy(
			CommonChainGateways,
			[addrs[0], [image1]],
			{
				kind: "uups",
				initializer: "__CommonChainGateways_init",
				constructorArgs: [attestationVerifier.target, 600, token]
			},
		);

		expect(await commonChainGateways.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
		expect(await commonChainGateways.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await commonChainGateways.hasRole(await commonChainGateways.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		expect(await commonChainGateways.getRoleMemberCount(await commonChainGateways.DEFAULT_ADMIN_ROLE())).to.equal(1);
		{
			const { PCR0, PCR1, PCR2 } = await commonChainGateways.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
	});

	it("cannot initialize with zero address as admin", async function () {
		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		await expect(
			upgrades.deployProxy(
				CommonChainGateways,
				[ZeroAddress, [image1, image2, image3]],
				{
					kind: "uups",
					initializer: "__CommonChainGateways_init",
					constructorArgs: [attestationVerifier.target, 600, token]
				},
			)
		).to.be.revertedWith("ZERO_ADDRESS_ADMIN");
	});

	it("upgrades", async function () {
		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGateways = await upgrades.deployProxy(
			CommonChainGateways,
			[addrs[0], [image1, image2, image3]],
			{
				kind: "uups",
				initializer: "__CommonChainGateways_init",
				constructorArgs: [addrs[10], 600, token]
			},
		);
		await upgrades.upgradeProxy(
			commonChainGateways.target,
			CommonChainGateways,
			{
				kind: "uups",
				constructorArgs: [addrs[10], 600, token]
			}
		);

		expect(await commonChainGateways.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await commonChainGateways.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await commonChainGateways.hasRole(await commonChainGateways.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		expect(await commonChainGateways.getRoleMemberCount(await commonChainGateways.DEFAULT_ADMIN_ROLE())).to.equal(1);
		{
			const { PCR0, PCR1, PCR2 } = await commonChainGateways.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
		{
			const { PCR0, PCR1, PCR2 } = await commonChainGateways.getWhitelistedImage(getImageId(image2));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
		}
		{
			const { PCR0, PCR1, PCR2 } = await commonChainGateways.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}
	});

	it("does not upgrade without admin", async function () {
		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGateways = await upgrades.deployProxy(
			CommonChainGateways,
			[addrs[0], [image1, image2, image3]],
			{
				kind: "uups",
				initializer: "__CommonChainGateways_init",
				constructorArgs: [addrs[10], 600, token]
			},
		);

		await expect(
			upgrades.upgradeProxy(commonChainGateways.target, CommonChainGateways.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [addrs[10], 600, token],
			}),
		).to.be.revertedWith("only admin");
	});
});

describe("CommonChainGateways - Verify", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let token: string;
	let commonChainGateways: CommonChainGateways;

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

		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGatewaysContract = await upgrades.deployProxy(
			CommonChainGateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "__CommonChainGateways_init",
				constructorArgs: [attestationVerifier.target, 600, token]
			},
		);
		commonChainGateways = getCommonChainGateways(commonChainGatewaysContract.target as string, signers[0]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify enclave key", async function () {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await expect(commonChainGateways.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.emit(commonChainGateways, "EnclaveKeyVerified").withArgs(pubkeys[15], getImageId(image3));
		expect(await commonChainGateways.getVerifiedKey(addrs[15])).to.equal(getImageId(image3));
	});
});

describe("CommonChainGateways - Global chains", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let token: Pond;
	let attestationVerifier: AttestationVerifier;
	let commonChainGateways: CommonChainGateways;

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

		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGatewaysContract = await upgrades.deployProxy(
			CommonChainGateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "__CommonChainGateways_init",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		commonChainGateways = getCommonChainGateways(commonChainGatewaysContract.target as string, signers[0]);

	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can add global chain", async function () {
		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				rpcUrl: "https://eth.rpc"
			}
		]
		await commonChainGateways.addChainGlobal(chainIds, reqChains);

		let {contractAddress, rpcUrl} = await commonChainGateways.requestChains(1);
		expect({contractAddress, rpcUrl}).to.deep.eq(reqChains[0]);
	});

	it("can remove global chain", async function () {
		let chainIds = [1];
		await commonChainGateways.removeChainGlobal(chainIds);

		let {contractAddress, rpcUrl} = await commonChainGateways.requestChains(1);
		expect(contractAddress).to.be.eq(ZeroAddress);
		expect(rpcUrl).to.be.eq("");
	});

});

describe("CommonChainGateways - Register gateway", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let token: Pond;
	let attestationVerifier: AttestationVerifier;
	let commonChainGateways: CommonChainGateways;

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

		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGatewaysContract = await upgrades.deployProxy(
			CommonChainGateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "__CommonChainGateways_init",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		commonChainGateways = getCommonChainGateways(commonChainGatewaysContract.target as string, signers[0]);

		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				rpcUrl: "https://eth.rpc"
			}
		]
		await commonChainGateways.addChainGlobal(chainIds, reqChains);

	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can register gateway", async function () {
		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1];
		const message = solidityPacked(
			["uint256[]"],
			[chainIds],
		);
		const digest = keccak256(message);
		let sign = wallets[15]._signingKey().signDigest(digest);
		let signedDigest = joinSignature(sign);

		await expect(commonChainGateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, 0))
			.to.emit(commonChainGateways, "EnclaveKeyVerified").withArgs(pubkeys[15], getImageId(image2));
		expect(await commonChainGateways.getVerifiedKey(addrs[15])).to.equal(getImageId(image2));

	});

	it('can deregister gateway', async function () {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1];
		const message = solidityPacked(
			["uint256[]"],
			[chainIds],
		);
		const digest = keccak256(message);
		let sign = wallets[15]._signingKey().signDigest(digest);
		let signedDigest = joinSignature(sign);

		await commonChainGateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, 0);

		await expect(commonChainGateways.connect(signers[1]).deregisterGateway(pubkeys[15]))
			.to.emit(commonChainGateways, "GatewayDeregistered").withArgs(addrs[15]);
	});

});

describe("CommonChainGateways - Staking", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let token: Pond;
	let attestationVerifier: AttestationVerifier;
	let commonChainGateways: CommonChainGateways;

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

		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGatewaysContract = await upgrades.deployProxy(
			CommonChainGateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "__CommonChainGateways_init",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		commonChainGateways = getCommonChainGateways(commonChainGatewaysContract.target as string, signers[0]);

		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				rpcUrl: "https://eth.rpc"
			}
		]
		await commonChainGateways.addChainGlobal(chainIds, reqChains);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(commonChainGateways.target, 10000);

		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let stakeAmount = 10;
		let signedDigest = createGatewaySignature(chainIds, wallets[15]);
		await commonChainGateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, chainIds, signedDigest, stakeAmount);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can stake", async function () {
		let amount = 20;
		await expect(commonChainGateways.connect(signers[1]).addGatewayStake(pubkeys[15], amount))
			.to.emit(commonChainGateways, "GatewayStakeAdded");
		
		let executor = await commonChainGateways.gateways(addrs[15]);
		expect(executor.stakeAmount).to.be.eq(30);
	});

	it("can unstake", async function () {
		let amount = 5;
		await expect(commonChainGateways.connect(signers[1]).removeGatewayStake(pubkeys[15], amount))
			.to.emit(commonChainGateways, "GatewayStakeRemoved");
		
		let executor = await commonChainGateways.gateways(addrs[15]);
		expect(executor.stakeAmount).to.be.eq(5);
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

function createGatewaySignature(
	chainIds: number[],
	sourceEnclaveWallet: Wallet
): string {
	const message = solidityPacked(
		["uint256[]"],
		[chainIds],
	);
	const digest = keccak256(message);
	let sign = sourceEnclaveWallet._signingKey().signDigest(digest);
	let signedDigest = joinSignature(sign);
	return signedDigest;
}

function walletForIndex(idx: number): Wallet {
	let wallet = Wallet.fromMnemonic("test test test test test test test test test test test junk", "m/44'/60'/0'/0/" + idx.toString());

	return wallet;
}
