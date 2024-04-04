import { parseUnits } from '@ethersproject/units';
import { Wallet } from '@ethersproject/wallet';
import { expect } from "chai";
import { BytesLike, Signer, ZeroAddress, keccak256, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationVerifier } from "../../typechain-types";
import { AttestationAutherUpgradeable } from "../../typechain-types/contracts/AttestationAutherSample";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";


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

describe("CommonChainJobs - Init", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: string;
    let commonChainGateway: string;
    let commonChainExecutors: string;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		token = addrs[1];
        commonChainGateway = addrs[1];
        commonChainExecutors = addrs[1];
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("deploys with initialization disabled", async function () {

		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobs = await CommonChainJobs.deploy();

		await expect(
			commonChainJobs.__CommonChainJobs_init(addrs[0], token, commonChainGateway, commonChainExecutors, 100, 3),
		).to.be.revertedWithCustomError(commonChainJobs, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function () {
		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobs = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], token, commonChainGateway, commonChainExecutors, 100, 3],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init"
			},
		);

		expect(await commonChainJobs.hasRole(await commonChainJobs.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		expect(await commonChainJobs.getRoleMemberCount(await commonChainJobs.DEFAULT_ADMIN_ROLE())).to.equal(1);
	});

	it("cannot initialize with zero address as admin", async function () {
		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		await expect(
			upgrades.deployProxy(
				CommonChainJobs,
				[ZeroAddress, token, commonChainGateway, commonChainExecutors, 100, 3],
				{
					kind: "uups",
					initializer: "__CommonChainJobs_init"
				},
			)
		).to.be.revertedWith("ZERO_ADDRESS_ADMIN");
	});

	it("upgrades", async function () {
		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobs = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], token, commonChainGateway, commonChainExecutors, 100, 3],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init"
			},
		);
		await upgrades.upgradeProxy(
			commonChainJobs.target,
			CommonChainJobs,
			{
				kind: "uups"
			}
		);

		expect(await commonChainJobs.hasRole(await commonChainJobs.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		expect(await commonChainJobs.getRoleMemberCount(await commonChainJobs.DEFAULT_ADMIN_ROLE())).to.equal(1);
	});

	it("does not upgrade without admin", async function () {
		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobs = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], token, commonChainGateway, commonChainExecutors, 100, 3],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init"
			},
		);

		await expect(
			upgrades.upgradeProxy(commonChainJobs.target, CommonChainJobs.connect(signers[1]), {
				kind: "uups"
			}),
		).to.be.revertedWith("only admin");
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
