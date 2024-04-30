import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, ZeroAddress, ZeroHash, keccak256, solidityPacked, Wallet } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, Gateways, Pond } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { getAttestationVerifier, getGateways, getPond } from "../../utils/typechainConvertor";

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

describe("Gateways - Init", function () {
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
		const Gateways = await ethers.getContractFactory("Gateways");
		const gateways = await Gateways.deploy(addrs[10], 600, token, 600);

		expect(await gateways.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await gateways.ATTESTATION_MAX_AGE()).to.equal(600);

		await expect(
			gateways.initialize(addrs[0], []),
		).to.be.revertedWithCustomError(gateways, "InvalidInitialization");

		await expect(
			gateways.initialize(addrs[0], [image1, image2]),
		).to.be.revertedWithCustomError(gateways, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function () {
		const Gateways = await ethers.getContractFactory("Gateways");
		const gateways = await upgrades.deployProxy(
			Gateways,
			[addrs[0], [image1]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token, 600]
			},
		);

		expect(await gateways.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
		expect(await gateways.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await gateways.hasRole(await gateways.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		{
			const { PCR0, PCR1, PCR2 } = await gateways.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
	});

	it("cannot initialize with zero address as admin", async function () {
		const Gateways = await ethers.getContractFactory("Gateways");
		await expect(upgrades.deployProxy(
			Gateways,
			[ZeroAddress, [image1, image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token, 600]
			},
		)).to.be.revertedWithCustomError(Gateways, "ZeroAddressAdmin");
	});

	it("upgrades", async function () {
		const Gateways = await ethers.getContractFactory("Gateways");
		const gateways = await upgrades.deployProxy(
			Gateways,
			[addrs[0], [image1, image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [addrs[10], 600, token, 600]
			},
		);
		await upgrades.upgradeProxy(
			gateways.target,
			Gateways,
			{
				kind: "uups",
				constructorArgs: [addrs[10], 600, token, 600]
			}
		);

		expect(await gateways.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await gateways.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await gateways.hasRole(await gateways.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		{
			const { PCR0, PCR1, PCR2 } = await gateways.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
		{
			const { PCR0, PCR1, PCR2 } = await gateways.getWhitelistedImage(getImageId(image2));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
		}
		{
			const { PCR0, PCR1, PCR2 } = await gateways.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}
	});

	it("does not upgrade without admin", async function () {
		const Gateways = await ethers.getContractFactory("Gateways");
		const gateways = await upgrades.deployProxy(
			Gateways,
			[addrs[0], [image1, image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [addrs[10], 600, token, 600]
			},
		);

		await expect(
			upgrades.upgradeProxy(gateways.target, Gateways.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [addrs[10], 600, token, 600],
			}),
		).to.be.revertedWithCustomError(gateways, "AccessControlUnauthorizedAccount");
	});
});

describe("Gateways - Verify", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let token: string;
	let gateways: Gateways;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifierContract = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		);
		attestationVerifier = getAttestationVerifier(attestationVerifierContract.target as string, signers[0]);

		token = addrs[1];

		const Gateways = await ethers.getContractFactory("Gateways");
		const gatewaysContract = await upgrades.deployProxy(
			Gateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token, 600]
			},
		);
		gateways = getGateways(gatewaysContract.target as string, signers[0]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify enclave key", async function () {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await expect(gateways.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.emit(gateways, "EnclaveKeyVerified").withArgs(addrs[15], getImageId(image3), pubkeys[15]);
		expect(await gateways.getVerifiedKey(addrs[15])).to.equal(getImageId(image3));
	});
});

describe("Gateways - Global chains", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let token: Pond;
	let attestationVerifier: AttestationVerifier;
	let gateways: Gateways;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

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

		const Gateways = await ethers.getContractFactory("Gateways");
		const gatewaysContract = await upgrades.deployProxy(
			Gateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target, 600]
			},
		);
		gateways = getGateways(gatewaysContract.target as string, signers[0]);

	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can add global chain", async function () {
		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				httpRpcUrl: "https://eth.rpc",
				wsRpcUrl: "wss://eth.rpc"
			}
		]
		await gateways.addChainGlobal(chainIds, reqChains);

		let {contractAddress, httpRpcUrl, wsRpcUrl} = await gateways.requestChains(1);
		expect({contractAddress, httpRpcUrl, wsRpcUrl}).to.deep.eq(reqChains[0]);
	});

	it("cannot add global chain without admin", async function () {
		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				httpRpcUrl: "https://eth.rpc",
				wsRpcUrl: "wss://eth.rpc"
			}
		]
		await expect(gateways.connect(signers[1]).addChainGlobal(chainIds, reqChains))
			.to.be.revertedWithCustomError(gateways, "AccessControlUnauthorizedAccount");
	});

	it("cannot execute add global chain with empty chain array", async function () {
		let chainIds: any = [];
		let reqChains: any = [];
		await expect(gateways.addChainGlobal(chainIds, reqChains))
			.to.be.revertedWithCustomError(gateways, "InvalidLength");

		chainIds = [1];
		await expect(gateways.addChainGlobal(chainIds, reqChains))
			.to.be.revertedWithCustomError(gateways, "InvalidLength");
	});

	it("can remove global chain", async function () {
		let chainIds = [1];
		await gateways.removeChainGlobal(chainIds);

		let {contractAddress, httpRpcUrl} = await gateways.requestChains(1);
		expect(contractAddress).to.be.eq(ZeroAddress);
		expect(httpRpcUrl).to.be.eq("");
	});

	it("cannot remove global chain without admin", async function () {
		let chainIds = [1];
		await expect(gateways.connect(signers[1]).removeChainGlobal(chainIds))
			.to.be.revertedWithCustomError(gateways, "AccessControlUnauthorizedAccount");
	});

	it("cannot execute remove global chain with empty chain array", async function () {
		let chainIds: any = [];
		await expect(gateways.removeChainGlobal(chainIds))
			.to.be.revertedWithCustomError(gateways, "InvalidLength");
	});

});

describe("Gateways - Global chains", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let token: Pond;
	let attestationVerifier: AttestationVerifier;
	let gateways: Gateways;
	let reqChains: {
		contractAddress: string,
		httpRpcUrl: string,
		wsRpcUrl: string
	}[];

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

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

		const Gateways = await ethers.getContractFactory("Gateways");
		const gatewaysContract = await upgrades.deployProxy(
			Gateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target, 600]
			},
		);
		gateways = getGateways(gatewaysContract.target as string, signers[0]);

		let chainIds = [1, 56];
		reqChains = [
			{
				contractAddress: addrs[1],
				httpRpcUrl: "https://eth.rpc",
				wsRpcUrl: "wss://eth.rpc"
			},
			{
				contractAddress: addrs[2],
				httpRpcUrl: "https://bsc.rpc",
				wsRpcUrl: "wss://bsc.rpc"
			}
		]
		await gateways.addChainGlobal(chainIds, reqChains);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(gateways.target, 10000);

		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let stakeAmount = 10;
		let signedDigest = await createGatewaySignature([1], wallets[15]);
		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, stakeAmount);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can add chains", async function () {
		let chainIds = [56];
		await expect(gateways.connect(signers[1]).addChains(pubkeys[15], chainIds))
			.to.emit(gateways, "ChainAdded").withArgs(addrs[15], 56);
		
		let gatewayChainIds = await gateways.getGatewayChainIds(addrs[15]);
		expect(gatewayChainIds.length).equals(2);
		expect(gatewayChainIds).contains(BigInt(56));
	});

	it("cannot add chains without gateway operator", async function () {
		let chainIds = [56];
		await expect(gateways.addChains(pubkeys[15], chainIds))
			.to.be.revertedWithCustomError(gateways, "InvalidGatewayOperator");
	});

	it("cannot execute add chains with empty chain array", async function () {
		let chainIds: any = [];
		await expect(gateways.connect(signers[1]).addChains(pubkeys[15], chainIds))
			.to.be.revertedWithCustomError(gateways, "EmptyRequestedChains");
	});

	it("cannot add chains that are not supported globally", async function () {
		let chainIds = [137];
		await expect(gateways.connect(signers[1]).addChains(pubkeys[15], chainIds))
			.to.be.revertedWithCustomError(gateways, "UnsupportedChain");
	});

	it("cannot add chains that already exists", async function () {
		let chainIds = [1];
		await expect(gateways.connect(signers[1]).addChains(pubkeys[15], chainIds))
			.to.be.revertedWithCustomError(gateways, "ChainAlreadyExists").withArgs(1);
	});


	it("can remove chain", async function () {
		let chainIds = [1];
		await expect(gateways.connect(signers[1]).removeChains(pubkeys[15], chainIds))
			.to.emit(gateways, "ChainRemoved").withArgs(addrs[15], 1);
		
		let gatewayChainIds = await gateways.getGatewayChainIds(addrs[15]);
		expect(gatewayChainIds.length).equals(0);
	});

	it("cannot remove chain without gateway operator", async function () {
		let chainIds = [1];
		await expect(gateways.removeChains(pubkeys[15], chainIds))
			.to.be.revertedWithCustomError(gateways, "InvalidGatewayOperator");
	});

	it("cannot execute remove chains with empty chain array", async function () {
		let chainIds: any = [];
		await expect(gateways.connect(signers[1]).removeChains(pubkeys[15], chainIds))
			.to.be.revertedWithCustomError(gateways, "EmptyRequestedChains");
	});

	it("cannot remove chain that hasn't been added", async function () {
		let chainIds = [56];
		await expect(gateways.connect(signers[1]).removeChains(pubkeys[15], chainIds))
			.to.be.revertedWithCustomError(gateways, "ChainNotFound").withArgs(56);
	});

});

describe("Gateways - Register gateway", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let token: Pond;
	let attestationVerifier: AttestationVerifier;
	let gateways: Gateways;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

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

		const Gateways = await ethers.getContractFactory("Gateways");
		const gatewaysContract = await upgrades.deployProxy(
			Gateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target, 600]
			},
		);
		gateways = getGateways(gatewaysContract.target as string, signers[0]);

		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				httpRpcUrl: "https://eth.rpc",
				wsRpcUrl: "wss://eth.rpc"
			}
		]
		await gateways.addChainGlobal(chainIds, reqChains);

	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can register gateway", async function () {
		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1];
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);

		await expect(gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, 0))
			.to.emit(gateways, "EnclaveKeyVerified").withArgs(addrs[15], getImageId(image2), pubkeys[15]);
		expect(await gateways.getVerifiedKey(addrs[15])).to.equal(getImageId(image2));

	});

	it("cannot register gateway with same enclave key twice", async function () {
		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1];
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);

		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, 0);

		await expect(gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, 0))
			.to.be.revertedWithCustomError(gateways, "GatewayAlreadyExists");
	});

	it("cannot register gateway with chain id not added globally", async function () {
		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1, 2];
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);

		await expect(gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, chainIds, signedDigest, 0))
			.to.be.revertedWithCustomError(gateways, "UnsupportedChain");
	});

	it('cannot complete deregister gateway without initiating deregistration', async function () {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1];
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);

		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, 0);

		await expect(gateways.connect(signers[1]).completeDegistration(pubkeys[15]))
			.to.be.revertedWithCustomError(gateways, "GatewayDeregisterNotInitiated");
	});

	it('can initiate deregister gateway', async function () {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1];
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);

		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, 0);

		await expect(gateways.connect(signers[1]).deregisterGateway(pubkeys[15]))
			.to.emit(gateways, "GatewayDeregistered").withArgs(addrs[15]);

		expect((await gateways.gateways(addrs[15])).status).to.be.eq(false);
	});

	it('cannot initiate deregister without gateway operator', async function () {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1];
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);

		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, 0);

		await expect(gateways.connect(signers[0]).deregisterGateway(pubkeys[15]))
			.to.be.revertedWithCustomError(gateways, "InvalidGatewayOperator");
	});

	it('cannot initiate deregister twice', async function () {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1];
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);

		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, 0);
		await gateways.connect(signers[1]).deregisterGateway(pubkeys[15]);

		await expect(gateways.connect(signers[1]).deregisterGateway(pubkeys[15]))
			.to.be.revertedWithCustomError(gateways, "GatewayDeregisterAlreadyInitiated");
	});

	it('cannot complete deregister gateway before timeout', async function () {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1];
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);

		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, 0);

		await gateways.connect(signers[1]).deregisterGateway(pubkeys[15]);

		await expect(gateways.connect(signers[1]).completeDegistration(pubkeys[15]))
			.to.be.revertedWithCustomError(gateways, "DeregisterTimePending");
	});

	it('can complete deregister gateway', async function () {
		await token.transfer(addrs[1], 100);
		await token.connect(signers[1]).approve(gateways.target, 100);

		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1];
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);

		let stakeAmount = 10;
		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, stakeAmount);
		expect(await token.balanceOf(gateways.target)).to.be.eq(10);
		expect(await token.balanceOf(addrs[1])).to.be.eq(90);

		await gateways.connect(signers[1]).deregisterGateway(pubkeys[15]);

		await time.increase(700);
		await expect(gateways.connect(signers[1]).completeDegistration(pubkeys[15]))
			.to.emit(gateways, "GatewayDeregisterCompleted").withArgs(addrs[15]);

		let gateway = await gateways.gateways(addrs[15]);
		expect(gateway.operator).to.be.eq(ZeroAddress);
		expect(await token.balanceOf(gateways.target)).to.be.eq(0);
		expect(await token.balanceOf(addrs[1])).to.be.eq(100);
	});

	it('cannot complete deregister without gateway operator', async function () {
		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let chainIds = [1];
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);

		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, [1], signedDigest, 0);

		await gateways.connect(signers[1]).deregisterGateway(pubkeys[15]);

		await time.increase(700);
		await expect(gateways.connect(signers[0]).completeDegistration(pubkeys[15]))
			.to.be.revertedWithCustomError(gateways, "InvalidGatewayOperator");
	});

});

describe("Gateways - Staking", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let token: Pond;
	let attestationVerifier: AttestationVerifier;
	let gateways: Gateways;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

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

		const Gateways = await ethers.getContractFactory("Gateways");
		const gatewaysContract = await upgrades.deployProxy(
			Gateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target, 600]
			},
		);
		gateways = getGateways(gatewaysContract.target as string, signers[0]);

		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				httpRpcUrl: "https://eth.rpc",
				wsRpcUrl: "wss://eth.rpc"
			}
		]
		await gateways.addChainGlobal(chainIds, reqChains);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(gateways.target, 10000);

		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let stakeAmount = 10;
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);
		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, chainIds, signedDigest, stakeAmount);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("cannot stake without gateway operator", async function () {
		let amount = 20;
		await expect(gateways.connect(signers[0]).addGatewayStake(pubkeys[15], amount))
			.to.be.revertedWithCustomError(gateways, "InvalidGatewayOperator");
	});

	it("can stake", async function () {
		let amount = 20;
		await expect(gateways.connect(signers[1]).addGatewayStake(pubkeys[15], amount))
			.to.emit(gateways, "GatewayStakeAdded");
		
		let executor = await gateways.gateways(addrs[15]);
		expect(executor.stakeAmount).to.be.eq(30);
	});

	it("can initiate unstake", async function () {
		await expect(gateways.connect(signers[1]).removeGatewayStake(pubkeys[15]))
			.to.emit(gateways, "GatewayStakeRemoveInitiated");
		
		let gateway = await gateways.gateways(addrs[15]);
		expect(gateway.status).to.be.eq(false);
		expect(gateway.unstakeStartTime).to.be.greaterThan(0);
	});

	it("cannot initiate unstake if deregistration is already initiated", async function () {
		await gateways.connect(signers[1]).deregisterGateway(pubkeys[15]);

		await expect(gateways.connect(signers[1]).removeGatewayStake(pubkeys[15]))
			.to.be.revertedWithCustomError(gateways, "GatewayDeregisterAlreadyInitiated");
	});

	it("cannot initiate unstake twice", async function () {
		await gateways.connect(signers[1]).removeGatewayStake(pubkeys[15]);

		await expect(gateways.connect(signers[1]).removeGatewayStake(pubkeys[15]))
			.to.be.revertedWithCustomError(gateways, "GatewayStakeRemoveAlreadyInitiated");
	});

	it("cannot initiate unstake without gateway operator", async function () {
		await expect(gateways.connect(signers[0]).removeGatewayStake(pubkeys[15]))
			.to.be.revertedWithCustomError(gateways, "InvalidGatewayOperator");
		
	});

	it("cannot complete unstake without initiating unstake", async function () {
		await expect(gateways.connect(signers[1]).completeRemoveGatewayStake(pubkeys[15], 10))
			.to.be.revertedWithCustomError(gateways, "InvalidStatus");
	});

	it("cannot complete unstake before timeout", async function () {
		await gateways.connect(signers[1]).removeGatewayStake(pubkeys[15]);

		await expect(gateways.connect(signers[1]).completeRemoveGatewayStake(pubkeys[15], 10))
			.to.be.revertedWithCustomError(gateways, "UnstakeTimePending");
	});

	it("cannot complete unstake with zero amount", async function () {
		await gateways.connect(signers[1]).removeGatewayStake(pubkeys[15]);

		await time.increase(700);
		await expect(gateways.connect(signers[1]).completeRemoveGatewayStake(pubkeys[15], 0))
			.to.be.revertedWithCustomError(gateways, "InvalidAmount");
	});

	it("cannot complete unstake without gateway operator", async function () {
		await gateways.connect(signers[1]).removeGatewayStake(pubkeys[15]);

		await time.increase(700);
		await expect(gateways.connect(signers[0]).completeRemoveGatewayStake(pubkeys[15], 5))
			.to.be.revertedWithCustomError(gateways, "InvalidGatewayOperator");
		
	});

	it("can complete unstake", async function () {
		await gateways.connect(signers[1]).removeGatewayStake(pubkeys[15]);

		await time.increase(700);
		await expect(gateways.connect(signers[1]).completeRemoveGatewayStake(pubkeys[15], 5))
			.to.emit(gateways, "GatewayStakeRemoved");
		
		let gateway = await gateways.gateways(addrs[15]);
		expect(gateway.stakeAmount).to.be.eq(5);
		expect(gateway.unstakeStartTime).to.be.eq(0);
		expect(gateway.status).to.be.eq(true);
		expect(await token.balanceOf(gateways.target)).to.be.eq(5);
		expect(await token.balanceOf(addrs[1])).to.be.eq(99995);
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

async function createGatewaySignature(
	chainIds: number[],
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const message = ethers.solidityPackedKeccak256(
        ["uint256[]"],
        [chainIds]
    );
	const signature = await sourceEnclaveWallet.signingKey.sign(message);
	let signedDigest = ethers.Signature.from(signature).serialized;
	return signedDigest;
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
}
