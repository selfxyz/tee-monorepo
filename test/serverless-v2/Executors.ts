import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, ZeroHash, keccak256, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, Executors, Pond } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { getAttestationVerifier, getExecutors, getGateways, getJobs, getPond } from "../../utils/typechainConvertor";

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

describe("Executors - Init", function () {
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

		const Executors = await ethers.getContractFactory("Executors");
		const executors = await Executors.deploy(addrs[10], 600, token);

		expect(await executors.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await executors.ATTESTATION_MAX_AGE()).to.equal(600);

		await expect(
			executors.initialize(addrs[0], []),
		).to.be.revertedWithCustomError(executors, "InvalidInitialization");

		await expect(
			executors.initialize(addrs[0], [image1, image2]),
		).to.be.revertedWithCustomError(executors, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function () {
		const Executors = await ethers.getContractFactory("Executors");
		const executors = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image1]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token]
			},
		);

		expect(await executors.ATTESTATION_VERIFIER()).to.equal(attestationVerifier.target);
		expect(await executors.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await executors.hasRole(await executors.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		{
			const { PCR0, PCR1, PCR2 } = await executors.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
	});

	it("cannot initialize with zero address as admin", async function () {
		const Executors = await ethers.getContractFactory("Executors");
		await expect(
			upgrades.deployProxy(
				Executors,
				[ZeroAddress, [image1, image2, image3]],
				{
					kind: "uups",
					initializer: "initialize",
					constructorArgs: [attestationVerifier.target, 600, token]
				},
			)
		).to.be.revertedWithCustomError(Executors, "ZeroAddressAdmin");
	});

	it("upgrades", async function () {
		const Executors = await ethers.getContractFactory("Executors");
		const executors = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image1, image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [addrs[10], 600, token]
			},
		);
		await upgrades.upgradeProxy(
			executors.target,
			Executors,
			{
				kind: "uups",
				constructorArgs: [addrs[10], 600, token]
			}
		);

		expect(await executors.ATTESTATION_VERIFIER()).to.equal(addrs[10]);
		expect(await executors.ATTESTATION_MAX_AGE()).to.equal(600);

		expect(await executors.hasRole(await executors.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		{
			const { PCR0, PCR1, PCR2 } = await executors.getWhitelistedImage(getImageId(image1));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image1);
		}
		{
			const { PCR0, PCR1, PCR2 } = await executors.getWhitelistedImage(getImageId(image2));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image2);
		}
		{
			const { PCR0, PCR1, PCR2 } = await executors.getWhitelistedImage(getImageId(image3));
			expect({ PCR0, PCR1, PCR2 }).to.deep.equal(image3);
		}
	});

	it("does not upgrade without admin", async function () {
		const Executors = await ethers.getContractFactory("Executors");
		const executors = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image1, image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [addrs[10], 600, token]
			},
		);

		await expect(
			upgrades.upgradeProxy(executors.target, Executors.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [addrs[10], 600, token],
			}),
		).to.be.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
	});
});

describe("Executors - Verify", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let token: string;
	let executors: Executors;

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

		const Executors = await ethers.getContractFactory("Executors");
		const executorsContract = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token]
			},
		);
		executors = getExecutors(executorsContract.target as string, signers[0]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can verify enclave key", async function () {
		const timestamp = await time.latest() * 1000;
        let [signature, attestation] = await createAttestation(pubkeys[15], image3, wallets[14], timestamp - 540000);

		await expect(executors.connect(signers[1]).verifyEnclaveKey(signature, attestation))
			.to.emit(executors, "EnclaveKeyVerified").withArgs(addrs[15], getImageId(image3), pubkeys[15]);
		expect(await executors.getVerifiedKey(addrs[15])).to.equal(getImageId(image3));
	});

	it("can whitelist enclave image with admin account", async function () {
		await expect(executors.connect(signers[0]).whitelistEnclaveImage(image1.PCR0, image1.PCR1, image1.PCR2))
			.to.emit(executors, "EnclaveImageWhitelisted").withArgs(getImageId(image1), image1.PCR0, image1.PCR1, image1.PCR2);
		
		const { PCR0, PCR1, PCR2 } = await executors.getWhitelistedImage(getImageId(image1));
		expect({PCR0, PCR1, PCR2}).to.deep.equal(image1);
	});

	it("cannot whitelist enclave image without admin account", async function () {
		await expect(executors.connect(signers[1]).whitelistEnclaveImage(image1.PCR0, image1.PCR1, image1.PCR2))
			.to.be.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
	});

	it("can revoke enclave image with admin account", async function () {
		await expect(executors.connect(signers[0]).revokeEnclaveImage(getImageId(image2)))
			.to.emit(executors, "EnclaveImageRevoked").withArgs(getImageId(image2));
		
		const { PCR0 } = await executors.getWhitelistedImage(getImageId(image2));
		expect(PCR0).to.equal("0x");
	});

	it("cannot revoke enclave image without admin account", async function () {
		await expect(executors.connect(signers[1]).revokeEnclaveImage(getImageId(image2)))
			.to.be.revertedWithCustomError(executors, "AccessControlUnauthorizedAccount");
	});
});

describe("Executors - Register executor", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let token: Pond;
	let attestationVerifier: AttestationVerifier;
	let executors: Executors;

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

		const Executors = await ethers.getContractFactory("Executors");
		const executorsContract = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		executors = getExecutors(executorsContract.target as string, signers[0]);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can register executor", async function () {
		const timestamp = await time.latest() * 1000;
        let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let jobCapacity = 20;
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[15]);

		await expect(executors.connect(signers[1]).registerExecutor(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, jobCapacity, signedDigest, 0))
			.to.emit(executors, "EnclaveKeyVerified").withArgs(addrs[15], getImageId(image2), pubkeys[15]);
		expect(await executors.getVerifiedKey(addrs[15])).to.equal(getImageId(image2));
	});

	it("cannot register executor with same enclave key twice", async function () {
		const timestamp = await time.latest() * 1000;
        let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let jobCapacity = 20;
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[15]);
		executors.connect(signers[1]).registerExecutor(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, jobCapacity, signedDigest, 0);

		await expect(executors.connect(signers[1]).registerExecutor(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, jobCapacity, signedDigest, 0))
			.to.revertedWithCustomError(executors, "ExecutorAlreadyExists");
	});

	it('can deregister executor without active jobs', async function () {
		const timestamp = await time.latest() * 1000;
        let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let jobCapacity = 20;
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[15]);

		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, jobCapacity, signedDigest, 0);

		await expect(executors.connect(signers[1]).deregisterExecutor(pubkeys[15]))
			.to.emit(executors, "ExecutorDeregistered").withArgs(addrs[15]);

		expect(await executors.getVerifiedKey(addrs[15])).to.equal(ZeroHash);
		expect((await executors.executors(addrs[15])).operator).to.be.eq(ZeroAddress);
	});

	it('can deregister executor with active jobs', async function () {
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
		let gateways = getGateways(gatewaysContract.target as string, signers[0]);

		const Jobs = await ethers.getContractFactory("Jobs");
		const jobsContract = await upgrades.deployProxy(
			Jobs,
			[addrs[0], gateways.target, executors.target],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					token.target,
					100,
					100,
					1
				]
			},
		);
		let jobs = getJobs(jobsContract.target as string, signers[0]);

		await executors.setJobsContract(jobs.target);

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
		await token.connect(signers[1]).approve(executors.target, 10000);

		let timestamp = await time.latest() * 1000,
			stakeAmount = 10;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);
		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, chainIds, signedDigest, stakeAmount);
		
		timestamp = await time.latest() * 1000;
        [signature] = await createAttestation(pubkeys[16], image2, wallets[14], timestamp - 540000);

		let jobCapacity = 20;
		signedDigest = await createExecutorSignature(jobCapacity, wallets[16]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[16], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
		await jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);

		await expect(executors.connect(signers[1]).deregisterExecutor(pubkeys[16]))
			.to.emit(executors, "ExecutorDeregistered").withArgs(addrs[16]);

		expect(await executors.getVerifiedKey(addrs[16])).to.equal(getImageId(image2));
		expect((await executors.executors(addrs[16])).operator).to.be.eq(addrs[1]);
	});

	it('cannot deregister executor without the operator account', async function () {
		const timestamp = await time.latest() * 1000;
        let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		let jobCapacity = 20;
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[15]);

		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, jobCapacity, signedDigest, 0);

		await expect(executors.deregisterExecutor(pubkeys[15]))
			.to.revertedWithCustomError(executors, "InvalidExecutorOperator");
	});

	it('cannot deregister executor twice', async function () {
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
		let gateways = getGateways(gatewaysContract.target as string, signers[0]);

		const Jobs = await ethers.getContractFactory("Jobs");
		const jobsContract = await upgrades.deployProxy(
			Jobs,
			[addrs[0], gateways.target, executors.target],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					token.target,
					100,
					100,
					1
				]
			},
		);
		let jobs = getJobs(jobsContract.target as string, signers[0]);

		await executors.setJobsContract(jobs.target);

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
		await token.connect(signers[1]).approve(executors.target, 10000);

		let timestamp = await time.latest() * 1000,
			stakeAmount = 10;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);
		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, chainIds, signedDigest, stakeAmount);
		
		timestamp = await time.latest() * 1000;
        [signature] = await createAttestation(pubkeys[16], image2, wallets[14], timestamp - 540000);

		let jobCapacity = 20;
		signedDigest = await createExecutorSignature(jobCapacity, wallets[16]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[16], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
		await jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);

		await executors.connect(signers[1]).deregisterExecutor(pubkeys[16]);

		await expect(executors.connect(signers[1]).deregisterExecutor(pubkeys[16]))
			.to.revertedWithCustomError(executors, "AlreadyDeregistered");
	});

});

describe("Executors - Staking", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let token: Pond;
	let attestationVerifier: AttestationVerifier;
	let executors: Executors;

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

		const Executors = await ethers.getContractFactory("Executors");
		const executorsContract = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		executors = getExecutors(executorsContract.target as string, signers[0]);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(executors.target, 10000);

		const timestamp = await time.latest() * 1000;
        let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
		let jobCapacity = 20, 
			stakeAmount = 10;
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[15]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can stake", async function () {
		let amount = 20;
		await expect(executors.connect(signers[1]).addExecutorStake(pubkeys[15], amount))
			.to.emit(executors, "ExecutorStakeAdded");
		
		let executor = await executors.executors(addrs[15]);
		expect(executor.stakeAmount).to.be.eq(30);
		expect(await token.balanceOf(executors.target)).to.be.eq(30);
		expect(await token.balanceOf(addrs[1])).to.be.eq(99970);
	});

	it("cannot stake zero amount", async function () {
		let amount = 0;
		await expect(executors.connect(signers[1]).addExecutorStake(pubkeys[15], amount))
			.to.be.revertedWithCustomError(executors, "InvalidAmount");
	});

	it("cannot stake without executor operator", async function () {
		let amount = 20;
		await expect(executors.addExecutorStake(pubkeys[15], amount))
			.to.be.revertedWithCustomError(executors, "InvalidExecutorOperator");
	});

	it("can unstake if no active jobs", async function () {
		let amount = 10;
		await expect(executors.connect(signers[1]).removeExecutorStake(pubkeys[15], amount))
			.to.emit(executors, "ExecutorStakeRemoved");
		
		let executor = await executors.executors(addrs[15]);
		expect(executor.stakeAmount).to.be.eq(0);
		expect(await token.balanceOf(executors.target)).to.be.eq(0);
		expect(await token.balanceOf(addrs[1])).to.be.eq(100000);
	});

	it("cannot unstake zero amount", async function () {
		let amount = 0;
		await expect(executors.connect(signers[1]).removeExecutorStake(pubkeys[15], amount))
			.to.be.revertedWithCustomError(executors, "InvalidAmount");
	});

	it("cannot unstake without executor operator", async function () {
		let amount = 10;
		await expect(executors.removeExecutorStake(pubkeys[15], amount))
			.to.be.revertedWithCustomError(executors, "InvalidExecutorOperator");
	});

	it('can unstake with active jobs', async function () {
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
		let gateways = getGateways(gatewaysContract.target as string, signers[0]);

		const Jobs = await ethers.getContractFactory("Jobs");
		const jobsContract = await upgrades.deployProxy(
			Jobs,
			[addrs[0], gateways.target, executors.target],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					token.target,
					100,
					100,
					1
				]
			},
		);
		let jobs = getJobs(jobsContract.target as string, signers[0]);

		await executors.setJobsContract(jobs.target);

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
		await token.connect(signers[1]).approve(executors.target, 10000);

		let timestamp = await time.latest() * 1000,
			stakeAmount = 10;
		let [signature] = await createAttestation(pubkeys[16], image2, wallets[14], timestamp - 540000);
		let signedDigest = await createGatewaySignature(chainIds, wallets[16]);
		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[16], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, chainIds, signedDigest, stakeAmount);
		
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[16]);
		await jobs.relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);

		let amount = 5;
		await expect(executors.connect(signers[1]).removeExecutorStake(pubkeys[15], amount))
			.to.emit(executors, "ExecutorStakeRemoveInitiated").withArgs(addrs[15], amount);

		let executor = await executors.executors(addrs[15]);
		expect(executor.unstakeAmount).to.be.eq(amount);
		expect(executor.unstakeStatus).to.be.true;
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

async function createExecutorSignature(
	jobCapacity: number,
	sourceEnclaveWallet: Wallet
): Promise<string> {

	const message = ethers.solidityPackedKeccak256(
        ["uint256"],
		[jobCapacity]
    );
	const signature = await sourceEnclaveWallet.signingKey.sign(message);
	let signedDigest = ethers.Signature.from(signature).serialized;
	return signedDigest;
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
	let signedDigest = ethers.Signature.from(signature).serialized
	return signedDigest;
}

async function createRelayJobSignature(
	jobId: number,
    codeHash: string,
	codeInputs: string,
    deadline: number,
	jobRequestTimestamp: number,
	sequenceId: number,
	jobOwner: string,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const message = ethers.solidityPackedKeccak256(
		["uint256", "bytes32", "bytes", "uint256", "uint256", "uint8", "address"],
		[jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner]
	);
	const signature = await sourceEnclaveWallet.signingKey.sign(message);
	let signedDigest = ethers.Signature.from(signature).serialized
	return signedDigest;
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
}
