import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, keccak256, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, Executors, Gateways, Jobs, Pond } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { getAttestationVerifier, getExecutors, getGateways, getJobs, getPond } from '../../utils/typechainConvertor';


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

const image4: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: ethers.hexlify(ethers.randomBytes(48)),
	PCR1: ethers.hexlify(ethers.randomBytes(48)),
	PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

const image5: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: ethers.hexlify(ethers.randomBytes(48)),
	PCR1: ethers.hexlify(ethers.randomBytes(48)),
	PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

const image6: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: ethers.hexlify(ethers.randomBytes(48)),
	PCR1: ethers.hexlify(ethers.randomBytes(48)),
	PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

const image7: AttestationAutherUpgradeable.EnclaveImageStruct = {
	PCR0: ethers.hexlify(ethers.randomBytes(48)),
	PCR1: ethers.hexlify(ethers.randomBytes(48)),
	PCR2: ethers.hexlify(ethers.randomBytes(48)),
};

describe.only("Jobs - Init", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: string;
	let commonChainGateway: string;
	let executors: string;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		token = addrs[1];
		commonChainGateway = addrs[1];
		executors = addrs[1];
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("deploys with initialization disabled", async function () {

		const Jobs = await ethers.getContractFactory("Jobs");
		const jobs = await Jobs.deploy(token, 100, 100, 3);

		await expect(
			jobs.initialize(addrs[0], commonChainGateway, executors),
		).to.be.revertedWithCustomError(jobs, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function () {
		const Jobs = await ethers.getContractFactory("Jobs");
		const jobs = await upgrades.deployProxy(
			Jobs,
			[addrs[0], commonChainGateway, executors],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			},
		);

		expect(await jobs.hasRole(await jobs.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
	});

	it("cannot initialize with zero address as admin", async function () {
		const Jobs = await ethers.getContractFactory("Jobs");
		await expect(
			upgrades.deployProxy(
				Jobs,
				[ZeroAddress, commonChainGateway, executors],
				{
					kind: "uups",
					initializer: "initialize",
					constructorArgs: [
						token,
						100,
						100,
						3
					]
				},
			)
		).to.be.revertedWithCustomError(Jobs, "ZeroAddressAdmin");
	});

	it("upgrades", async function () {
		const Jobs = await ethers.getContractFactory("Jobs");
		const jobs = await upgrades.deployProxy(
			Jobs,
			[addrs[0], commonChainGateway, executors],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			},
		);
		await upgrades.upgradeProxy(
			jobs.target,
			Jobs,
			{
				kind: "uups",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			}
		);

		expect(await jobs.hasRole(await jobs.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
	});

	it("does not upgrade without admin", async function () {
		const Jobs = await ethers.getContractFactory("Jobs");
		const jobs = await upgrades.deployProxy(
			Jobs,
			[addrs[0], commonChainGateway, executors],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			},
		);

		await expect(
			upgrades.upgradeProxy(jobs.target, Jobs.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			}),
		).to.be.revertedWithCustomError(Jobs, "AccessControlUnauthorizedAccount");
	});

	it("can set gateway contract only with admin role", async function () {
		const Jobs = await ethers.getContractFactory("Jobs");
		const jobsContract = await upgrades.deployProxy(
			Jobs,
			[addrs[0], commonChainGateway, executors],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			},
		);
		const jobs = getJobs(jobsContract.target as string, signers[0]);
		
		await expect(jobs.connect(signers[1]).setGatewaysContract(addrs[1]))
			.to.be.revertedWithCustomError(jobs, "AccessControlUnauthorizedAccount");
		await expect(jobs.setGatewaysContract(addrs[1])).to.not.be.rejected;
	});

	it("can set executor contract only with admin role", async function () {
		const Jobs = await ethers.getContractFactory("Jobs");
		const jobsContract = await upgrades.deployProxy(
			Jobs,
			[addrs[0], commonChainGateway, executors],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			},
		);
		const jobs = getJobs(jobsContract.target as string, signers[0]);
		
		await expect(jobs.connect(signers[1]).setExecutorsContract(addrs[1]))
			.to.be.revertedWithCustomError(jobs, "AccessControlUnauthorizedAccount");
		await expect(jobs.setExecutorsContract(addrs[1])).to.not.be.rejected;
	});
});

describe.only("Jobs - Relay", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let gateways: Gateways;
	let executors: Executors;
	let jobs: Jobs;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const Pond = await ethers.getContractFactory("Pond");
		const pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});
		token = getPond(pondContract.target as string, signers[0]);

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifierContract = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		);
		attestationVerifier = getAttestationVerifier(attestationVerifierContract.target as string, signers[0]);

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

		const Executors = await ethers.getContractFactory("Executors");
		const executorsContract = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image4, image5, image6, image7]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		executors = getExecutors(executorsContract.target as string, signers[0]);

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
					3
				]
			},
		);
		jobs = getJobs(jobsContract.target as string, signers[0]);

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

		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
		await gateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);
		[signature, attestation] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
		await gateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(executors.target, 10000);

		let jobCapacity = 3, stakeAmount = 10;
		[signature] = await createAttestation(pubkeys[17], image4, wallets[14], timestamp - 540000);
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[17]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[18]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[19]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[20]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can relay job", async function () {
		// let reqChainId = (await ethers.provider.getNetwork()).chainId;
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		let tx = await jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);
		await expect(tx).to.emit(jobs, "JobRelayed");

		let job = await jobs.jobs(jobId);

		expect(job.jobId).to.eq(jobId);
		expect(job.jobOwner).to.eq(jobOwner);
		
		let selectedExecutors = await jobs.getSelectedExecutors(jobId);
		for (let index = 0; index < selectedExecutors.length; index++) {
			const executor = selectedExecutors[index];
			expect([addrs[17], addrs[18], addrs[19], addrs[20]]).to.contain(executor);
		}
	});

	it("cannot relay job after relay time is over", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await time.increase(1000);
		await expect(jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(jobs, "RelayTimeOver");
	});

	it("cannot relay job with wrong sequence id", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 2,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(jobs, "InvalidSequenceId");
	});

	it("cannot relay a job twice with same job id", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
		await jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);

		await expect(jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(jobs, "JobAlreadyRelayed");
	});

	it("cannot relay job with unsupported chain id", async function () {
		let jobId: any = (BigInt(2) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(jobs, "UnsupportedChain");
	});

	it("cannot relay job when a minimum no. of executor nodes are not available", async function () {
		await executors.connect(signers[1]).deregisterExecutor(pubkeys[19]);
		await executors.connect(signers[1]).deregisterExecutor(pubkeys[20]);

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(jobs, "JobResourceUnavailable").withArgs(jobId, addrs[15]);

		expect((await jobs.jobs(jobId)).isResourceUnavailable).to.be.true;
	});

	it("cannot relay job again if it's marked as ended due to unavailable executors", async function () {
		await executors.connect(signers[1]).deregisterExecutor(pubkeys[19]);
		await executors.connect(signers[1]).deregisterExecutor(pubkeys[20]);

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(jobs, "JobResourceUnavailable").withArgs(jobId, addrs[15]);

		// relay again
		await expect(jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(jobs, "JobMarkedEndedAsResourceUnavailable");
	});

	it("cannot relay job after all the executors are fully occupied", async function () {
		await executors.connect(signers[1]).deregisterExecutor(pubkeys[20]);

		for (let index = 1; index <= 3; index++) {
			let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(index),
				codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
				codeInputs = solidityPacked(["string"], ["codeInput"]),
				deadline = await time.latest() + 10000,
				jobRequestTimestamp = await time.latest(),
				sequenceId = 1,
				jobOwner = addrs[1];
			let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
			
			await expect(await jobs.relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
				.to.emit(jobs, "JobRelayed");
		}

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(4),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(jobs.relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(jobs, "JobResourceUnavailable").withArgs(jobId, addrs[0]);

		expect((await jobs.jobs(jobId)).isResourceUnavailable).to.be.true;

		// SUBMIT OUTPUT AND THEN RELAY JOB WILL WORK
		jobId = (BigInt(1) << BigInt(192)) + BigInt(1);
		let	output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);
		await jobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);

		signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[18]);
		await jobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);

		signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[19]);
		await jobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);

		// RELAY AGAIN WORKS
		jobId = (BigInt(1) << BigInt(192)) + BigInt(5);
		signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
			
		await expect(jobs.relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(jobs, "JobRelayed");
	});
});

describe.only("Jobs - Output", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let gateways: Gateways;
	let executors: Executors;
	let jobs: Jobs;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const Pond = await ethers.getContractFactory("Pond");
		const pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});
		token = getPond(pondContract.target as string, signers[0]);

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifierContract = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		);
		attestationVerifier = getAttestationVerifier(attestationVerifierContract.target as string, signers[0]);

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

		const Executors = await ethers.getContractFactory("Executors");
		const executorsContract = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image4, image5, image6, image7]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		executors = getExecutors(executorsContract.target as string, signers[0]);

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
					3
				]
			},
		);
		jobs = getJobs(jobsContract.target as string, signers[0]);

		await executors.setJobsContract(jobs.target);

		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				httpRpcUrl: "https://eth.rpc",
				wsRpcUrl: "wss://eth.rpc",
			}
		]
		await gateways.addChainGlobal(chainIds, reqChains);

		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
		await gateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);
		[signature, attestation] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
		await gateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(executors.target, 10000);

		let jobCapacity = 20, stakeAmount = 10;
		[signature] = await createAttestation(pubkeys[17], image4, wallets[14], timestamp - 540000);
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[17]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[18]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[19]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		// [signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		// signedDigest = await createExecutorSignature(jobCapacity, wallets[20]);
		// await executors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
		
		// RELAY JOB
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = 100000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await jobs.relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can submit output by selected executor node", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);
		let tx = await jobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.emit(jobs, "JobResponded");
	});

	it("cannot submit output after execution time is over", async function () {
		await time.increase(300);

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);

		await expect(jobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode))
			.to.be.revertedWithCustomError(jobs, "ExecutionTimeOver"); 
	});

	it("cannot submit output twice", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);
		let tx = await jobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.emit(jobs, "JobResponded"); 

		let tx2 = jobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx2).to.revertedWithCustomError(jobs, "ExecutorAlreadySubmittedOutput");
	});

	it("cannot submit output from unselected executor node", async function () {
		let jobCapacity = 20,
			stakeAmount = 10,
			timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[20]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
		
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[20]);
		let tx = jobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.revertedWithCustomError(jobs, "NotSelectedExecutor"); 
	});

	it("can submit output after executor initiates unstake", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;

		await executors.connect(signers[1]).removeExecutorStake(pubkeys[17], 5);
		
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);
		await expect(jobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode))
			.to.emit(executors, "ExecutorStakeRemoved").and.to.emit(jobs, "JobResponded");

		let executor = await executors.executors(addrs[17]);
		expect(executor.unstakeStatus).to.be.false;
		expect(executor.unstakeAmount).to.be.eq(0);
		expect(executor.stakeAmount).to.be.eq(5);
		expect(await token.balanceOf(executors.target)).to.be.eq(25);
		expect(await token.balanceOf(addrs[1])).to.be.eq(99975);
	});

	it("can submit output after executor initiates deregistration", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;

		await executors.connect(signers[1]).deregisterExecutor(pubkeys[17]);
		
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);
		await expect(jobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode))
			.to.emit(executors, "EnclaveKeyRevoked").and.to.emit(jobs, "JobResponded");

		expect((await executors.executors(addrs[17])).operator).to.be.eq(ZeroAddress);
		expect(await token.balanceOf(executors.target)).to.be.eq(20);
		expect(await token.balanceOf(addrs[1])).to.be.eq(99980);
	});

});

describe.only("Jobs - Slashing", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let gateways: Gateways;
	let executors: Executors;
	let jobs: Jobs;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const Pond = await ethers.getContractFactory("Pond");
		const pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});
		token = getPond(pondContract.target as string, signers[0]);

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifierContract = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		);
		attestationVerifier = getAttestationVerifier(attestationVerifierContract.target as string, signers[0]);

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

		const Executors = await ethers.getContractFactory("Executors");
		const executorsContract = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image4, image5, image6, image7]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		executors = getExecutors(executorsContract.target as string, signers[0]);

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
					3
				]
			},
		);
		jobs = getJobs(jobsContract.target as string, signers[0]);

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

		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
		await gateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);
		[signature, attestation] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
		await gateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(executors.target, 10000);

		let jobCapacity = 20, stakeAmount = 10;
		[signature] = await createAttestation(pubkeys[17], image4, wallets[14], timestamp - 540000);
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[17]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[18]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[19]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		// [signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		// signedDigest = await createExecutorSignature(jobCapacity, wallets[20]);
		// await executors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
		
		// RELAY JOB
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = 100000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
	
		await jobs.relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can slash after deadline over", async function () {
		await time.increase(await time.latest() + 100000);
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);
		let tx = await jobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.emit(jobs, "SlashedOnExecutionTimeout");
	});

	it("cannot slash non-existing job", async function () {
		let jobId = 2;
		let tx = jobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.revertedWithCustomError(jobs, "InvalidJob");
	});

	it("cannot slash before deadline over", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);
		let tx = jobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.revertedWithCustomError(jobs, "DeadlineNotOver");
	});

	it("cannot slash twice", async function () {
		await time.increase(await time.latest() + 100000);
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);
		let tx = await jobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.emit(jobs, "SlashedOnExecutionTimeout");

		let tx2 = jobs.slashOnExecutionTimeout(jobId);
		await expect(tx2).to.revertedWithCustomError(jobs, "InvalidJob");
	});

	it("can slash after executor initiates unstake", async function () {
		await executors.connect(signers[1]).removeExecutorStake(pubkeys[17], 5);
		
		await time.increase(await time.latest() + 100000);
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);

		await expect(jobs.slashOnExecutionTimeout(jobId))
			.to.emit(executors, "ExecutorStakeRemoved").and.to.emit(jobs, "SlashedOnExecutionTimeout");

		let executor = await executors.executors(addrs[17]);
		expect(executor.unstakeStatus).to.be.false;
		expect(executor.unstakeAmount).to.be.eq(0);
		expect(executor.stakeAmount).to.be.eq(5);
		expect(await token.balanceOf(executors.target)).to.be.eq(25);
		expect(await token.balanceOf(addrs[1])).to.be.eq(99975);
	});

	it("can slash after executor initiates deregistration", async function () {
		await executors.connect(signers[1]).deregisterExecutor(pubkeys[17]);
		
		await time.increase(await time.latest() + 100000);
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);

		await expect(jobs.slashOnExecutionTimeout(jobId))
			.to.emit(executors, "EnclaveKeyRevoked").and.to.emit(jobs, "SlashedOnExecutionTimeout");

		expect((await executors.executors(addrs[17])).operator).to.be.eq(ZeroAddress);
		expect(await token.balanceOf(executors.target)).to.be.eq(20);
		expect(await token.balanceOf(addrs[1])).to.be.eq(99980);
	});

});

describe.only("Jobs - Reassign Gateway", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let gateways: Gateways;
	let executors: Executors;
	let jobs: Jobs;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));

		const Pond = await ethers.getContractFactory("Pond");
		const pondContract = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});
		token = getPond(pondContract.target as string, signers[0]);

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		const attestationVerifierContract = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		);
		attestationVerifier = getAttestationVerifier(attestationVerifierContract.target as string, signers[0]);

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

		const Executors = await ethers.getContractFactory("Executors");
		const executorsContract = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image4, image5, image6, image7]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		executors = getExecutors(executorsContract.target as string, signers[0]);

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
					3
				]
			},
		);
		jobs = getJobs(jobsContract.target as string, signers[0]);

		await executors.setJobsContract(jobs.target);

		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				httpRpcUrl: "https://eth.rpc",
				wsRpcUrl: "ws://eth.rpc"
			}
		]
		await gateways.addChainGlobal(chainIds, reqChains);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(gateways.target, 10000);
		await token.connect(signers[1]).approve(executors.target, 10000);

		// REGISTER GATEWAYS
		const timestamp = await time.latest() * 1000,
			stakeAmount = 10;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);
		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, chainIds, signedDigest, stakeAmount);
		
		[signature] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
		signedDigest = await createGatewaySignature(chainIds, wallets[16]);
		await gateways.connect(signers[1]).registerGateway(signature, pubkeys[16], image3.PCR0, image3.PCR1, image3.PCR2, timestamp - 540000, chainIds, signedDigest, stakeAmount);

		// REEGISTER EXECUTORS
		let jobCapacity = 20;
		[signature] = await createAttestation(pubkeys[17], image4, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[17]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[18]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[19]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can reassign after job output not relayed", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			gatewayOperatorOld = addrs[15],
			sequenceId = 1,
			jobRequestTimestamp = await time.latest() + 100;

		let signedDigest = await createReassignGatewaySignature(jobId, gatewayOperatorOld, sequenceId, jobRequestTimestamp, wallets[16]);
		let tx = await jobs.connect(signers[16]).reassignGatewayRelay(gatewayOperatorOld, jobId, signedDigest, sequenceId, jobRequestTimestamp);
		await expect(tx).to.emit(jobs, "GatewayReassigned");
	});

	it("cannot reassign for wrong sequenceId", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			gatewayOperatorOld = addrs[15],
			sequenceId = 2,
			jobRequestTimestamp = await time.latest() + 10;

		let signedDigest = await createReassignGatewaySignature(jobId, gatewayOperatorOld, sequenceId, jobRequestTimestamp, wallets[16]);
		let tx = jobs.connect(signers[16]).reassignGatewayRelay(gatewayOperatorOld, jobId, signedDigest, sequenceId, jobRequestTimestamp);
		await expect(tx).to.revertedWithCustomError(jobs, "InvalidSequenceId");
	});

	it("cannot reassign after relay time is over", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			gatewayOperatorOld = addrs[15],
			sequenceId = 1,
			jobRequestTimestamp = await time.latest() + 10;

		let signedDigest = await createReassignGatewaySignature(jobId, gatewayOperatorOld, sequenceId, jobRequestTimestamp, wallets[16]);
		
		await time.increase(1000);
		let tx = jobs.connect(signers[16]).reassignGatewayRelay(gatewayOperatorOld, jobId, signedDigest, sequenceId, jobRequestTimestamp);
		await expect(tx).to.revertedWithCustomError(jobs, "RelayTimeOver");
	});

	it("cannot reassign new gateway if job is marked as ended due to unavailable executors", async function () {
		await executors.connect(signers[1]).deregisterExecutor(pubkeys[19]);

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(jobs, "JobResourceUnavailable").withArgs(jobId, addrs[15]);

		let gatewayOperatorOld = addrs[15];
		jobRequestTimestamp = await time.latest() + 10;
		signedDigest = await createReassignGatewaySignature(jobId, gatewayOperatorOld, sequenceId, jobRequestTimestamp, wallets[16]);
		
		// reassign new gateway
		await expect(jobs.connect(signers[15]).reassignGatewayRelay(gatewayOperatorOld, jobId, signedDigest, sequenceId, jobRequestTimestamp))
			.to.be.revertedWithCustomError(jobs, "JobMarkedEndedAsResourceUnavailable");
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
	let signedDigest = ethers.Signature.from(signature).serialized
	return signedDigest;
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

async function createOutputSignature(
	jobId: number,
    output: string,
	totalTime: number,
    errorCode: number,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const message = ethers.solidityPackedKeccak256(
        ["uint256", "bytes", "uint256", "uint8"],
		[jobId, output, totalTime, errorCode]
    );
	const signature = await sourceEnclaveWallet.signingKey.sign(message);
	let signedDigest = ethers.Signature.from(signature).serialized
	return signedDigest;
}

async function createReassignGatewaySignature(
	jobId: number,
    gatewayOperatorOld: string,
	sequenceId: number,
	jobRequestTimestamp: number,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const message = ethers.solidityPackedKeccak256(
        ["uint256", "address", "uint8", "uint256"],
		[jobId, gatewayOperatorOld, sequenceId, jobRequestTimestamp]
    );
	const signature = await sourceEnclaveWallet.signingKey.sign(message);
	let signedDigest = ethers.Signature.from(signature).serialized
	return signedDigest;
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
}