import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, keccak256, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, Executors, Gateways, Jobs, Pond, USDCoin } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { timeStamp } from 'console';

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

describe("Jobs - Init", function () {
	let signers: Signer[];
	let addrs: string[];
	let staking_token: string;
	let usdc_token: string;
	let executors: string;
	let staking_payment_pool: string;
	let usdc_payment_pool: string;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		staking_token = addrs[1];
		usdc_token = addrs[1];
		executors = addrs[1];
		staking_payment_pool = addrs[1];
		usdc_payment_pool = addrs[1];
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("deploys with initialization disabled", async function () {

		const Jobs = await ethers.getContractFactory("Jobs");
		const jobs = await Jobs.deploy(
			staking_token,
			usdc_token,
			100,
			100,
			3,
			1,
			1,
			staking_payment_pool,
			usdc_payment_pool,
			executors
		);

		await expect(
			jobs.initialize(addrs[0]),
		).to.be.revertedWithCustomError(jobs, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function () {
		const Jobs = await ethers.getContractFactory("Jobs");
		const jobs = await upgrades.deployProxy(
			Jobs,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					staking_token,
					usdc_token,
					100,
					100,
					3,
					1,
					1,
					staking_payment_pool,
					usdc_payment_pool,
					executors
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
				[ZeroAddress],
				{
					kind: "uups",
					initializer: "initialize",
					constructorArgs: [
						staking_token,
						usdc_token,
						100,
						100,
						3,
						1,
						1,
						staking_payment_pool,
						usdc_payment_pool,
						executors
					]
				},
			)
		).to.be.revertedWithCustomError(Jobs, "JobsZeroAddressAdmin");
	});

	it("upgrades", async function () {
		const Jobs = await ethers.getContractFactory("Jobs");
		const jobs = await upgrades.deployProxy(
			Jobs,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					staking_token,
					usdc_token,
					100,
					100,
					3,
					1,
					1,
					staking_payment_pool,
					usdc_payment_pool,
					executors
				]
			},
		);
		await upgrades.upgradeProxy(
			jobs.target,
			Jobs,
			{
				kind: "uups",
				constructorArgs: [
					staking_token,
					usdc_token,
					100,
					100,
					3,
					1,
					1,
					staking_payment_pool,
					usdc_payment_pool,
					executors
				]
			}
		);

		expect(await jobs.hasRole(await jobs.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
		// TODO verify immutables are updated
	});

	it("does not upgrade without admin", async function () {
		const Jobs = await ethers.getContractFactory("Jobs");
		const jobs = await upgrades.deployProxy(
			Jobs,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					staking_token,
					usdc_token,
					100,
					100,
					3,
					1,
					1,
					staking_payment_pool,
					usdc_payment_pool,
					executors
				]
			},
		);

		await expect(
			upgrades.upgradeProxy(jobs.target, Jobs.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [
					staking_token,
					usdc_token,
					100,
					100,
					3,
					1,
					1,
					staking_payment_pool,
					usdc_payment_pool,
					executors
				]
			}),
		).to.be.revertedWithCustomError(Jobs, "AccessControlUnauthorizedAccount");
	});

});

describe("Jobs - Create", function () {
	let signers: Signer[];
	let addrs: string[];
	let staking_token: Pond;
	let usdc_token: USDCoin;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let executors: Executors;
	let jobs: Jobs;
	let staking_payment_pool: string;
	let usdc_payment_pool: string;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
		wallets = signers.map((_, idx) => walletForIndex(idx));
		pubkeys = wallets.map((w) => normalize(w.signingKey.publicKey));
		staking_payment_pool = addrs[1];
		usdc_payment_pool = addrs[1];

		const Pond = await ethers.getContractFactory("Pond");
		staking_token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		}) as unknown as Pond;

		const USDCoin = await ethers.getContractFactory("USDCoin");
		usdc_token = await upgrades.deployProxy(USDCoin, [addrs[0]], {
			kind: "uups",
		}) as unknown as USDCoin;

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		attestationVerifier = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		) as unknown as AttestationVerifier;

		// TODO check why getAddress have to be called to obtain the address
		let attestationVerifierAddress = await attestationVerifier.getAddress();
		let staking_token_address = await staking_token.getAddress();
		let usdc_token_address = await usdc_token.getAddress();
		let executor_images = [image4, image5, image6, image7]
		const Executors = await ethers.getContractFactory("Executors");
		executors = await upgrades.deployProxy(
			Executors,
			[addrs[0], executor_images],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					attestationVerifierAddress,
					600,
					staking_token_address,
					10**10,
					10**2,
					10**6
				]
			},
		) as unknown as Executors;

		let executors_address = await executors.getAddress();
		const Jobs = await ethers.getContractFactory("Jobs");
		jobs = await upgrades.deployProxy(
			Jobs,
			[addrs[0]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					staking_token_address,
					usdc_token_address,
					100,
					100,
					3,
					1,
					1,
					staking_payment_pool,
					usdc_payment_pool,
					executors_address
				]
			},
		) as unknown as Jobs;

		// Grant role to jobs contract on executor
		await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);
		const timestamp = await time.latest() * 1000;

		// Register Executors. Owner is addrs[1]
		await staking_token.transfer(addrs[1], 100000);
		await staking_token.connect(signers[1]).approve(executors.target, 10000);

		let jobCapacity = 3, stakeAmount = 10;


		for (let index = 0; index < 4; index++) {
			let signTimestamp = await time.latest() - 540;
			// Executor index using wallet 17 + index as enclave address
			let [attestationSign, attestation] = await createAttestation(pubkeys[17 + index], executor_images[index],
																		 wallets[14], timestamp - 540000);
			let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, signTimestamp,
															 wallets[17 + index]);

			await executors.connect(signers[1]).registerExecutor(
				attestationSign,
				attestation, 
				jobCapacity,
				signTimestamp,
				signedDigest,
				stakeAmount
			);
		}
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can relay job", async function () {
		// let reqChainId = (await ethers.provider.getNetwork()).chainId;
		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobOwner = addrs[1];

		let tx = await jobs.connect(signers[1]).createJob(codeHash, codeInputs, deadline);
		await expect(tx).to.emit(jobs, "JobCreated");
		
		// Since it is a first job.
		let jobId = 0;
		let job = await jobs.jobs(jobId);

		expect(job.jobOwner).to.eq(jobOwner);
		expect(job.deadline).to.eq(deadline);
		expect(job.execStartTime).to.eq(1); // TODO get the block timestamp.

		
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
		let signedDigest = await createRelayJobSignature(addrs[1], jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await time.increase(1000);
		await expect(jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(jobs, "JobsRelayTimeOver");
	});

	it("cannot relay job with wrong sequence id", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 2,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(addrs[1], jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(jobs, "JobsInvalidSequenceId");
	});

	it("cannot relay a job twice with same job id", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(addrs[1], jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
		await jobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);

		await expect(jobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(jobs, "JobsJobAlreadyRelayed");
	});

	it("cannot relay job with unsupported chain id", async function () {
		let jobId: any = (BigInt(2) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(addrs[1], jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(jobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(jobs, "JobsUnsupportedChain");
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
		let signedDigest = await createRelayJobSignature(addrs[1], jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(jobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(jobs, "JobResourceUnavailable").withArgs(jobId, addrs[1]);

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
		let signedDigest = await createRelayJobSignature(addrs[1], jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(jobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(jobs, "JobResourceUnavailable").withArgs(jobId, addrs[1]);

		// relay again
		await expect(jobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(jobs, "JobsJobMarkedEndedAsResourceUnavailable");
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
			let signedDigest = await createRelayJobSignature(addrs[1], jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
			
			await expect(await jobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
				.to.emit(jobs, "JobRelayed");
		}

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(4),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(addrs[1], jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(jobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(jobs, "JobResourceUnavailable").withArgs(jobId, addrs[1]);

		expect((await jobs.jobs(jobId)).isResourceUnavailable).to.be.true;

		// SUBMIT OUTPUT AND THEN RELAY JOB WILL WORK
		jobId = (BigInt(1) << BigInt(192)) + BigInt(1);
		let	output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		signedDigest = await createOutputSignature(addrs[1], jobId, output, totalTime, errorCode, wallets[17]);
		await jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode);

		signedDigest = await createOutputSignature(addrs[1], jobId, output, totalTime, errorCode, wallets[18]);
		await jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode);

		signedDigest = await createOutputSignature(addrs[1], jobId, output, totalTime, errorCode, wallets[19]);
		await jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode);

		// RELAY AGAIN WORKS
		jobId = (BigInt(1) << BigInt(192)) + BigInt(5);
		signedDigest = await createRelayJobSignature(addrs[1], jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
			
		await expect(jobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(jobs, "JobRelayed");
	});
});

describe("Jobs - Output", function () {
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
		token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		}) as unknown as Pond;

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		attestationVerifier = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		) as unknown as AttestationVerifier;

		const Gateways = await ethers.getContractFactory("Gateways");
		gateways = await upgrades.deployProxy(
			Gateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target, 600]
			},
		) as unknown as Gateways;

		const Executors = await ethers.getContractFactory("Executors");
		executors = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image4, image5, image6, image7]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		) as unknown as Executors;

		const Jobs = await ethers.getContractFactory("Jobs");
		jobs = await upgrades.deployProxy(
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
		) as unknown as Jobs;

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
		let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, wallets[17]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(addrs[1], jobCapacity, wallets[18]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(addrs[1], jobCapacity, wallets[19]);
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
		signedDigest = await createRelayJobSignature(addrs[1], jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await jobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can submit output by selected executor node", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createOutputSignature(addrs[1], jobId, output, totalTime, errorCode, wallets[17]);
		let tx = await jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.emit(jobs, "JobResponded");
	});

	it("cannot submit output after execution time is over", async function () {
		await time.increase(300);

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		let signedDigest = await createOutputSignature(addrs[1], jobId, output, totalTime, errorCode, wallets[17]);

		await expect(jobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode))
			.to.be.revertedWithCustomError(jobs, "JobsExecutionTimeOver"); 
	});

	it("cannot submit output twice", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createOutputSignature(addrs[1], jobId, output, totalTime, errorCode, wallets[17]);
		let tx = await jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.emit(jobs, "JobResponded"); 

		let tx2 = jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx2).to.revertedWithCustomError(jobs, "JobsExecutorAlreadySubmittedOutput");
	});

	it("cannot submit output from unselected executor node", async function () {
		let jobCapacity = 20,
			stakeAmount = 10,
			timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, wallets[20]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
		
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		signedDigest = await createOutputSignature(addrs[1], jobId, output, totalTime, errorCode, wallets[20]);
		let tx = jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.revertedWithCustomError(jobs, "JobsNotSelectedExecutor"); 
	});

	it("can submit output after executor initiates unstake", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;

		await executors.connect(signers[1]).removeExecutorStake(pubkeys[17], 5);
		
		let signedDigest = await createOutputSignature(addrs[1], jobId, output, totalTime, errorCode, wallets[17]);
		await expect(jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode))
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
		
		let signedDigest = await createOutputSignature(addrs[1], jobId, output, totalTime, errorCode, wallets[17]);
		await expect(jobs.connect(signers[1]).submitOutput(signedDigest, jobId, output, totalTime, errorCode))
			.to.emit(executors, "EnclaveKeyRevoked").and.to.emit(jobs, "JobResponded");

		expect((await executors.executors(addrs[17])).operator).to.be.eq(ZeroAddress);
		expect(await token.balanceOf(executors.target)).to.be.eq(20);
		expect(await token.balanceOf(addrs[1])).to.be.eq(99980);
	});

});

describe("Jobs - Slashing", function () {
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
		token = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		}) as unknown as Pond;

		const AttestationVerifier = await ethers.getContractFactory("AttestationVerifier");
		attestationVerifier = await upgrades.deployProxy(
			AttestationVerifier,
			[[image1], [pubkeys[14]], addrs[0]],
			{ kind: "uups" },
		) as unknown as AttestationVerifier;

		const Gateways = await ethers.getContractFactory("Gateways");
		gateways = await upgrades.deployProxy(
			Gateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target, 600]
			},
		) as unknown as Gateways;

		const Executors = await ethers.getContractFactory("Executors");
		executors = await upgrades.deployProxy(
			Executors,
			[addrs[0], [image4, image5, image6, image7]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		) as unknown as Executors;

		const Jobs = await ethers.getContractFactory("Jobs");
		jobs = await upgrades.deployProxy(
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
		) as unknown as Jobs;

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
		let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, wallets[17]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(addrs[1], jobCapacity, wallets[18]);
		await executors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(addrs[1], jobCapacity, wallets[19]);
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
		signedDigest = await createRelayJobSignature(addrs[1], jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
	
		await jobs.connect(signers[1]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);
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
		await expect(tx).to.revertedWithCustomError(jobs, "JobsInvalidJob");
	});

	it("cannot slash before deadline over", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);
		let tx = jobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.revertedWithCustomError(jobs, "JobsDeadlineNotOver");
	});

	it("cannot slash twice", async function () {
		await time.increase(await time.latest() + 100000);
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);
		let tx = await jobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.emit(jobs, "SlashedOnExecutionTimeout");

		let tx2 = jobs.slashOnExecutionTimeout(jobId);
		await expect(tx2).to.revertedWithCustomError(jobs, "JobsInvalidJob");
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
	owner: string,
	jobCapacity: number,
	signTimestamp: number,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const domain = {
		name: 'marlin.oyster.Executors',
		version: '1',
	};

	const types = {
		Register: [
			{ name: 'owner', type: 'address' },
			{ name: 'jobCapacity', type: 'uint256' },
			{ name: 'signTimestamp', type: 'uint256' }
		]
	};

	const value = {
		owner,
		jobCapacity,
		signTimestamp
	};

	const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
	return ethers.Signature.from(sign).serialized;
}

async function createRelayJobSignature(
	operator: string,
	jobId: number,
    codeHash: string,
	codeInputs: string,
    deadline: number,
	jobRequestTimestamp: number,
	sequenceId: number,
	jobOwner: string,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const domain = {
		name: 'marlin.oyster.Jobs',
		version: '1',
	};

	const types = {
		RelayJob: [
			{ name: 'operator', type: 'address' },
			{ name: 'jobId', type: 'uint256' },
			{ name: 'codeHash', type: 'bytes32' },
			{ name: 'codeInputs', type: 'bytes' },
			{ name: 'deadline', type: 'uint256' },
			{ name: 'jobRequestTimestamp', type: 'uint256' },
			{ name: 'sequenceId', type: 'uint8' },
			{ name: 'jobOwner', type: 'address' }
		]
	};

	const value = {
		operator,
		jobId, 
		codeHash, 
		codeInputs, 
		deadline, 
		jobRequestTimestamp, 
		sequenceId, 
		jobOwner
	};

	const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
	return ethers.Signature.from(sign).serialized;
}

async function createOutputSignature(
	operator: string,
	jobId: number,
    output: string,
	totalTime: number,
    errorCode: number,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const domain = {
		name: 'marlin.oyster.Jobs',
		version: '1',
	};

	const types = {
		SubmitOutput: [
			{ name: 'operator', type: 'address' },
			{ name: 'jobId', type: 'uint256' },
			{ name: 'output', type: 'bytes' },
			{ name: 'totalTime', type: 'uint256' },
			{ name: 'errorCode', type: 'uint8' }
		]
	};

	const value = {
		operator,
		jobId,
		output,
		totalTime,
		errorCode
	};

	const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
	return ethers.Signature.from(sign).serialized;
}

async function createReassignGatewaySignature(
	operator: string,
	jobId: number,
    gatewayKeyOld: string,
	sequenceId: number,
	jobRequestTimestamp: number,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const domain = {
		name: 'marlin.oyster.Jobs',
		version: '1',
	};

	const types = {
		ReassignGateway: [
			{ name: 'operator', type: 'address' },
			{ name: 'jobId', type: 'uint256' },
			{ name: 'gatewayKeyOld', type: 'address' },
			{ name: 'sequenceId', type: 'uint8' },
			{ name: 'jobRequestTimestamp', type: 'uint256' }
		]
	};

	const value = {
		operator,
		jobId,
		gatewayKeyOld,
		sequenceId,
		jobRequestTimestamp
	};

	const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
	return ethers.Signature.from(sign).serialized;
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
}