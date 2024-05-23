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
		await staking_token.transfer(addrs[1], 10n**20n);
		await staking_token.connect(signers[1]).approve(executors.target, 10n**20n);

		let jobCapacity = 3, stakeAmount = 10n**19n;


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

		await usdc_token.transfer(addrs[1], 10n**6n);
		await usdc_token.connect(signers[1]).approve(jobs.target, 10n**6n);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can relay job", async function () {
		// let reqChainId = (await ethers.provider.getNetwork()).chainId;
		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = 10000,
			jobOwner = addrs[1];

		let tx = await jobs.connect(signers[1]).createJob(codeHash, codeInputs, deadline);
		await tx.wait();
		await expect(tx).to.emit(jobs, "JobCreated");
		
		// Since it is a first job.
		let jobId = 0;
		let job = await jobs.jobs(jobId);

		expect(job.jobOwner).to.eq(jobOwner);
		expect(job.deadline).to.eq(deadline);
		expect(job.execStartTime).to.eq((await tx.getBlock())?.timestamp);

		
		let selectedExecutors = await jobs.getSelectedExecutors(jobId);
		for (let index = 0; index < selectedExecutors.length; index++) {
			const executor = selectedExecutors[index];
			expect([addrs[17], addrs[18], addrs[19], addrs[20]]).to.contain(executor);
		}
	});

	it("cannot relay job when a minimum no. of executor nodes are not available", async function () {
		await executors.connect(signers[1]).drainExecutor(addrs[19]);
		await executors.connect(signers[1]).drainExecutor(addrs[20]);

		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = 10000;

		await expect(jobs.connect(signers[1]).createJob(codeHash, codeInputs, deadline))
			.to.revertedWithCustomError(jobs, "JobsUnavailableResources");
	});

	it("cannot relay job after all the executors are fully occupied", async function () {
		await executors.connect(signers[1]).drainExecutor(addrs[20]);
		
		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = 10000;
			
		for (let index = 1; index <= 3; index++) {
			await expect(jobs.connect(signers[1]).createJob(codeHash, codeInputs, deadline))
				.to.emit(jobs, "JobCreated");
		}

		await expect(jobs.connect(signers[1]).createJob(codeHash, codeInputs, deadline))
			.to.revertedWithCustomError(jobs, "JobsUnavailableResources");
	});
});

// TODO: add case for combination of relay, resource full, submit ouptut and relay again. 

describe("Jobs - Output", function () {
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
					600,
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

		// Register Executors. Owner is addrs[1]
		await staking_token.transfer(addrs[1], 10n**20n);
		await staking_token.connect(signers[1]).approve(executors.target, 10n**20n);

		let jobCapacity = 20, stakeAmount = 10n**19n;
		const timestamp = await time.latest() * 1000;

		for (let index = 0; index < 3; index++) {
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
		// RELAY JOB
		await usdc_token.transfer(addrs[1], 10n**6n);
		await usdc_token.connect(signers[1]).approve(jobs.target, 10n**6n);


		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = 10000;
		await jobs.connect(signers[1]).createJob(codeHash, codeInputs, deadline);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can submit output by selected executor node", async function () {
		let jobId = 0,
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0,
			signTimestamp = await time.latest() - 540;
		
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
		let tx = await jobs.connect(signers[1]).submitOutput(
			signedDigest,
			jobId,
			output,
			totalTime,
			errorCode,
			signTimestamp
		);
		await expect(tx).to.emit(jobs, "JobResponded");
	});

	it("cannot submit output after execution time is over", async function () {
		await time.increase(20000);

		let jobId = 0,
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0,
			signTimestamp = await time.latest() - 540;
		
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);

		await expect(jobs.connect(signers[1]).submitOutput(
			signedDigest,
			jobId,
			output,
			totalTime,
			errorCode,
			signTimestamp
			))
			.to.be.revertedWithCustomError(jobs, "JobsExecutionTimeOver"); 
	});

	it("cannot submit output twice", async function () {
		let jobId = 0,
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0,
			signTimestamp = await time.latest() - 540;
	
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
		let tx = await jobs.connect(signers[1]).submitOutput(
			signedDigest,
			jobId,
			output,
			totalTime,
			errorCode,
			signTimestamp
		);
		await expect(tx).to.emit(jobs, "JobResponded"); 

		await expect(jobs.connect(signers[1]).submitOutput(
			signedDigest,
			jobId,
			output,
			totalTime,
			errorCode,
			signTimestamp
			))
			.to.revertedWithCustomError(jobs, "JobsExecutorAlreadySubmittedOutput");
	});

	it("cannot submit output from unselected executor node", async function () {
		let jobCapacity = 20,
			stakeAmount = 10,
			timestamp = await time.latest() * 1000;

		let signTimestamp = await time.latest() - 540;
		// Executor index using wallet 17 + index as enclave address
		let [attestationSign, attestation] = await createAttestation(pubkeys[20], image4,
																		wallets[14], timestamp - 540000);
		let signedDigest = await createExecutorSignature(addrs[1], jobCapacity, signTimestamp,
															wallets[20]);

		await executors.connect(signers[1]).registerExecutor(
			attestationSign,
			attestation, 
			jobCapacity,
			signTimestamp,
			signedDigest,
			stakeAmount
		);

		let jobId = 0,
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		signTimestamp = await time.latest() - 540;
		signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[20]);
		await expect(jobs.connect(signers[1]).submitOutput(
			signedDigest,
			jobId,
			output,
			totalTime,
			errorCode,
			signTimestamp
			))
			.to.revertedWithCustomError(jobs, "JobsNotSelectedExecutor");
	});

	it("can submit output after executor initiates draining", async function () {
		let jobId = 0,
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0,
			signTimestamp = await time.latest() - 540;

		await executors.connect(signers[1]).drainExecutor(addrs[17]);
		
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, signTimestamp, wallets[17]);
		await expect(jobs.connect(signers[1]).submitOutput(
			signedDigest,
			jobId,
			output,
			totalTime,
			errorCode,
			signTimestamp
			))
			.to.emit(jobs, "JobResponded");

		let executor = await executors.executors(addrs[17]);
		expect(executor.draining).to.be.true;
	});
});

describe("Jobs - Slashing", function () {
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

		await executors.grantRole(keccak256(ethers.toUtf8Bytes("JOBS_ROLE")), jobs.target);


		// Grant role to jobs contract on executor
		await staking_token.transfer(addrs[1], 10n**20n);
		await staking_token.connect(signers[1]).approve(executors.target, 10n**20n);

		let jobCapacity = 20, stakeAmount = 10n**19n;
		const timestamp = await time.latest() * 1000;
		for (let index = 0; index < 3; index++) {
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

		// RELAY JOB
		await usdc_token.transfer(addrs[1], 10n**6n);
		await usdc_token.connect(signers[1]).approve(jobs.target, 10n**6n);


		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = 10000;
		await jobs.connect(signers[1]).createJob(codeHash, codeInputs, deadline);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can slash after deadline over", async function () {
		await time.increase(await time.latest() + 100000);
		let jobId = 0;
		let tx = await jobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.emit(jobs, "SlashedOnExecutionTimeout");
	});

	it("cannot slash non-existing job with id greater than total job count", async function () {
		let jobId = 2;
		let tx = jobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.revertedWithPanic(0x32);
	});

	it("cannot slash before deadline over", async function () {
		let jobId = 0;
		let tx = jobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.revertedWithCustomError(jobs, "JobsDeadlineNotOver");
	});

	it("cannot slash twice", async function () {
		await time.increase(await time.latest() + 100000);
		let jobId = 0;
		let tx = await jobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.emit(jobs, "SlashedOnExecutionTimeout");

		let tx2 = jobs.slashOnExecutionTimeout(jobId);
		await expect(tx2).to.revertedWithCustomError(jobs, "JobsInvalidJob");
	});

	it("can slash after executor initiates drain", async function () {
		await executors.connect(signers[1]).drainExecutor(addrs[17]);
		
		await time.increase(await time.latest() + 100000);
		let jobId = 0;

		await expect(jobs.slashOnExecutionTimeout(jobId))
			.to.emit(jobs, "SlashedOnExecutionTimeout");

		let executor = await executors.executors(addrs[17]);
		expect(executor.draining).to.be.true;
	});
});

// TODO: Increase Coverage

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
	jobId: number,
    output: string,
	totalTime: number,
    errorCode: number,
	signTimestamp: number,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const domain = {
		name: 'marlin.oyster.Jobs',
		version: '1',
	};

	const types = {
		SubmitOutput: [
			{ name: 'jobId', type: 'uint256' },
			{ name: 'output', type: 'bytes' },
			{ name: 'totalTime', type: 'uint256' },
			{ name: 'errorCode', type: 'uint8' },
			{ name: 'signTimestamp', type: 'uint256'}
		]
	};

	const value = {
		jobId,
		output,
		totalTime,
		errorCode,
		signTimestamp
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