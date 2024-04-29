import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, keccak256, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationVerifier, CommonChainExecutors, CommonChainGateways, CommonChainJobs, Pond } from "../../typechain-types";
import { AttestationAutherUpgradeable } from "../../typechain-types/contracts/AttestationAutherSample";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { getAttestationVerifier, getCommonChainExecutors, getCommonChainGateways, getCommonChainJobs, getPond } from '../../utils/typechainConvertor';


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
		const commonChainJobs = await CommonChainJobs.deploy(token, 100, 100, 3);

		await expect(
			commonChainJobs.__CommonChainJobs_init(addrs[0], commonChainGateway, commonChainExecutors),
		).to.be.revertedWithCustomError(commonChainJobs, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function () {
		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobs = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], commonChainGateway, commonChainExecutors],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			},
		);

		expect(await commonChainJobs.hasRole(await commonChainJobs.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
	});

	it("cannot initialize with zero address as admin", async function () {
		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		await expect(
			upgrades.deployProxy(
				CommonChainJobs,
				[ZeroAddress, commonChainGateway, commonChainExecutors],
				{
					kind: "uups",
					initializer: "__CommonChainJobs_init",
					constructorArgs: [
						token,
						100,
						100,
						3
					]
				},
			)
		).to.be.revertedWithCustomError(CommonChainJobs, "ZeroAddressAdmin");
	});

	it("upgrades", async function () {
		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobs = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], commonChainGateway, commonChainExecutors],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			},
		);
		await upgrades.upgradeProxy(
			commonChainJobs.target,
			CommonChainJobs,
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

		expect(await commonChainJobs.hasRole(await commonChainJobs.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
	});

	it("does not upgrade without admin", async function () {
		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobs = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], commonChainGateway, commonChainExecutors],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			},
		);

		await expect(
			upgrades.upgradeProxy(commonChainJobs.target, CommonChainJobs.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			}),
		).to.be.revertedWithCustomError(CommonChainJobs, "AccessControlUnauthorizedAccount");
	});

	it("can set gateway contract only with admin role", async function () {
		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobsContract = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], commonChainGateway, commonChainExecutors],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			},
		);
		const commonChainJobs = getCommonChainJobs(commonChainJobsContract.target as string, signers[0]);
		
		await expect(commonChainJobs.connect(signers[1]).setGatewaysContract(addrs[1]))
			.to.be.revertedWithCustomError(commonChainJobs, "AccessControlUnauthorizedAccount");
		await expect(commonChainJobs.setGatewaysContract(addrs[1])).to.not.be.rejected;
	});

	it("can set executor contract only with admin role", async function () {
		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobsContract = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], commonChainGateway, commonChainExecutors],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init",
				constructorArgs: [
					token,
					100,
					100,
					3
				]
			},
		);
		const commonChainJobs = getCommonChainJobs(commonChainJobsContract.target as string, signers[0]);
		
		await expect(commonChainJobs.connect(signers[1]).setExecutorsContract(addrs[1]))
			.to.be.revertedWithCustomError(commonChainJobs, "AccessControlUnauthorizedAccount");
		await expect(commonChainJobs.setExecutorsContract(addrs[1])).to.not.be.rejected;
	});
});

describe("CommonChainJobs - Relay", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let commonChainGateways: CommonChainGateways;
	let commonChainExecutors: CommonChainExecutors;
	let commonChainJobs: CommonChainJobs;

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

		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGatewaysContract = await upgrades.deployProxy(
			CommonChainGateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "__CommonChainGateways_init",
				constructorArgs: [attestationVerifier.target, 600, token.target, 600]
			},
		);
		commonChainGateways = getCommonChainGateways(commonChainGatewaysContract.target as string, signers[0]);

		const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
		const commonChainExecutorsContract = await upgrades.deployProxy(
			CommonChainExecutors,
			[addrs[0], [image4, image5, image6, image7]],
			{
				kind: "uups",
				initializer: "__CommonChainExecutors_init",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		commonChainExecutors = getCommonChainExecutors(commonChainExecutorsContract.target as string, signers[0]);

		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobsContract = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], commonChainGateways.target, commonChainExecutors.target],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init",
				constructorArgs: [
					token.target,
					100,
					100,
					3
				]
			},
		);
		commonChainJobs = getCommonChainJobs(commonChainJobsContract.target as string, signers[0]);

		await commonChainExecutors.setJobsContract(commonChainJobs.target);

		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				httpRpcUrl: "https://eth.rpc",
				wsRpcUrl: "wss://eth.rpc"
			}
		]
		await commonChainGateways.addChainGlobal(chainIds, reqChains);

		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
		await commonChainGateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);
		[signature, attestation] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
		await commonChainGateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(commonChainExecutors.target, 10000);

		let jobCapacity = 3, stakeAmount = 10;
		[signature] = await createAttestation(pubkeys[17], image4, wallets[14], timestamp - 540000);
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[17]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[18]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[19]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[20]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
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

		let tx = await commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);
		await expect(tx).to.emit(commonChainJobs, "JobRelayed");

		let job = await commonChainJobs.jobs(jobId);

		expect(job.jobId).to.eq(jobId);
		expect(job.jobOwner).to.eq(jobOwner);
		
		let selectedExecutors = await commonChainJobs.getSelectedExecutors(jobId);
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
		await expect(commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(commonChainJobs, "RelayTimeOver");
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

		await expect(commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(commonChainJobs, "InvalidSequenceId");
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
		await commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);

		await expect(commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(commonChainJobs, "JobAlreadyRelayed");
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

		await expect(commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(commonChainJobs, "UnsupportedChain");
	});

	it("cannot relay job when a minimum no. of executor nodes are not available", async function () {
		await commonChainExecutors.connect(signers[1]).deregisterExecutor(pubkeys[19]);
		await commonChainExecutors.connect(signers[1]).deregisterExecutor(pubkeys[20]);

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(commonChainJobs, "JobResourceUnavailable").withArgs(jobId, addrs[15]);

		expect((await commonChainJobs.jobs(jobId)).isResourceUnavailable).to.be.true;
	});

	it("cannot relay job again if it's marked as ended due to unavailable executors", async function () {
		await commonChainExecutors.connect(signers[1]).deregisterExecutor(pubkeys[19]);
		await commonChainExecutors.connect(signers[1]).deregisterExecutor(pubkeys[20]);

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(commonChainJobs, "JobResourceUnavailable").withArgs(jobId, addrs[15]);

		// relay again
		await expect(commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.be.revertedWithCustomError(commonChainJobs, "JobMarkedEndedAsResourceUnavailable");
	});

	it("cannot relay job after all the executors are fully occupied", async function () {
		await commonChainExecutors.connect(signers[1]).deregisterExecutor(pubkeys[20]);

		for (let index = 1; index <= 3; index++) {
			let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(index),
				codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
				codeInputs = solidityPacked(["string"], ["codeInput"]),
				deadline = await time.latest() + 10000,
				jobRequestTimestamp = await time.latest(),
				sequenceId = 1,
				jobOwner = addrs[1];
			let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
			
			await expect(await commonChainJobs.relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
				.to.emit(commonChainJobs, "JobRelayed");
		}

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(4),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(commonChainJobs.relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(commonChainJobs, "JobResourceUnavailable").withArgs(jobId, addrs[0]);

		expect((await commonChainJobs.jobs(jobId)).isResourceUnavailable).to.be.true;

		// SUBMIT OUTPUT AND THEN RELAY JOB WILL WORK
		jobId = (BigInt(1) << BigInt(192)) + BigInt(1);
		let	output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);
		await commonChainJobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);

		signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[18]);
		await commonChainJobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);

		signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[19]);
		await commonChainJobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);

		// RELAY AGAIN WORKS
		jobId = (BigInt(1) << BigInt(192)) + BigInt(5);
		signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
			
		await expect(commonChainJobs.relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(commonChainJobs, "JobRelayed");
	});
});

describe("CommonChainJobs - Output", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let commonChainGateways: CommonChainGateways;
	let commonChainExecutors: CommonChainExecutors;
	let commonChainJobs: CommonChainJobs;

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

		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGatewaysContract = await upgrades.deployProxy(
			CommonChainGateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "__CommonChainGateways_init",
				constructorArgs: [attestationVerifier.target, 600, token.target, 600]
			},
		);
		commonChainGateways = getCommonChainGateways(commonChainGatewaysContract.target as string, signers[0]);

		const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
		const commonChainExecutorsContract = await upgrades.deployProxy(
			CommonChainExecutors,
			[addrs[0], [image4, image5, image6, image7]],
			{
				kind: "uups",
				initializer: "__CommonChainExecutors_init",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		commonChainExecutors = getCommonChainExecutors(commonChainExecutorsContract.target as string, signers[0]);

		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobsContract = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], commonChainGateways.target, commonChainExecutors.target],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init",
				constructorArgs: [
					token.target,
					100,
					100,
					3
				]
			},
		);
		commonChainJobs = getCommonChainJobs(commonChainJobsContract.target as string, signers[0]);

		await commonChainExecutors.setJobsContract(commonChainJobs.target);

		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				httpRpcUrl: "https://eth.rpc",
				wsRpcUrl: "wss://eth.rpc",
			}
		]
		await commonChainGateways.addChainGlobal(chainIds, reqChains);

		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
		await commonChainGateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);
		[signature, attestation] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
		await commonChainGateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(commonChainExecutors.target, 10000);

		let jobCapacity = 20, stakeAmount = 10;
		[signature] = await createAttestation(pubkeys[17], image4, wallets[14], timestamp - 540000);
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[17]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[18]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[19]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		// [signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		// signedDigest = await createExecutorSignature(jobCapacity, wallets[20]);
		// await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
		
		// RELAY JOB
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = 100000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await commonChainJobs.relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can submit output by selected executor node", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);
		let tx = await commonChainJobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.emit(commonChainJobs, "JobResponded");
	});

	it("cannot submit output after execution time is over", async function () {
		await time.increase(300);

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);

		await expect(commonChainJobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode))
			.to.be.revertedWithCustomError(commonChainJobs, "ExecutionTimeOver"); 
	});

	it("cannot submit output twice", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);
		let tx = await commonChainJobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.emit(commonChainJobs, "JobResponded"); 

		let tx2 = commonChainJobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx2).to.revertedWithCustomError(commonChainJobs, "ExecutorAlreadySubmittedOutput");
	});

	it("cannot submit output from unselected executor node", async function () {
		let jobCapacity = 20,
			stakeAmount = 10,
			timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[20]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
		
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[20]);
		let tx = commonChainJobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.revertedWithCustomError(commonChainJobs, "NotSelectedExecutor"); 
	});

	it("can submit output after executor initiates unstake", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;

		await commonChainExecutors.connect(signers[1]).removeExecutorStake(pubkeys[17], 5);
		
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);
		await expect(commonChainJobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode))
			.to.emit(commonChainExecutors, "ExecutorStakeRemoved").and.to.emit(commonChainJobs, "JobResponded");

		let executor = await commonChainExecutors.executors(addrs[17]);
		expect(executor.unstakeStatus).to.be.false;
		expect(executor.unstakeAmount).to.be.eq(0);
		expect(executor.stakeAmount).to.be.eq(5);
		expect(await token.balanceOf(commonChainExecutors.target)).to.be.eq(25);
		expect(await token.balanceOf(addrs[1])).to.be.eq(99975);
	});

	it("can submit output after executor initiates deregistration", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;

		await commonChainExecutors.connect(signers[1]).deregisterExecutor(pubkeys[17]);
		
		let signedDigest = await createOutputSignature(jobId, output, totalTime, errorCode, wallets[17]);
		await expect(commonChainJobs.submitOutput(signedDigest, jobId, output, totalTime, errorCode))
			.to.emit(commonChainExecutors, "EnclaveKeyRevoked2").and.to.emit(commonChainJobs, "JobResponded");

		expect((await commonChainExecutors.executors(addrs[17])).operator).to.be.eq(ZeroAddress);
		expect(await token.balanceOf(commonChainExecutors.target)).to.be.eq(20);
		expect(await token.balanceOf(addrs[1])).to.be.eq(99980);
	});

});

describe("CommonChainJobs - Slashing", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let commonChainGateways: CommonChainGateways;
	let commonChainExecutors: CommonChainExecutors;
	let commonChainJobs: CommonChainJobs;

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

		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGatewaysContract = await upgrades.deployProxy(
			CommonChainGateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "__CommonChainGateways_init",
				constructorArgs: [attestationVerifier.target, 600, token.target, 600]
			},
		);
		commonChainGateways = getCommonChainGateways(commonChainGatewaysContract.target as string, signers[0]);

		const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
		const commonChainExecutorsContract = await upgrades.deployProxy(
			CommonChainExecutors,
			[addrs[0], [image4, image5, image6, image7]],
			{
				kind: "uups",
				initializer: "__CommonChainExecutors_init",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		commonChainExecutors = getCommonChainExecutors(commonChainExecutorsContract.target as string, signers[0]);

		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobsContract = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], commonChainGateways.target, commonChainExecutors.target],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init",
				constructorArgs: [
					token.target,
					100,
					100,
					3
				]
			},
		);
		commonChainJobs = getCommonChainJobs(commonChainJobsContract.target as string, signers[0]);

		await commonChainExecutors.setJobsContract(commonChainJobs.target);

		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				httpRpcUrl: "https://eth.rpc",
				wsRpcUrl: "wss://eth.rpc"
			}
		]
		await commonChainGateways.addChainGlobal(chainIds, reqChains);

		const timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
		await commonChainGateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);
		[signature, attestation] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
		await commonChainGateways.connect(signers[1]).verifyEnclaveKey(signature, attestation);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(commonChainExecutors.target, 10000);

		let jobCapacity = 20, stakeAmount = 10;
		[signature] = await createAttestation(pubkeys[17], image4, wallets[14], timestamp - 540000);
		let signedDigest = await createExecutorSignature(jobCapacity, wallets[17]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[18]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[19]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		// [signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		// signedDigest = await createExecutorSignature(jobCapacity, wallets[20]);
		// await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
		
		// RELAY JOB
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = 100000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);
	
		await commonChainJobs.relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can slash after deadline over", async function () {
		await time.increase(await time.latest() + 100000);
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);
		let tx = await commonChainJobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.emit(commonChainJobs, "SlashedOnExecutionTimeout");
	});

	it("cannot slash non-existing job", async function () {
		let jobId = 2;
		let tx = commonChainJobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.revertedWithCustomError(commonChainJobs, "InvalidJob");
	});

	it("cannot slash before deadline over", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);
		let tx = commonChainJobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.revertedWithCustomError(commonChainJobs, "DeadlineNotOver");
	});

	it("cannot slash twice", async function () {
		await time.increase(await time.latest() + 100000);
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);
		let tx = await commonChainJobs.slashOnExecutionTimeout(jobId);
		await expect(tx).to.emit(commonChainJobs, "SlashedOnExecutionTimeout");

		let tx2 = commonChainJobs.slashOnExecutionTimeout(jobId);
		await expect(tx2).to.revertedWithCustomError(commonChainJobs, "InvalidJob");
	});

	it("can slash after executor initiates unstake", async function () {
		await commonChainExecutors.connect(signers[1]).removeExecutorStake(pubkeys[17], 5);
		
		await time.increase(await time.latest() + 100000);
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);

		await expect(commonChainJobs.slashOnExecutionTimeout(jobId))
			.to.emit(commonChainExecutors, "ExecutorStakeRemoved").and.to.emit(commonChainJobs, "SlashedOnExecutionTimeout");

		let executor = await commonChainExecutors.executors(addrs[17]);
		expect(executor.unstakeStatus).to.be.false;
		expect(executor.unstakeAmount).to.be.eq(0);
		expect(executor.stakeAmount).to.be.eq(5);
		expect(await token.balanceOf(commonChainExecutors.target)).to.be.eq(25);
		expect(await token.balanceOf(addrs[1])).to.be.eq(99975);
	});

	it("can slash after executor initiates deregistration", async function () {
		await commonChainExecutors.connect(signers[1]).deregisterExecutor(pubkeys[17]);
		
		await time.increase(await time.latest() + 100000);
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1);

		await expect(commonChainJobs.slashOnExecutionTimeout(jobId))
			.to.emit(commonChainExecutors, "EnclaveKeyRevoked2").and.to.emit(commonChainJobs, "SlashedOnExecutionTimeout");

		expect((await commonChainExecutors.executors(addrs[17])).operator).to.be.eq(ZeroAddress);
		expect(await token.balanceOf(commonChainExecutors.target)).to.be.eq(20);
		expect(await token.balanceOf(addrs[1])).to.be.eq(99980);
	});

});

describe("CommonChainJobs - Reassign Gateway", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let commonChainGateways: CommonChainGateways;
	let commonChainExecutors: CommonChainExecutors;
	let commonChainJobs: CommonChainJobs;

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

		const CommonChainGateways = await ethers.getContractFactory("CommonChainGateways");
		const commonChainGatewaysContract = await upgrades.deployProxy(
			CommonChainGateways,
			[addrs[0], [image2, image3]],
			{
				kind: "uups",
				initializer: "__CommonChainGateways_init",
				constructorArgs: [attestationVerifier.target, 600, token.target, 600]
			},
		);
		commonChainGateways = getCommonChainGateways(commonChainGatewaysContract.target as string, signers[0]);

		const CommonChainExecutors = await ethers.getContractFactory("CommonChainExecutors");
		const commonChainExecutorsContract = await upgrades.deployProxy(
			CommonChainExecutors,
			[addrs[0], [image4, image5, image6, image7]],
			{
				kind: "uups",
				initializer: "__CommonChainExecutors_init",
				constructorArgs: [attestationVerifier.target, 600, token.target]
			},
		);
		commonChainExecutors = getCommonChainExecutors(commonChainExecutorsContract.target as string, signers[0]);

		const CommonChainJobs = await ethers.getContractFactory("CommonChainJobs");
		const commonChainJobsContract = await upgrades.deployProxy(
			CommonChainJobs,
			[addrs[0], commonChainGateways.target, commonChainExecutors.target],
			{
				kind: "uups",
				initializer: "__CommonChainJobs_init",
				constructorArgs: [
					token.target,
					100,
					100,
					3
				]
			},
		);
		commonChainJobs = getCommonChainJobs(commonChainJobsContract.target as string, signers[0]);

		await commonChainExecutors.setJobsContract(commonChainJobs.target);

		let chainIds = [1];
		let reqChains = [
			{
				contractAddress: addrs[1],
				httpRpcUrl: "https://eth.rpc",
				wsRpcUrl: "ws://eth.rpc"
			}
		]
		await commonChainGateways.addChainGlobal(chainIds, reqChains);

		await token.transfer(addrs[1], 100000);
		await token.connect(signers[1]).approve(commonChainGateways.target, 10000);
		await token.connect(signers[1]).approve(commonChainExecutors.target, 10000);

		// REGISTER GATEWAYS
		const timestamp = await time.latest() * 1000,
			stakeAmount = 10;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);
		let signedDigest = await createGatewaySignature(chainIds, wallets[15]);
		await commonChainGateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, chainIds, signedDigest, stakeAmount);
		
		[signature] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
		signedDigest = await createGatewaySignature(chainIds, wallets[16]);
		await commonChainGateways.connect(signers[1]).registerGateway(signature, pubkeys[16], image3.PCR0, image3.PCR1, image3.PCR2, timestamp - 540000, chainIds, signedDigest, stakeAmount);

		// REEGISTER EXECUTORS
		let jobCapacity = 20;
		[signature] = await createAttestation(pubkeys[17], image4, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[17]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[18]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = await createExecutorSignature(jobCapacity, wallets[19]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can reassign after job output not relayed", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			gatewayOperatorOld = addrs[15],
			sequenceId = 1,
			jobRequestTimestamp = await time.latest() + 100;

		let signedDigest = await createReassignGatewaySignature(jobId, gatewayOperatorOld, sequenceId, jobRequestTimestamp, wallets[16]);
		let tx = await commonChainJobs.connect(signers[16]).reassignGatewayRelay(gatewayOperatorOld, jobId, signedDigest, sequenceId, jobRequestTimestamp);
		await expect(tx).to.emit(commonChainJobs, "GatewayReassigned");
	});

	it("cannot reassign for wrong sequenceId", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			gatewayOperatorOld = addrs[15],
			sequenceId = 2,
			jobRequestTimestamp = await time.latest() + 10;

		let signedDigest = await createReassignGatewaySignature(jobId, gatewayOperatorOld, sequenceId, jobRequestTimestamp, wallets[16]);
		let tx = commonChainJobs.connect(signers[16]).reassignGatewayRelay(gatewayOperatorOld, jobId, signedDigest, sequenceId, jobRequestTimestamp);
		await expect(tx).to.revertedWithCustomError(commonChainJobs, "InvalidSequenceId");
	});

	it("cannot reassign after relay time is over", async function () {
		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			gatewayOperatorOld = addrs[15],
			sequenceId = 1,
			jobRequestTimestamp = await time.latest() + 10;

		let signedDigest = await createReassignGatewaySignature(jobId, gatewayOperatorOld, sequenceId, jobRequestTimestamp, wallets[16]);
		
		await time.increase(1000);
		let tx = commonChainJobs.connect(signers[16]).reassignGatewayRelay(gatewayOperatorOld, jobId, signedDigest, sequenceId, jobRequestTimestamp);
		await expect(tx).to.revertedWithCustomError(commonChainJobs, "RelayTimeOver");
	});

	it("cannot reassign new gateway if job is marked as ended due to unavailable executors", async function () {
		await commonChainExecutors.connect(signers[1]).deregisterExecutor(pubkeys[19]);

		let jobId: any = (BigInt(1) << BigInt(192)) + BigInt(1),
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		let signedDigest = await createRelayJobSignature(jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner, wallets[15]);

		await expect(commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner))
			.to.emit(commonChainJobs, "JobResourceUnavailable").withArgs(jobId, addrs[15]);

		let gatewayOperatorOld = addrs[15];
		jobRequestTimestamp = await time.latest() + 10;
		signedDigest = await createReassignGatewaySignature(jobId, gatewayOperatorOld, sequenceId, jobRequestTimestamp, wallets[16]);
		
		// reassign new gateway
		await expect(commonChainJobs.connect(signers[15]).reassignGatewayRelay(gatewayOperatorOld, jobId, signedDigest, sequenceId, jobRequestTimestamp))
			.to.be.revertedWithCustomError(commonChainJobs, "JobMarkedEndedAsResourceUnavailable");
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