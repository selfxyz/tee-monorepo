import { joinSignature } from '@ethersproject/bytes';
import { Wallet } from '@ethersproject/wallet';
import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, ZeroAddress, keccak256, solidityPacked } from "ethers";
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
		expect(await commonChainJobs.getRoleMemberCount(await commonChainJobs.DEFAULT_ADMIN_ROLE())).to.equal(1);
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
		).to.be.revertedWith("ZERO_ADDRESS_ADMIN");
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
		expect(await commonChainJobs.getRoleMemberCount(await commonChainJobs.DEFAULT_ADMIN_ROLE())).to.equal(1);
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
		).to.be.revertedWith("only admin");
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
		pubkeys = wallets.map((w) => normalize(w.publicKey));

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
				constructorArgs: [attestationVerifier.target, 600, token.target]
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
				rpcUrl: "https://eth.rpc"
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
		let signedDigest = createExecutorSignature(jobCapacity, wallets[17]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = createExecutorSignature(jobCapacity, wallets[18]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = createExecutorSignature(jobCapacity, wallets[19]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		signedDigest = createExecutorSignature(jobCapacity, wallets[20]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can relay job", async function () {
		let jobId = 1,
			reqChainId = 1,
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		const message = solidityPacked(
			["uint256", "uint256", "bytes32", "bytes", "uint256", "uint256", "uint8", "address"],
			[jobId, reqChainId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner],
		);
		const digest = keccak256(message);
		let sign = wallets[15]._signingKey().signDigest(digest);
		let signedDigest = joinSignature(sign);

		let tx = await commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, reqChainId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);
		await expect(tx).to.emit(commonChainJobs, "JobRelayed");

		let key = await commonChainJobs.getKey(jobId, reqChainId);
		let job = await commonChainJobs.jobs(key);

		expect(job.jobId).to.eq(jobId);
		expect(job.jobOwner).to.eq(jobOwner);
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
		pubkeys = wallets.map((w) => normalize(w.publicKey));

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
				constructorArgs: [attestationVerifier.target, 600, token.target]
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
				rpcUrl: "https://eth.rpc"
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
		let signedDigest = createExecutorSignature(jobCapacity, wallets[17]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = createExecutorSignature(jobCapacity, wallets[18]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = createExecutorSignature(jobCapacity, wallets[19]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		// [signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		// signedDigest = createExecutorSignature(jobCapacity, wallets[20]);
		// await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
		
		// RELAY JOB
		let jobId = 1,
			reqChainId = 1,
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		const message = solidityPacked(
			["uint256", "uint256", "bytes32", "bytes", "uint256", "uint256", "uint8", "address"],
			[jobId, reqChainId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner],
		);
		const digest = keccak256(message);
		let sign = wallets[15]._signingKey().signDigest(digest);
		signedDigest = joinSignature(sign);
	
		await commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, reqChainId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can submit output by selected executor node", async function () {
		let jobId = 1,
			reqChainId = 1,
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = createOutputSignature(jobId, reqChainId, output, totalTime, errorCode, wallets[17]);
		let tx = await commonChainJobs.submitOutput(signedDigest, jobId, reqChainId, output, totalTime, errorCode);
		await expect(tx).to.emit(commonChainJobs, "JobResponded"); 
	});

	it("cannot submit output twice", async function () {
		let jobId = 1,
			reqChainId = 1,
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = createOutputSignature(jobId, reqChainId, output, totalTime, errorCode, wallets[17]);
		let tx = await commonChainJobs.submitOutput(signedDigest, jobId, reqChainId, output, totalTime, errorCode);
		await expect(tx).to.emit(commonChainJobs, "JobResponded"); 

		let tx2 = commonChainJobs.submitOutput(signedDigest, jobId, reqChainId, output, totalTime, errorCode);
		await expect(tx2).to.revertedWith("EXECUTOR_ALREADY_SUBMITTED_OUTPUT");
	});

	it("cannot submit output from unselected executor node", async function () {
		let jobCapacity = 20,
			stakeAmount = 10,
			timestamp = await time.latest() * 1000;
		let [signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		let signedDigest = createExecutorSignature(jobCapacity, wallets[20]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
		
		let jobId = 1,
			reqChainId = 1,
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		signedDigest = createOutputSignature(jobId, reqChainId, output, totalTime, errorCode, wallets[20]);
		let tx = commonChainJobs.submitOutput(signedDigest, jobId, reqChainId, output, totalTime, errorCode);
		await expect(tx).to.revertedWith("NOT_SELECTED_EXECUTOR"); 
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
		pubkeys = wallets.map((w) => normalize(w.publicKey));

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
				constructorArgs: [attestationVerifier.target, 600, token.target]
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
				rpcUrl: "https://eth.rpc"
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
		let signedDigest = createExecutorSignature(jobCapacity, wallets[17]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = createExecutorSignature(jobCapacity, wallets[18]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature, attestation] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = createExecutorSignature(jobCapacity, wallets[19]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		// [signature, attestation] = await createAttestation(pubkeys[20], image7, wallets[14], timestamp - 540000);
		// signedDigest = createExecutorSignature(jobCapacity, wallets[20]);
		// await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[20], image7.PCR0, image7.PCR1, image7.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);
		
		// RELAY JOB
		let jobId = 1,
			reqChainId = 1,
			codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			deadline = await time.latest() + 10000,
			jobRequestTimestamp = await time.latest(),
			sequenceId = 1,
			jobOwner = addrs[1];
		const message = solidityPacked(
			["uint256", "uint256", "bytes32", "bytes", "uint256", "uint256", "uint8", "address"],
			[jobId, reqChainId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner],
		);
		const digest = keccak256(message);
		let sign = wallets[15]._signingKey().signDigest(digest);
		signedDigest = joinSignature(sign);
	
		await commonChainJobs.connect(signers[15]).relayJob(signedDigest, jobId, reqChainId, codeHash, codeInputs, deadline, jobRequestTimestamp, sequenceId, jobOwner);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can slash after deadline over", async function () {
		await time.increase(await time.latest() + 100000);
		let jobId = 1,
			reqChainId = 1;
		let tx = await commonChainJobs.slashOnExecutionTimeout(jobId, reqChainId);
		await expect(tx).to.emit(commonChainJobs, "SlashedOnExecutionTimeout");
	});

	it("cannot slash before deadline over", async function () {
		await time.increase(await time.latest() + 10000);
		let jobId = 1,
			reqChainId = 1;
		let tx = commonChainJobs.slashOnExecutionTimeout(jobId, reqChainId);
		await expect(tx).to.revertedWith("DEADLINE_NOT_OVER");
	});

	it("cannot slash twice", async function () {
		await time.increase(await time.latest() + 100000);
		let jobId = 1,
			reqChainId = 1;
		let tx = await commonChainJobs.slashOnExecutionTimeout(jobId, reqChainId);
		await expect(tx).to.emit(commonChainJobs, "SlashedOnExecutionTimeout");

		let tx2 = commonChainJobs.slashOnExecutionTimeout(jobId, reqChainId);
		await expect(tx2).to.revertedWith("INVALID_JOB");
	});

	it("cannot slash non-existing job", async function () {
		let jobId = 2,
			reqChainId = 1;
		let tx = commonChainJobs.slashOnExecutionTimeout(jobId, reqChainId);
		await expect(tx).to.revertedWith("INVALID_JOB");
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
		pubkeys = wallets.map((w) => normalize(w.publicKey));

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
				constructorArgs: [attestationVerifier.target, 600, token.target]
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
				rpcUrl: "https://eth.rpc"
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
		let signedDigest = createGatewaySignature(chainIds, wallets[15]);
		await commonChainGateways.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000, chainIds, signedDigest, stakeAmount);
		
		[signature] = await createAttestation(pubkeys[16], image3, wallets[14], timestamp - 540000);
		signedDigest = createGatewaySignature(chainIds, wallets[16]);
		await commonChainGateways.connect(signers[1]).registerGateway(signature, pubkeys[16], image3.PCR0, image3.PCR1, image3.PCR2, timestamp - 540000, chainIds, signedDigest, stakeAmount);

		// REEGISTER EXECUTORS
		let jobCapacity = 20;
		[signature] = await createAttestation(pubkeys[17], image4, wallets[14], timestamp - 540000);
		signedDigest = createExecutorSignature(jobCapacity, wallets[17]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[17], image4.PCR0, image4.PCR1, image4.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature] = await createAttestation(pubkeys[18], image5, wallets[14], timestamp - 540000);
		signedDigest = createExecutorSignature(jobCapacity, wallets[18]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[18], image5.PCR0, image5.PCR1, image5.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

		[signature] = await createAttestation(pubkeys[19], image6, wallets[14], timestamp - 540000);
		signedDigest = createExecutorSignature(jobCapacity, wallets[19]);
		await commonChainExecutors.connect(signers[1]).registerExecutor(signature, pubkeys[19], image6.PCR0, image6.PCR1, image6.PCR2, timestamp - 540000, jobCapacity, signedDigest, stakeAmount);

	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can reassign after job output not relayed", async function () {
		let jobId = 1,
			reqChainId = 1,
			gatewayOperatorOld = addrs[15],
			sequenceId = 1;

		let signedDigest = createReassignGatewaySignature(jobId, reqChainId, gatewayOperatorOld, sequenceId, wallets[16]);
		let tx = await commonChainJobs.connect(signers[16]).reassignGatewayRelay(gatewayOperatorOld, jobId, reqChainId, signedDigest, sequenceId);
		await expect(tx).to.emit(commonChainJobs, "GatewayReassigned");
	});

	it("cannot reassign for wrong sequenceId", async function () {
		let jobId = 1,
			reqChainId = 1,
			gatewayOperatorOld = addrs[15],
			sequenceId = 2;

		let signedDigest = createReassignGatewaySignature(jobId, reqChainId, gatewayOperatorOld, sequenceId, wallets[16]);
		let tx = commonChainJobs.connect(signers[16]).reassignGatewayRelay(gatewayOperatorOld, jobId, reqChainId, signedDigest, sequenceId);
		await expect(tx).to.revertedWith("INVALID_SEQUENCE_ID");
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

function createExecutorSignature(
	jobCapacity: number,
	sourceEnclaveWallet: Wallet
): string {
	const message = solidityPacked(
		["uint256"],
		[jobCapacity],
	);
	const digest = keccak256(message);
	let sign = sourceEnclaveWallet._signingKey().signDigest(digest);
	let signedDigest = joinSignature(sign);
	return signedDigest;
}

function createOutputSignature(
	jobId: number,
	reqChainId: number,
    output: string,
	totalTime: number,
    errorCode: number,
	sourceEnclaveWallet: Wallet
): string {
	const message = solidityPacked(
		["uint256", "uint256", "bytes", "uint256", "uint8"],
		[jobId, reqChainId, output, totalTime, errorCode],
	);
	const digest = keccak256(message);
	let sign = sourceEnclaveWallet._signingKey().signDigest(digest);
	let signedDigest = joinSignature(sign);
	return signedDigest;
}

function createReassignGatewaySignature(
	jobId: number,
	reqChainId: number,
    gatewayOperatorOld: string,
	sequenceId: number,
	sourceEnclaveWallet: Wallet
): string {
	const message = solidityPacked(
		["uint256", "uint256", "address", "uint8"],
		[jobId, reqChainId, gatewayOperatorOld, sequenceId],
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
