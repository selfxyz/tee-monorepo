import { time } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from "chai";
import { BytesLike, Signer, Wallet, ZeroAddress, keccak256, parseUnits, solidityPacked } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationAutherUpgradeable, AttestationVerifier, Pond, Relay, User } from "../../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../../utils/testSuite";
import { getAttestationVerifier, getPond, getRelay, getUser } from '../../utils/typechainConvertor';

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

function getImageId(image: AttestationAutherUpgradeable.EnclaveImageStruct): string {
	return keccak256(solidityPacked(["bytes", "bytes", "bytes"], [image.PCR0, image.PCR1, image.PCR2]));
}

describe("Relay - Init", function () {
	let signers: Signer[];
	let addrs: string[];
	let attestationVerifier: string;
	let token: string;

	before(async function () {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		attestationVerifier = addrs[1];
		token = addrs[1];
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("deploys with initialization disabled", async function () {

		const Relay = await ethers.getContractFactory("Relay");
		const relay = await Relay.deploy(attestationVerifier, 500, token, 100, 500, 1000);

		await expect(
			relay.initialize(addrs[0], [image1]),
		).to.be.revertedWithCustomError(Relay, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function () {
		const Relay = await ethers.getContractFactory("Relay");
		const relay = await upgrades.deployProxy(
			Relay,
			[addrs[0], [image1]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					attestationVerifier, 
					100,
					token,
					100,
					500,
					1000
				]
			},
		);

		expect(await relay.hasRole(await relay.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
	});

	it("cannot initialize with zero address as admin", async function () {
		const Relay = await ethers.getContractFactory("Relay");
		await expect(
			upgrades.deployProxy(
				Relay,
				[ZeroAddress, [image1]],
				{
					kind: "uups",
					initializer: "initialize",
					constructorArgs: [
						attestationVerifier,
						500,
						token,
						10,
						1000,
						1000
					]
				},
			)
		).to.be.revertedWithCustomError(Relay, "ZeroAddressAdmin");
	});

	it("upgrades", async function () {
		const Relay = await ethers.getContractFactory("Relay");
		const relay = await upgrades.deployProxy(
			Relay,
			[addrs[0], [image1]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					attestationVerifier,
					100,
					token,
					10,
					1000,
					1000
				]
			},
		);
		await upgrades.upgradeProxy(
			relay.target,
			Relay,
			{
				kind: "uups",
				constructorArgs: [
					attestationVerifier,
					100,
					token,
					10,
					1000,
					1000
				]
			}
		);

		expect(await relay.hasRole(await relay.DEFAULT_ADMIN_ROLE(), addrs[0])).to.be.true;
	});

	it("does not upgrade without admin", async function () {
		const Relay = await ethers.getContractFactory("Relay");
		const relay = await upgrades.deployProxy(
			Relay,
			[addrs[0], [image1]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					attestationVerifier,
					100,
					token,
					10,
					1000,
					1000
				]
			},
		);

		await expect(
			upgrades.upgradeProxy(relay.target, Relay.connect(signers[1]), {
				kind: "uups",
				constructorArgs: [
					attestationVerifier,
					100,
					token,
					10,
					1000,
					1000
				]
			}),
		).to.be.revertedWithCustomError(Relay, "AccessControlUnauthorizedAccount");
	});
});

describe("Relay - Register gateway", function () {
	let signers: Signer[];
	let addrs: string[];
	let wallets: Wallet[];
	let pubkeys: string[];
	let token: Pond;
	let attestationVerifier: AttestationVerifier;
	let relay: Relay;

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

		const Relay = await ethers.getContractFactory("Relay");
		const relayContract = await upgrades.deployProxy(
			Relay,
			[addrs[0], [image1, image2]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					attestationVerifier.target, 
					600, 
					token.target, 
					600,
					1000,
					1000
				]
			},
		);
		relay = getRelay(relayContract.target as string, signers[0]);

	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can register gateway", async function () {
		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		await expect(relay.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000))
			.to.emit(relay, "GatewayRegistered").withArgs(addrs[15], addrs[1]);
		expect(await relay.getVerifiedKey(addrs[15])).to.equal(getImageId(image2));
	});

	it("cannot register gateway with same enclaveKey twice", async function () {
		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		await expect(relay.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000))
			.to.emit(relay, "GatewayRegistered").withArgs(addrs[15], addrs[1]);

		await expect(relay.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000))
			.to.revertedWithCustomError(relay, "GatewayAlreadyExists");
	});

	it('can deregister gateway', async function () {
		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		await relay.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000);

		await expect(relay.connect(signers[1]).deregisterGateway(pubkeys[15]))
			.to.emit(relay, "GatewayDeregistered").withArgs(addrs[15]);
	});

	it('cannot deregister gateway without gateway operator', async function () {
		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		await relay.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000);

		await expect(relay.connect(signers[2]).deregisterGateway(pubkeys[15]))
			.to.revertedWithCustomError(relay, "InvalidGatewayOperator");
	});

});

describe("Relay - Relay Job", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let relay: Relay;

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

		const Relay = await ethers.getContractFactory("Relay");
		const relayContract = await upgrades.deployProxy(
			Relay,
			[addrs[0], [image1, image2]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					attestationVerifier.target,
					600,
					token.target,
					100,
					1000,
					1000
				]
			},
		);
		relay = getRelay(relayContract.target as string, signers[0]);

		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		await relay.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can relay job", async function () {
		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			userTimeout = 500000,
			maxGasPrice = 100,
			usdcDeposit = 100,
			callbackDeposit = 100;
		let tx = await relay.connect(signers[15]).relayJob(codeHash, codeInputs, userTimeout, maxGasPrice, usdcDeposit, callbackDeposit);
		await expect(tx).to.emit(relay, "JobRelayed");

		let key = await relay.jobCount();
		let job = await relay.jobs(key);

		expect(job.jobOwner).to.eq(addrs[15]);
	});

	it("cannot relay job with invalid user timeout", async function () {
		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			userTimeout = 500,
			maxGasPrice = 100,
			usdcDeposit = 100,
			callbackDeposit = 100;
		let tx = relay.connect(signers[15]).relayJob(codeHash, codeInputs, userTimeout, maxGasPrice, usdcDeposit, callbackDeposit);
		await expect(tx).to.revertedWithCustomError(relay, "InvalidUserTimeout");
	});
});

describe("Relay - Job Response", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let relay: Relay;

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

		const Relay = await ethers.getContractFactory("Relay");
		const relayContract = await upgrades.deployProxy(
			Relay,
			[addrs[0], [image1, image2]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					attestationVerifier.target,
					600,
					token.target,
					100,
					1000,
					1000
				]
			},
		);
		relay = getRelay(relayContract.target as string, signers[0]);

		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		await relay.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000);
	
		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			userTimeout = 500000,
			maxGasPrice = 100,
			usdcDeposit = 100,
			callbackDeposit = 100;
		await relay.connect(signers[15]).relayJob(codeHash, codeInputs, userTimeout, maxGasPrice, usdcDeposit, callbackDeposit);
		
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can submit response", async function () {
		let jobId: any = await relay.jobCount(),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, wallets[15]);
		let tx = relay.jobResponse(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.emit(relay, "JobResponded"); 
	});

	it("cannot submit response twice", async function () {
		let jobId: any = await relay.jobCount(),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, wallets[15]);
		let tx = relay.jobResponse(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.emit(relay, "JobResponded"); 

		let tx2 = relay.jobResponse(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx2).to.revertedWithCustomError(relay, "JobNotExists");
	});

	it("cannot submit output from unverified gateway", async function () {
		let jobId: any = await relay.jobCount(),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, wallets[16]);
		let tx = relay.jobResponse(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.revertedWithCustomError(relay, "AttestationAutherKeyNotVerified"); 
	});

	it("cannot submit response after overall timeout if over", async function () {
		await time.increase(1100);
		let jobId: any = await relay.jobCount(),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, wallets[15]);
		let tx = relay.jobResponse(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.revertedWithCustomError(relay, "OverallTimeoutOver"); 
	});

});

describe("Relay - Job Cancel", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let relay: Relay;

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

		const Relay = await ethers.getContractFactory("Relay");
		const relayContract = await upgrades.deployProxy(
			Relay,
			[addrs[0], [image1, image2]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					attestationVerifier.target,
					600,
					token.target,
					100,
					1000,
					1000
				]
			},
		);
		relay = getRelay(relayContract.target as string, signers[0]);

		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		await relay.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000);
	
		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			userTimeout = 500000,
			maxGasPrice = 100,
			usdcDeposit = 100,
			callbackDeposit = 100;
		await relay.connect(signers[15]).relayJob(codeHash, codeInputs, userTimeout, maxGasPrice, usdcDeposit, callbackDeposit);
		
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("cannot cancel after job response", async function () {
		let jobId: any = await relay.jobCount(),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, wallets[15]);
		await expect(
			relay.jobResponse(signedDigest, jobId, output, totalTime, errorCode)
		).to.emit(relay, "JobResponded"); 

		await expect(
			relay.connect(signers[15]).jobCancel(jobId)
		).to.be.revertedWithCustomError(relay, "InvalidJobOwner");
	});

	it("cannot cancel before overall timeout", async function () {
		let jobId: any = await relay.jobCount();

		await expect(
			relay.connect(signers[15]).jobCancel(jobId)
		).to.revertedWithCustomError(relay, "OverallTimeoutNotOver");
	});

	it("cannot cancel from other any other account except job owner", async function () {
		let jobId: any = await relay.jobCount();
		await time.increase(1100);

		await expect(
			relay.jobCancel(jobId)
		).to.revertedWithCustomError(relay, "InvalidJobOwner");
	});

	it("can cancel from job owner account after overall timeout", async function () {
		let jobId: any = await relay.jobCount();
		await time.increase(1100);

		await expect(
			relay.connect(signers[15]).jobCancel(jobId)
		).to.emit(relay, "JobCancelled").withArgs(jobId);

		let job = await relay.jobs(jobId);
		expect(job.jobOwner).to.eq(ZeroAddress);
	});

});

describe("Relay - Job sent by User contract", function () {
	let signers: Signer[];
	let addrs: string[];
	let token: Pond;
	let wallets: Wallet[];
	let pubkeys: string[];
	let attestationVerifier: AttestationVerifier;
	let relay: Relay;
	let user: User;

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

		const Relay = await ethers.getContractFactory("Relay");
		const relayContract = await upgrades.deployProxy(
			Relay,
			[addrs[0], [image1, image2]],
			{
				kind: "uups",
				initializer: "initialize",
				constructorArgs: [
					attestationVerifier.target,
					600,
					token.target,
					100,
					1000,
					1000
				]
			},
		);
		relay = getRelay(relayContract.target as string, signers[0]);

		const timestamp = await time.latest() * 1000;
		let [signature] = await createAttestation(pubkeys[15], image2, wallets[14], timestamp - 540000);

		await relay.connect(signers[1]).registerGateway(signature, pubkeys[15], image2.PCR0, image2.PCR1, image2.PCR2, timestamp - 540000);
	
		const User = await ethers.getContractFactory("User");
		const userContract = await User.deploy(relay);
		user = getUser(userContract.target as string, signers[0]);		
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can submit response and execute callback", async function () {
		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			userTimeout = 500000,
			maxGasPrice = 100,
			usdcDeposit = 100,
			callbackDeposit = parseUnits("1");	// 1 eth
		await user.relayJob(
			codeHash, codeInputs, userTimeout, maxGasPrice, usdcDeposit, callbackDeposit, 
			{value: callbackDeposit}
		);

		let jobId: any = await relay.jobCount(),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;
		
		let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, wallets[15]);
		let tx = relay.connect(signers[1]).jobResponse(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.emit(user, "CalledBack").and.to.emit(relay, "JobResponded");
	});

	it("can submit response but fails to execute callback due to less callbackDeposit", async function () {
		let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
			codeInputs = solidityPacked(["string"], ["codeInput"]),
			userTimeout = 500000,
			maxGasPrice = 100,
			usdcDeposit = 100,
			callbackDeposit = 1;	// 1 wei
		await user.relayJob(
			codeHash, codeInputs, userTimeout, maxGasPrice, usdcDeposit, callbackDeposit, 
			{value: callbackDeposit}
		);

		let jobId: any = await relay.jobCount(),
			output = solidityPacked(["string"], ["it is the output"]),
			totalTime = 100,
			errorCode = 0;

		let signedDigest = await createJobResponseSignature(jobId, output, totalTime, errorCode, wallets[15]);
		let tx = relay.connect(signers[1]).jobResponse(signedDigest, jobId, output, totalTime, errorCode);
		await expect(tx).to.emit(relay, "JobResponded").and.to.not.emit(user, "CalledBack");
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

async function createJobResponseSignature(
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

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
}