import { BytesLike, getBytes, keccak256, parseUnits, solidityPacked, Wallet } from "ethers";
import { ethers, upgrades } from "hardhat";
import { AttestationVerifier, Relay } from "../typechain-types";

async function main() {
    //Create Enclave Image object
    const img = {
        PCR0 : getBytes("0xcfa7554f87ba13620037695d62a381a2d876b74c2e1b435584fe5c02c53393ac1c5cd5a8b6f92e866f9a65af751e0462"),
        PCR1 : getBytes("0xbcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f"),
        PCR2 : getBytes("0x20caae8a6a69d9b1aecdf01a0b9c5f3eafd1f06cb51892bf47cef476935bfe77b5b75714b68a69146d650683a217c5b3"),
    };

    let wallet = walletForIndex(0);
    console.log("Attestation Verifer Enclave Private Key: ", wallet.signingKey.privateKey);
    let enclavePubKey = normalize(wallet.signingKey.publicKey);
    console.log("Attestation Verifer Enclave Public Key: ", enclavePubKey);
    // Admin address
    let signers = await ethers.getSigners();
    let admin_addr = await signers[0].getAddress();
    
    let relay_addr = "0xD02e33f98a08030B72A471Ae41e696a57cFecCc8";
    let usdc_token_addr = "0xD330cF76192274bb3f10f2E574a1bDba4ED29352";

    const Relay = await ethers.getContractFactory("Relay");
    let relay = Relay.attach(relay_addr);

    const USDCoin = await ethers.getContractFactory("USDCoin");
    let usdc_token = USDCoin.attach(usdc_token_addr);

    let gatewayWallet = walletForIndex(1);
    let gatewayEnclaveKey = normalize(gatewayWallet.signingKey.publicKey);
    console.log("Gateway Enclave Private Key: ", gatewayWallet.signingKey.privateKey);
    console.log("Gateway Enclave Public Key: ", gatewayEnclaveKey);
    let time = new Date();
    let timestamp = time.getTime();
    console.log(timestamp);
    let [signature, attestation] = await createAttestation(gatewayEnclaveKey, img, wallet, timestamp);

    time = new Date();
    let signTimestamp = Math.floor(time.getTime() / 1000);
    let signedDigest = await createGatewaySignature(admin_addr, signTimestamp, gatewayWallet);

    // register enclave
    console.log(signature, attestation, signedDigest, signTimestamp);
    await relay.registerGateway(signature, attestation, signedDigest, signTimestamp);
    console.log("Gateway registered");
    await usdc_token.approve(relay.target, 1000000);
    console.log("USDCoin approved");

    let codeHash = keccak256(solidityPacked(["string"], ["codehash"])),
        codeInputs = solidityPacked(["string"], ["codeInput"]),
        userTimeout = 100,
        maxGasPrice = parseUnits("2", 9),
        callbackDeposit = parseUnits("1", 15),
        refundAccount = admin_addr,
        callbackContract = admin_addr,
        callbackGasLimit = 0;
        console.log("callbackDeposit: ", callbackDeposit, maxGasPrice)
	await relay.relayJob(
		codeHash, codeInputs, userTimeout, maxGasPrice, refundAccount, callbackContract, callbackGasLimit, 
		{ value: callbackDeposit }
	);
	console.log("Job relayed");
        
    // job response
    let jobId: any = await relay.jobCount(),
        output = solidityPacked(["string"], ["it is the output"]),
        totalTime = 100,
        errorCode = 0;
    time = new Date();
    signTimestamp = Math.floor(time.getTime() / 1000);
    
    signedDigest = await createJobResponseSignature(
        jobId, output, totalTime, errorCode, signTimestamp, gatewayWallet
    );
    console.log(signedDigest, jobId, output, totalTime, errorCode, signTimestamp);
    await relay.jobResponse(signedDigest, jobId, output, totalTime, errorCode, signTimestamp, {maxFeePerGas: 2n * maxGasPrice + 1n, maxPriorityFeePerGas: maxGasPrice + 1n});
    console.log("Job response relayed");
}

function normalize(key: string): string {
	return '0x' + key.substring(4);
}

function walletForIndex(idx: number): Wallet {
	let wallet = ethers.HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/" + idx.toString());

	return new Wallet(wallet.privateKey);
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
	owner: string,
	signTimestamp: number,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const domain = {
		name: 'marlin.oyster.Relay',
		version: '1',
	};

	const types = {
		Register: [
			{ name: 'owner', type: 'address' },
			{ name: 'signTimestamp', type: 'uint256' }
		]
	};

	const value = {
		owner,
		signTimestamp
	};

	const sign = await sourceEnclaveWallet.signTypedData(domain, types, value);
	return ethers.Signature.from(sign).serialized;
}

async function createJobResponseSignature(
	jobId: number,
    output: string,
	totalTime: number,
    errorCode: number,
	signTimestamp: number,
	sourceEnclaveWallet: Wallet
): Promise<string> {
	const domain = {
		name: 'marlin.oyster.Relay',
		version: '1'
	};

	const types = {
		JobResponse: [
			{ name: 'jobId', type: 'uint256' },
			{ name: 'output', type: 'bytes' },
			{ name: 'totalTime', type: 'uint256' },
			{ name: 'errorCode', type: 'uint8' },
			{ name: 'signTimestamp', type: 'uint256' }
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

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });