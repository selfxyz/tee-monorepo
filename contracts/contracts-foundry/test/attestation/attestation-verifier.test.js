import { createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

const walletClient = createWalletClient({
  chain: foundry,
  transport: http(""),
});

const DOMAIN = {
  name: 'marlin.oyster.AttestationVerifier',
  version: '1',
};

const TYPES = {
  Attestation: [
    { name: 'enclavePubKey', type: 'bytes' },
    { name: 'imageId', type: 'bytes32' },
    { name: 'timestampInMilliseconds', type: 'uint256' },
  ],
};

async function main() {
  const signature = await walletClient.signTypedData({
    account: privateKeyToAccount("0x900ae318f7deaf644fe51b89fb372c742cdcdf9baa606957c03b07cc0bd4d01d"),
    domain: DOMAIN,
    types: TYPES,
    primaryType: 'Attestation',
    message: {
      enclavePubKey: "0xf0fe0d77cffb34d4b71cd8dd9c237d56edaa95945a621236f9893316cd6ed407d8b87ac388d0f210c5f3261e4c2b33e29b0045320e3c719554ea376e44cc5d6b",
      imageId: "0xd8b87ac388d0f210c5f3261e4c2b33e29b0045320e3c719554ea376e44cc5d6b",
      timestampInMilliseconds: "0x4e43046b",
    }
  });

  console.log('Generated signature:', signature);
}

main().catch(console.error);
