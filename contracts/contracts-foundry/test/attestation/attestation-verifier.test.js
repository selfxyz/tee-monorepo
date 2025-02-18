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

const account =
  privateKeyToAccount("0xdc18850da3d958ffe330e8d87937622bb33964972c7030857b19369a6e81ed3d");

const signature = await walletClient.signTypedData({
  account,
  domain: DOMAIN,
  types: TYPES,
  primaryType: 'Attestation',
  message: {
    enclavePubKey: "0x9d17c9747a93e74b4065164eaf1df2e22bd36dc17772cf3fb99bfe6ff47bbd3ce8034234fa46b89c99d6e81393e60e7bcc83680e7b15bfd0fbcb01ae78aa9c76",
    imageId: "0x0000000000000000000000000000000000000000000000000000000000000002",
    timestampInMilliseconds: 0x4e43046b,
  }
});

console.log('Generated signature:', signature);
console.log('Pubkey:', account.publicKey);
