![Marlin Oyster Logo](./logo.svg)

# KMS Creator Verifier

The KMS Creator Verifier verifies the generated encrypted seed from the KMS Creator.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.kms.creator-verifier.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## Usage

```
$ ./target/release/creator-verifier --help
Verify creator signatures and recover public keys

Usage: creator-verifier <MESSAGE_HEX>

Arguments:
  <MESSAGE_HEX>  Hex string containing message followed by 65-byte signature

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Example

```
$ ./target/release/creator-verifier 544d4b69000100009293c430807c79fea118542ce3e2af018fc76edb82145192344be25beaaefde850b53843e9373f13fbd5f7e13f67fac11e2a5b15c46099587116f84567ab75e6abf4953cebc1b5096adc8f9705a6dce7c10f6b591310e6b3b16ae3e60b6766f2a114ff2d609c176666edc8d568e4a661f527ba7996c005830bd7c2a21b60e42832f07f0951b49703e8564e5a61a892c8f4755cbd7361c4506c38084df743fd0b1244d5a0d6e93e9f27cc0d1a10792cb255e9c75c85872161f772574bebbc9b2c4352b4685b3ee2cd161fb301fb09d4efd8a87ad5918216fc4a41d542576b3d0bfabcaa141b15b63c9292c430868c3d012a5d524f0939e4ee4d60b738b4c44448ec286a5361e15ffbf2641e2df25363a204a738231e5f1a9621999741da01b87b22636f6e646974696f6e223a7b22636861696e223a312c22636f6e646974696f6e54797065223a22636f6e7472616374222c22636f6e747261637441646472657373223a22307843653735446232423235453061393636423634453337433232343646373065336133464630393439222c2266756e6374696f6e416269223a7b22696e70757473223a5b7b22696e7465726e616c54797065223a2261646472657373222c226e616d65223a22222c2274797065223a2261646472657373227d5d2c226e616d65223a2269735665726966696564222c226f757470757473223a5b7b22696e7465726e616c54797065223a22626f6f6c222c226e616d65223a22222c2274797065223a22626f6f6c227d5d2c2273746174654d75746162696c697479223a2276696577222c2274797065223a2266756e6374696f6e227d2c226d6574686f64223a2269735665726966696564222c22706172616d6574657273223a5b223a7573657241646472657373225d2c2272657475726e56616c756554657374223a7b22636f6d70617261746f72223a223d3d222c2276616c7565223a747275657d7d2c2276657273696f6e223a22312e302e30227dc441b4fc1206b3290a1da56ab118df0cf9e660c1bb069ae71edf32f0f7d4743f51061e861476e8a67d2b92d42559af3b6aac310785408a658d53765395ac8be2783c1c2e0e7188b594e150f11891912b282cac3a565dca5b6bc23acc7bb5e6a0fe509e45f9bdf2cb41226b8d47ed33d01718939606924beb96720f48cc72697f4832221c
Recovered msg: 544d4b69000100009293c430807c79fea118542ce3e2af018fc76edb82145192344be25beaaefde850b53843e9373f13fbd5f7e13f67fac11e2a5b15c46099587116f84567ab75e6abf4953cebc1b5096adc8f9705a6dce7c10f6b591310e6b3b16ae3e60b6766f2a114ff2d609c176666edc8d568e4a661f527ba7996c005830bd7c2a21b60e42832f07f0951b49703e8564e5a61a892c8f4755cbd7361c4506c38084df743fd0b1244d5a0d6e93e9f27cc0d1a10792cb255e9c75c85872161f772574bebbc9b2c4352b4685b3ee2cd161fb301fb09d4efd8a87ad5918216fc4a41d542576b3d0bfabcaa141b15b63c9292c430868c3d012a5d524f0939e4ee4d60b738b4c44448ec286a5361e15ffbf2641e2df25363a204a738231e5f1a9621999741da01b87b22636f6e646974696f6e223a7b22636861696e223a312c22636f6e646974696f6e54797065223a22636f6e7472616374222c22636f6e747261637441646472657373223a22307843653735446232423235453061393636423634453337433232343646373065336133464630393439222c2266756e6374696f6e416269223a7b22696e70757473223a5b7b22696e7465726e616c54797065223a2261646472657373222c226e616d65223a22222c2274797065223a2261646472657373227d5d2c226e616d65223a2269735665726966696564222c226f757470757473223a5b7b22696e7465726e616c54797065223a22626f6f6c222c226e616d65223a22222c2274797065223a22626f6f6c227d5d2c2273746174654d75746162696c697479223a2276696577222c2274797065223a2266756e6374696f6e227d2c226d6574686f64223a2269735665726966696564222c22706172616d6574657273223a5b223a7573657241646472657373225d2c2272657475726e56616c756554657374223a7b22636f6d70617261746f72223a223d3d222c2276616c7565223a747275657d7d2c2276657273696f6e223a22312e302e30227dc441b4fc1206b3290a1da56ab118df0cf9e660c1bb069ae71edf32f0f7d4743f51061e861476e8a67d2b92d42559af3b6aac310785408a658d53765395ac8be2783c1c
Recovered pubkey: 049d164dd16932d4587ecf909aa12e192e5139c7901296a65b4df44b471f3231883b276fe321d878e4ec4bf836feccb96f6cd7d23fb5311cc1a01b814168c197e6
Recovered address: 0x89E3fEb849bE0A29891DC2030293A23A84bAc0C8
Base64 seed: VE1LaQABAACSk8QwgHx5/qEYVCzj4q8Bj8du24IUUZI0S+Jb6q796FC1OEPpNz8T+9X34T9n+sEeKlsVxGCZWHEW+EVnq3Xmq/SVPOvBtQlq3I+XBabc58EPa1kTEOazsWrj5gtnZvKhFP8tYJwXZmbtyNVo5KZh9Se6eZbABYML18KiG2DkKDLwfwlRtJcD6FZOWmGoksj0dVy9c2HEUGw4CE33Q/0LEkTVoNbpPp8nzA0aEHksslXpx1yFhyFh93JXS+u8myxDUrRoWz7izRYfswH7CdTv2Kh61ZGCFvxKQdVCV2s9C/q8qhQbFbY8kpLEMIaMPQEqXVJPCTnk7k1gtzi0xERI7ChqU2HhX/vyZB4t8lNjogSnOCMeXxqWIZmXQdoBuHsiY29uZGl0aW9uIjp7ImNoYWluIjoxLCJjb25kaXRpb25UeXBlIjoiY29udHJhY3QiLCJjb250cmFjdEFkZHJlc3MiOiIweENlNzVEYjJCMjVFMGE5NjZCNjRFMzdDMjI0NkY3MGUzYTNGRjA5NDkiLCJmdW5jdGlvbkFiaSI6eyJpbnB1dHMiOlt7ImludGVybmFsVHlwZSI6ImFkZHJlc3MiLCJuYW1lIjoiIiwidHlwZSI6ImFkZHJlc3MifV0sIm5hbWUiOiJpc1ZlcmlmaWVkIiwib3V0cHV0cyI6W3siaW50ZXJuYWxUeXBlIjoiYm9vbCIsIm5hbWUiOiIiLCJ0eXBlIjoiYm9vbCJ9XSwic3RhdGVNdXRhYmlsaXR5IjoidmlldyIsInR5cGUiOiJmdW5jdGlvbiJ9LCJtZXRob2QiOiJpc1ZlcmlmaWVkIiwicGFyYW1ldGVycyI6WyI6dXNlckFkZHJlc3MiXSwicmV0dXJuVmFsdWVUZXN0Ijp7ImNvbXBhcmF0b3IiOiI9PSIsInZhbA==
Secp256k1 pubkey: 7565223a747275657d7d2c2276657273696f6e223a22312e302e30227dc441b4fc1206b3290a1da56ab118df0cf9e660c1bb069ae71edf32f0f7d4743f51061e
Secp256k1 address: 0x5A606e0C8E106FDC6085e35F5FF725aBb6Ba4CD4
X25519 pubkey: 861476e8a67d2b92d42559af3b6aac310785408a658d53765395ac8be2783c1c
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
