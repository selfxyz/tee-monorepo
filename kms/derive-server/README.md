![Marlin Oyster Logo](./logo.svg)

# KMS Derive Server

The KMS Derive Server provides derivation endpoints to derive secrets. It is meant to be run inside an enclave and used by enclave application to derive secrets like wallets.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.kms.derive-server.<output>
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
$ ./target/release/kms-root-server --help
Usage: kms-root-server [OPTIONS]

Options:
      --randomness-file <RANDOMNESS_FILE>
          Path to encrypted randomness file [default: /app/init-params]
      --scallop-listen-addr <SCALLOP_LISTEN_ADDR>
          Scallop listening address [default: 0.0.0.0:1100]
      --public-listen-addr <PUBLIC_LISTEN_ADDR>
          Public listening address [default: 0.0.0.0:1101]
      --signer <SIGNER>
          Path to file with private key signer [default: /app/secp256k1.sec]
      --porter <PORTER>
          Porter URI [default: https://porter.nucypher.io/decrypt]
      --ritual <RITUAL>
          Ritual id [default: 40]
      --coordinator <COORDINATOR>
          Coordinator address [default: 0xE74259e3dafe30bAA8700238e324b47aC98FE755]
      --rpc <RPC>
          RPC URL [default: https://polygon-rpc.com]
      --attestation-endpoint <ATTESTATION_ENDPOINT>
          Attestation endpoint [default: http://127.0.0.1:1301/attestation/raw]
      --secret-path <SECRET_PATH>
          Path to X25519 secret file [default: /app/x25519.sec]
      --threshold <THRESHOLD>
          DKG threshold [default: 16]
      --delay <DELAY>
          Initial delay to allow for attestation verification [default: 1800]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Endpoints

### Derive

#### Endpoint

`/derive`

#### Usage

```
GET /derive?path=<path>

<binary data of the derived key in response>
```

### Derive secp256k1 key (Ethereum wallet)

#### Endpoint

`/derive/secp256k1`

#### Usage

```
GET /derive/secp256k1?path=<path>

<binary data of the derived key in response>
```

### Derive ed25519 key (Solana wallet)

#### Endpoint

`/derive/ed25519`

#### Usage

```
GET /derive/ed25519?path=<path>

<binary data of the derived key in response>
```

### Derive x25519 key

#### Endpoint

`/derive/x25519`

#### Usage

```
GET /derive/x25519?path=<path>

<binary data of the derived key in response>
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
