![Marlin Oyster Logo](./logo.svg)

# Oyster Serverless Gateway

Monitors jobs on Request Chains and transfers them to the Common Chain for Executors to process. Once Executors respond to the jobs on the Common Chain, the Gateway forwards the responses back to the original Request Chain.

## Build
```
cargo build --target x86_64-unknown-linux-musl
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.serverless.gateway.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

# Dev Setup

- Clone the repository.
- Build the binary -
  ```
  cargo build --target x86_64-unknown-linux-musl
  ```
- Run the binary -
  ```
  ./target/x86_64-unknown-linux-musl/release/serverless-gateway
  ```
- Update the config with the contract addresses -
  ```json
  {
    "common_chain_id": 31337,
    "common_chain_http_url": "http://127.0.0.1:8545/",
    "common_chain_ws_url": "ws://127.0.0.1:8545/",
    "gateways_contract_addr": "0x610178dA211FEF7D417bC0e6FeD39F05609AD788",
    "gateway_jobs_contract_addr": "0x68B1D87F95878fE05B998F19b66F4baba5De1aed",
    "enclave_secret_key": "./enclave_secret_key",
    "epoch": 1718602200,
    "time_interval": 20
  }
  ```

# Dev Run

- Add Owner Address
  ```shell
  curl -X POST -H "Content-Type: application/json" -d '{"owner_address_hex": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}' http://localhost:6001/immutable-config -v
  ```
- Add Gas Address
  ```shell
  curl -X POST -H "Content-Type: application/json" -d '{"gas_key_hex": "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"}' http://localhost:6001/mutable-config -v
  ```
- Get signature
  ```shell
  curl -X GET -H "Content-Type: application/json" -d '{"chain_ids": [31337]}' http://localhost:6001/signed-registration-message -v
  ```
- Use the signature from the above endpoint to register on the commmon chain.

# Verifying Config

- Verify the Addresses on the gateway
  ```shell
  curl -X GET http://localhost:6001/gateway-details -v
  ```

# Running Tests

```shell
cargo test
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
