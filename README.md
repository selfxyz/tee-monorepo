# Oyster Serverless Gateway

Listens to jobs on Request Chains and puts them on the Common Chain where Executors pick them up. Once Executors response to the jobs on the Common Chain, the Gateway submits the response to the original Request Chain of the job.

# Installation

- Clone the repository.
- Build the binary -
  ```
  cargo build --target x86_64-unknown-linux-musl
  ```
- Run the binary -
  ```
  ./target/x86_64-unknown-linux-musl/release/serverless-gateway --release
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
