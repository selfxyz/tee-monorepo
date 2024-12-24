![Marlin Oyster Logo](./logo.svg)

# Oyster CVM CLI

A command line utility to manage Oyster CVM lifecycle: build, upload, deploy and verify. Get started easily with just a `docker-compose` file.

## Prerequisites

- Docker
- Nix
- Git (for fetching flakes)

## Installation

From source:

```bash
git clone https://github.com/marlinprotocol/oyster-monorepo.git
cd cli/oyster-cvm
cargo build --release
```

## Usage

### View help

```bash
oyster-cvm --help
```

### Commands

#### `doctor`
Checks if Docker and Nix are installed.

#### `build-image`
Builds an oyster-cvm image.

Options:
- `--platform` (amd64 or arm64)
- `--docker-compose` (path to docker-compose.yml)
- `--docker-images` (list of Docker .tar files to be loaded)
- `--output` (output directory, default: result)

#### `deploy`
Deploy an Oyster CVM instance.

Required Options:
- `--cpu` (Number of vCPUs required)
- `--memory` (Memory in GB required)
- `--duration` (Duration in days)
- `--max-usd-per-hour` (Maximum USD cost per hour)
- `--image-url` (URL of the enclave image)
- `--platform` (amd64 or arm64)
- `--region` (Region for deployment)
- `--wallet-private-key` (Wallet private key for transaction signing)

Optional Options:
- `--operator` (Specific operator address)

### Example

```bash
# Check system requirements
./oyster-cvm doctor

# Sample output:
[INFO ] Docker is installed ✓
[INFO ] Nix is installed ✓

# Build an oyster cvm image
./oyster-cvm build-image \
  --platform amd64 \
  --docker-compose ./docker-compose.yml \
  --docker-images ./image1.tar ./image2.tar \
  --output ./result

# Generated files in "result" directory:
# - image.eif  
# - log.txt  
# - pcr.json

# Deploy an oyster cvm instance
./oyster-cvm deploy \
  --cpu 2 \
  --memory 4 \
  --duration 7 \
  --max-usd-per-hour 0.5 \
  --image-url ipfs://QmXXX... \
  --platform amd64 \
  --region us-east-1 \
  --wallet-private-key 0xYYY...
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
