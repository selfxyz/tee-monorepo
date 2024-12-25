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

#### `upload`
Uploads an enclave image to IPFS via Pinata.

Options:
--file (path to the enclave image file)

Add env vars for Pinata:
["PINATA_API_KEY", "PINATA_SECRET_KEY"]

#### `verify-enclave`
Verifies an Oyster enclave's attestation document.

Options:
- `--enclave-ip` (-e): Enclave IP address
- `--pcr1` (-1): PCR1 value
- `--pcr2` (-2): PCR2 value  
- `--pcr3` (-3): PCR3 value
- `--cpu` (-c): Number of CPU cores
- `--memory` (-m): Memory in MB
- `--attestation-port` (-p): Attestation port (default: 1400)
- `--max-age` (-a): Maximum age of attestation in milliseconds (default: 300000)

### Example

```bash
# Check system requirements
./oyster-cvm doctor
# Sample output:
[INFO] Docker is installed ✓
[INFO] Nix is installed ✓

# Build an oyster cvm image
./oyster-cvm build-image \
  --platform amd64 \
  --docker-compose ./docker-compose.yml \
  --docker-images ./image1.tar ./image2.tar \
  --output ./result
# Generates a folder "result" with files
# image.eif  log.txt  pcr.json

# Upload image to IPFS using Pinata
./oyster-cvm upload --file ./result/image.eif
# Sample output:
[INFO] Successfully uploaded to Pinata: https://gateway.pinata.cloud/ipfs/Qm...

# Verify an enclave
./oyster-cvm verify-enclave \
  --enclave-ip 192.168.1.100 \
  --pcr1 value1 \
  --pcr2 value2 \
  --pcr3 value3 \
  --cpu 4 \
  --memory 8192 \
  --attestation-port 1400 \
  --max-age 300000

# Sample output:
[INFO ] Public key verified from enclave attestation
[INFO ] PCR values: PCR1=value1, PCR2=value2, PCR3=value3
[INFO ] CPU: 4, Memory: 8192
[INFO ] Public key: [...]
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
