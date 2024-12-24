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
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
