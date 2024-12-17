# Enclave Image Builder CLI

A CLI tool to build and deploy your apps to the oyster marketplace. Using just your Docker configurations.

## Prerequisites

- Docker
- Nix
- Git (for fetching flakes)

## Installation

From source:

```bash
git clone https://github.com/yourorg/enclave-image-builder.git
cd enclave-image-builder
cargo build --release
```

## Usage

### View help

```bash
oyster-cvm --help
```

### Commands

`doctor`
Checks if Docker and Nix are installed.

`build-image`
Builds an enclave image.
--platform (amd64 or arm64)
--docker-compose (path to docker-compose.yml)
--docker-images (list of Docker .tar files to be loaded)
--output (output directory, default result)

## Example

```bash
enclave-image-builder doctor
enclave-image-builder build-image \
  --platform amd64 \
  --docker-compose ./docker-compose.yml \
  --docker-images ./image1.tar ./image2.tar \
  --output ./result
```
