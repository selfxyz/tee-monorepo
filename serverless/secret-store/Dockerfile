FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y
RUN apt-get install apt-utils -y 
RUN apt-get install net-tools iptables iproute2 wget -y 
RUN apt-get autoclean && apt-get autoremove
RUN rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Supervisord to manage programs
RUN wget -O supervisord https://artifacts.marlin.org/oyster/binaries/supervisord_c2cae38b_linux_amd64
RUN chmod +x supervisord

# Transparent proxy component inside the enclave to enable outgoing connections
RUN wget -O ip-to-vsock-transparent https://artifacts.marlin.org/oyster/binaries/ip-to-vsock-transparent_v1.0.0_linux_amd64
RUN chmod +x ip-to-vsock-transparent

# Key generator to generate ecdsa keys
RUN wget -O keygen-secp256k1 https://artifacts.marlin.org/oyster/binaries/keygen-secp256k1_v1.0.0_linux_amd64
RUN chmod +x keygen-secp256k1

# Attestation server inside the enclave that generates attestations
RUN wget -O attestation-server https://artifacts.marlin.org/oyster/binaries/attestation-server_v2.0.0_linux_amd64
RUN chmod +x attestation-server

# Proxy to expose attestation server outside the enclave
RUN wget -O vsock-to-ip https://artifacts.marlin.org/oyster/binaries/vsock-to-ip_v1.0.0_linux_amd64
RUN chmod +x vsock-to-ip

# DNS proxy to provide DNS services inside the enclave
RUN wget -O dnsproxy https://artifacts.marlin.org/oyster/binaries/dnsproxy_v0.72.0_linux_amd64
RUN chmod +x dnsproxy

# setup.sh script that will act as entrypoint
COPY setup.sh ./
RUN chmod +x setup.sh

# supervisord config
COPY supervisord.conf /etc/supervisord.conf

# oyster serverless executor inside the enclave that executes web3 jobs
COPY target/x86_64-unknown-linux-musl/release/oyster-secret-store ./
RUN chmod +x oyster-secret-store

# oyster serverless executor config file
COPY ./oyster_secret_store_config.json ./

# Entry point
ENTRYPOINT [ "/app/setup.sh" ]