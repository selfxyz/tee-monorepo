use anyhow::Result;
use clap::{Parser, Subcommand};
mod commands;
mod types;

use tracing_subscriber::EnvFilter;

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
}

#[derive(Parser)]
#[command(about = "Oyster CVM command line utility")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check environment dependencies including Docker & Nix
    Doctor,
    /// Build Oyster CVM Image
    BuildImage {
        /// Platform (amd64 or arm64)
        #[arg(short, long, value_parser = [types::Platform::AMD64.as_str(), types::Platform::ARM64.as_str()])]
        platform: String,

        /// Path to docker-compose.yml file
        #[arg(short = 'c', long)]
        docker_compose: String,

        /// List of Docker image .tar file paths
        #[arg(short = 'i', long, required = true)]
        docker_images: Vec<String>,

        /// Output folder name
        #[arg(short, long, default_value = "result")]
        output: String,
    },
    /// Upload Enclave Image to IPFS
    Upload {
        /// Path to enclave image file
        #[arg(short, long)]
        file: String,
    },
    /// Verify Oyster Enclave Attestation
    VerifyEnclave {
        /// Enclave IP
        #[arg(short = 'e', long, required = true)]
        enclave_ip: String,

        /// PCR 0
        #[arg(short = '0', long, default_value = "")]
        pcr0: String,

        /// PCR 1
        #[arg(short = '1', long, default_value = "")]
        pcr1: String,

        /// PCR 2
        #[arg(short = '2', long, default_value = "")]
        pcr2: String,

        /// Attestation Port (default: 1300)
        #[arg(short = 'p', long, default_value = "1300")]
        attestation_port: u16,

        /// Maximum age of attestation (in milliseconds) (default: 300000)
        #[arg(short = 'a', long, default_value = "300000")]
        max_age: usize,

        /// Attestation timestamp (in milliseconds)
        #[arg(short = 't', long, default_value = "0")]
        timestamp: usize,

        /// Root public key
        #[arg(short = 'r', long, default_value = "")]
        root_public_key: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Doctor => commands::doctor::run_doctor(),
        Commands::BuildImage {
            platform,
            docker_compose,
            docker_images,
            output,
        } => {
            let platform = types::Platform::from_str(platform).map_err(|e| anyhow::anyhow!(e))?;
            commands::build::build_oyster_image(platform, docker_compose, docker_images, output)
        },
        Commands::Upload { file } => {
            let default_provider = types::StorageProvider::Pinata;
            commands::upload::upload_enclave_image(file, &default_provider).await
        },
        Commands::VerifyEnclave {
            pcr0,
            pcr1,
            pcr2,
            enclave_ip,
            attestation_port,
            max_age,
            root_public_key,
            timestamp,
        } => {
            commands::verify::verify_enclave(pcr0, pcr1, pcr2, enclave_ip, attestation_port, max_age, root_public_key, timestamp).await
        }
    };

    if let Err(err) = &result {
        tracing::error!("Error: {:#}", err);
        std::process::exit(1);
    }

    result
}
