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
    /// Deploy an Oyster CVM instance
    Deploy {
        /// Number of vCPUs required
        #[arg(long, required = true)]
        cpu: u32,

        /// Memory in GB required
        #[arg(long, required = true)]
        memory: u32,

        /// Duration in days
        #[arg(long, required = true)]
        duration: u32,

        /// Maximum USD cost per hour
        #[arg(long, required = true)]
        max_usd_per_hour: f64,

        /// URL of the enclave image
        #[arg(long, required = true)]
        image_url: String,

        /// Platform (amd64 or arm64)
        #[arg(long, value_parser = [types::Platform::AMD64.as_str(), types::Platform::ARM64.as_str()], required = true)]
        platform: String,

        /// Region for deployment
        #[arg(long, required = true)]
        region: String,

        /// Wallet private key for transaction signing
        #[arg(long, required = true)]
        wallet_private_key: String,

        /// Optional operator address
        #[arg(long)]
        operator: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Doctor => commands::doctor::run_doctor()?,
        Commands::BuildImage {
            platform,
            docker_compose,
            docker_images,
            output,
        } => {
            let platform = types::Platform::from_str(platform).map_err(|e| anyhow::anyhow!(e))?;
            commands::build::build_oyster_image(platform, docker_compose, docker_images, output)?
        }
        Commands::Deploy {
            cpu,
            memory,
            duration,
            max_usd_per_hour,
            image_url,
            platform,
            region,
            wallet_private_key,
            operator,
        } => {
            let platform = types::Platform::from_str(platform).map_err(|e| anyhow::anyhow!(e))?;
            commands::deploy::deploy_oyster_instance(
                *cpu,
                *memory,
                *duration,
                *max_usd_per_hour,
                image_url,
                platform,
                region,
                wallet_private_key,
                operator.as_deref(),
            ).await?
        }
    }

    Ok(())
}
