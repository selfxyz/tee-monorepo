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
        #[arg(short = 'i', long, required = false)]
        docker_images: Option<Vec<String>>,

        /// Output folder name
        #[arg(short, long, default_value = "result")]
        output: String,

        /// Git commit reference for oyster-monorepo
        #[arg(short = 'r', long, default_value = "3e6dbc844b42281462e65d7742d9436d4205fcfd")]
        commit_ref: String,
    },
    /// Upload Enclave Image to IPFS
    Upload {
        /// Path to enclave image file
        #[arg(short, long)]
        file: String,
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
            commit_ref,
        } => {
            let platform = types::Platform::from_str(platform).map_err(|e| anyhow::anyhow!(e))?;
            commands::build::build_oyster_image(platform, docker_compose, docker_images, output, commit_ref)?
        }
        Commands::Upload { file } => {
            let default_provider = types::StorageProvider::Pinata;
            commands::upload::upload_enclave_image(file, &default_provider).await?;
        }
    }

    Ok(())
}
