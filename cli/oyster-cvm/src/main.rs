use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::{
    build::BuildArgs, deploy::DeployArgs, doctor::DoctorArgs, list::ListArgs, update::UpdateArgs,
    upload::UploadArgs, verify::VerifyArgs,
};

mod args;
mod commands;
mod configs;
mod types;
mod utils;

use tracing_subscriber::EnvFilter;

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

#[derive(Parser)]
#[command(version, about = "Oyster CVM command line utility")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check optional system dependencies like Docker & Nix
    Doctor(DoctorArgs),
    /// Build enclave image
    Build(BuildArgs),
    /// Upload enclave image to IPFS
    Upload(UploadArgs),
    /// Deploy an Oyster CVM instance
    Deploy(DeployArgs),
    /// Verify Oyster Enclave Attestation
    Verify(VerifyArgs),
    /// List active jobs for a wallet address
    List(ListArgs),
    /// Update existing deployments
    Update(UpdateArgs),
    /// Stream logs from an Oyster CVM instance
    Logs {
        /// IP address of the instance
        #[arg(short, long, required = true)]
        ip: String,

        /// Optional log ID to start streaming from
        #[arg(short, long)]
        start_from: Option<String>,

        /// Include log ID prefix in output
        #[arg(short, long, default_value_t = false)]
        with_log_id: bool,

        /// Suppress connection status message
        #[arg(short, long, default_value_t = false)]
        quiet: bool,
    },
    /// Deposit funds to an existing job
    Deposit {
        /// Job ID
        #[arg(short, long, required = true)]
        job_id: String,

        /// Amount to deposit in USDC (e.g. 1000000 = 1 USDC since USDC has 6 decimal places)
        #[arg(short, long, required = true)]
        amount: u64,

        /// Wallet private key for transaction signing
        #[arg(long, required = true)]
        wallet_private_key: String,
    },
    /// Stop an Oyster CVM instance
    Stop {
        /// Job ID
        #[arg(short = 'j', long, required = true)]
        job_id: String,

        /// Wallet private key for transaction signing
        #[arg(long, required = true)]
        wallet_private_key: String,
    },
    /// Withdraw funds from an existing job
    Withdraw {
        /// Job ID
        #[arg(short, long, required = true)]
        job_id: String,

        /// Amount to withdraw in USDC (e.g. 1000000 = 1 USDC since USDC has 6 decimal places)
        #[arg(short, long, required_unless_present = "max")]
        amount: Option<u64>,

        /// Withdraw all remaining balance
        #[arg(long, conflicts_with = "amount")]
        max: bool,

        /// Wallet private key for transaction signing
        #[arg(long, required = true)]
        wallet_private_key: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Doctor(args) => commands::doctor::run_doctor(args),
        Commands::Build(args) => commands::build::build_oyster_image(args),
        Commands::Upload(args) => commands::upload::upload_enclave_image(args).await,
        Commands::Verify(args) => commands::verify::verify(args).await,
        Commands::Deploy(args) => commands::deploy::deploy(args).await,
        Commands::List(args) => commands::list::list_jobs(args).await,
        Commands::Update(args) => commands::update::update_job(args).await,
        Commands::Logs {
            ip,
            start_from,
            with_log_id,
            quiet,
        } => commands::log::stream_logs(&ip, start_from.as_deref(), with_log_id, quiet).await,
        Commands::Deposit {
            job_id,
            amount,
            wallet_private_key,
        } => commands::deposit::deposit_to_job(&job_id, amount, &wallet_private_key).await,
        Commands::Stop {
            job_id,
            wallet_private_key,
        } => commands::stop::stop_oyster_instance(&job_id, &wallet_private_key).await,
        Commands::Withdraw {
            job_id,
            amount,
            max,
            wallet_private_key,
        } => commands::withdraw::withdraw_from_job(&job_id, amount, max, &wallet_private_key).await,
    };

    if let Err(e) = result {
        tracing::error!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
