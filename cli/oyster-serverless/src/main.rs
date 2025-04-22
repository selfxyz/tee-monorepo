use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::doctor::DoctorArgs;

mod commands;
mod types;

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
#[command(version, about = "Oyster Serverless command line utility")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check optional system dependencies like Docker
    Doctor(DoctorArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Doctor(args) => commands::doctor::run_doctor(args),
    };

    if let Err(e) = result {
        tracing::error!("Error: {e:#}");
        std::process::exit(1);
    }

    Ok(())
}
