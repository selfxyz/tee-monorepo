use std::sync::{Arc, Mutex};

use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use axum::{routing::get, Router};
use clap::Parser;
use tokio::{fs::read, net::TcpListener};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod derive;
mod generate;
mod import;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Listening address
    #[arg(short, long, default_value = "0.0.0.0:1100")]
    listen_addr: String,

    /// Path to file with private key signer
    #[arg(short, long, default_value = "/app/secp256k1.sec")]
    signer: String,
}

#[derive(Clone)]
struct AppState {
    signer: PrivateKeySigner,
    randomness: Arc<Mutex<Option<Box<[u8]>>>>,
    encrypted: Arc<Mutex<Box<[u8]>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let args = Args::parse();

    let signer = PrivateKeySigner::from_slice(
        &read(args.signer)
            .await
            .context("failed to read signer file")?,
    )
    .context("failed to create signer")?;

    let app_state = AppState {
        signer,
        randomness: Default::default(),
        encrypted: Default::default(),
    };

    let app = Router::new()
        .route("/generate", get(generate::generate))
        .route("/import", get(import::import))
        .route("/derive", get(derive::derive))
        .with_state(app_state);

    let listener = TcpListener::bind(&args.listen_addr)
        .await
        .context("failed to bind listener")?;

    info!("Listening on {}", args.listen_addr);
    axum::serve(listener, app)
        .await
        .context("failed to serve")?;

    Ok(())
}

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
