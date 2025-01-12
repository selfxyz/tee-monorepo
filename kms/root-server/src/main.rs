use std::sync::{Arc, Mutex};

use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use nucypher_core::{ferveo::api::DkgPublicKey, Conditions};
use tokio::{fs::read, net::TcpListener};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod derive;
mod export;
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

    /// Condition string for the key
    #[arg(short, long)]
    condition: String,

    /// DKG public key in hex form
    #[arg(short, long)]
    dkg_public_key: String,
}

#[derive(Clone)]
struct AppState {
    randomness: Arc<Mutex<Option<Box<[u8]>>>>,
    encrypted: Arc<Mutex<String>>,
    signer: PrivateKeySigner,
    conditions: Conditions,
    dkg_public_key: DkgPublicKey,
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
        conditions: Conditions::new(&args.condition),
        dkg_public_key: DkgPublicKey::from_bytes(
            &hex::decode(args.dkg_public_key).context("failed to decode dkg public key")?,
        )
        .context("failed to create dkg public key")?,
    };

    let app = Router::new()
        .route("/generate", post(generate::generate))
        .route("/import", post(import::import))
        .route("/export", get(export::export))
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
