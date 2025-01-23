use alloy::{
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{anyhow, Context, Result};
use axum::{routing::get, Router};
use clap::Parser;
use oyster::axum::{ScallopListener, ScallopState};
use scallop::{AuthStore, AuthStoreState, Auther};
use taco::decrypt;
use tokio::{
    fs::{self, read},
    net::TcpListener,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod derive;
mod scallop;
mod taco;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to encrypted randomness file
    #[arg(long, default_value = "/app/init-params")]
    randomness_file: String,

    /// Listening address
    #[arg(long, default_value = "0.0.0.0:1100")]
    listen_addr: String,

    /// Path to file with private key signer
    #[arg(long, default_value = "/app/secp256k1.sec")]
    signer: String,

    /// Porter URI
    #[arg(long)]
    porter: String,

    /// Ritual id
    #[arg(long)]
    ritual: u32,

    /// Coordinator address
    #[arg(long)]
    coordinator: String,

    /// RPC URL
    #[arg(long)]
    rpc: String,

    /// Attestation endpoint
    #[arg(long, default_value = "http://127.0.0.1:1301/attestation/raw")]
    attestation_endpoint: String,

    /// Path to X25519 secret file
    #[arg(long, default_value = "/app/x25519.sec")]
    secret_path: String,

    /// DKG threshold
    #[arg(long)]
    threshold: u16,
}

#[derive(Clone)]
struct AppState {
    randomness: [u8; 64],
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let args = Args::parse();

    let taco_nodes = taco::get_taco_nodes(&args)
        .await
        .context("failed to fetch taco nodes")?;

    let signer = PrivateKeySigner::from_slice(
        &read(&args.signer)
            .await
            .context("failed to read signer file")?,
    )
    .context("failed to create signer")?;

    let chain_id = ProviderBuilder::new()
        .on_http(args.rpc.parse().context("failed to parse rpc url")?)
        .get_chain_id()
        .await
        .context("failed to get chain id")?;

    let encrypted_randomness = fs::read(args.randomness_file)
        .await
        .context("failed to read randomness file")?;
    let randomness = decrypt(
        &encrypted_randomness,
        args.ritual,
        &taco_nodes,
        args.threshold,
        &args.porter,
        &signer,
        chain_id,
    )
    .await
    .context("failed to decrypt randomness")?
    .as_ref()
    .try_into()
    .context("randomness is not the right size")?;

    let secret: [u8; 32] = read(args.secret_path)
        .await
        .context("failed to read secret file")?
        .try_into()
        .map_err(|_| anyhow!("failed to parse secret file"))?;

    let app_state = AppState { randomness };

    let auther = Auther {
        url: args.attestation_endpoint,
    };

    let auth_store = AuthStore {};

    let app = Router::new()
        .route("/derive", get(derive::derive))
        .with_state(app_state);

    let tcp_listener = TcpListener::bind(&args.listen_addr)
        .await
        .context("failed to bind listener")?;

    let listener = ScallopListener {
        listener: tcp_listener,
        secret,
        auth_store,
        auther,
    };

    info!("Listening on {}", args.listen_addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<ScallopState<AuthStoreState>>(),
    )
    .await
    .context("failed to serve")
}

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
