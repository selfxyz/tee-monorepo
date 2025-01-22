use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{anyhow, Context, Result};
use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use nucypher_core::{ferveo::api::DkgPublicKey, Conditions, SessionStaticKey};
use oyster::axum::{ScallopListener, ScallopState};
use scallop::{AuthStore, AuthStoreState, Auther};
use taco::decrypt;
use tokio::{
    fs::{self, read},
    net::TcpListener,
    spawn,
    time::sleep,
};
use tracing::{error, info};
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

    /// DKG listening address
    #[arg(long, default_value = "0.0.0.0:1101")]
    dkg_listen_addr: String,

    /// Derive listening address
    #[arg(long, default_value = "0.0.0.0:1100")]
    derive_listen_addr: String,

    /// Path to file with private key signer
    #[arg(long, default_value = "/app/secp256k1.sec")]
    signer: String,

    /// Condition string for the key
    #[arg(long)]
    condition: String,

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
    #[arg(long, default_value = "http://127.0.0.1:1300/attestation/raw")]
    attestation_endpoint: String,

    /// Path to X25519 secret file
    #[arg(long, default_value = "/app/x25519.sec")]
    secret_path: String,

    // this could be fetched from the RPC but that then adds trust on the RPC
    // especially for something critical like the public key against which
    // randomness is encrypted
    /// DKG ceremony public key
    #[arg(long)]
    dkg_public_key: String,

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

    let dkg_public_key = DkgPublicKey::from_bytes(
        &hex::decode(args.dkg_public_key).context("failed to decode dkg public key")?,
    )
    .context("failed to parse dkg public key")?;

    let app_state = AppState { randomness };

    let auther = Auther {
        url: args.attestation_endpoint,
    };

    let auth_store = AuthStore {};

    // Panic safety: we simply abort on panics and eschew any handling

    let app_state_clone = app_state.clone();
    let derive_handle = spawn(run_forever(move || {
        // what the actual fuck
        // TODO: see if there is a better way
        let app_state = app_state.clone();
        let listen_addr = args.derive_listen_addr.clone();
        let auther = auther.clone();
        let auth_store = auth_store.clone();
        let secret = secret.clone();
        async move { run_derive_server(app_state, listen_addr, auther, auth_store, secret).await }
    }));

    // should never exit unless through an abort on panic
    tokio::try_join!(derive_handle).expect("not supposed to ever exit");
    panic!("not supposed to ever exit");
}

async fn run_forever<T: FnMut() -> F, F: Future<Output = Result<()>>>(mut task: T) {
    loop {
        if let Err(e) = task().await {
            error!("{e:?}");
        }

        sleep(Duration::from_secs(5)).await;
    }
}

async fn run_derive_server(
    app_state: AppState,
    listen_addr: String,
    auther: Auther,
    auth_store: AuthStore,
    secret: [u8; 32],
) -> Result<()> {
    let app = Router::new()
        .route("/derive", get(derive::derive))
        .with_state(app_state);

    let tcp_listener = TcpListener::bind(&listen_addr)
        .await
        .context("failed to bind listener")?;

    let listener = ScallopListener {
        listener: tcp_listener,
        secret,
        auth_store,
        auther,
    };

    info!("Derive listening on {}", listen_addr);
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
