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
use scallop::{AuthStore, Auther, ScallopListener, ScallopState};
use tokio::{fs::read, net::TcpListener, spawn, time::sleep};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod derive;
mod export;
mod generate;
mod import;
mod scallop;
mod taco;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
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
}

#[derive(Clone)]
struct AppState {
    // lock hierarchy:
    // randomness
    // encrypted
    randomness: Arc<Mutex<Option<Box<[u8]>>>>,
    encrypted: Arc<Mutex<String>>,
    signer: PrivateKeySigner,
    conditions: Conditions,
    dkg_public_key: DkgPublicKey,
    ritual: u32,
    taco_nodes: HashMap<Address, SessionStaticKey>,
    threshold: u16,
    porter: String,
    chain_id: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let args = Args::parse();

    let signer = PrivateKeySigner::from_slice(
        &read(&args.signer)
            .await
            .context("failed to read signer file")?,
    )
    .context("failed to create signer")?;

    let (taco_nodes, threshold, dkg_public_key) = taco::get_taco_nodes(&args)
        .await
        .context("failed to fetch taco nodes")?;

    let chain_id = ProviderBuilder::new()
        .on_http(args.rpc.parse().context("failed to parse rpc url")?)
        .get_chain_id()
        .await
        .context("failed to get chain id")?;

    let secret: [u8; 32] = read(args.secret_path)
        .await
        .context("failed to read secret file")?
        .try_into()
        .map_err(|_| anyhow!("failed to parse secret file"))?;

    let app_state = AppState {
        signer,
        randomness: Default::default(),
        encrypted: Default::default(),
        conditions: Conditions::new(&args.condition),
        dkg_public_key,
        ritual: args.ritual,
        taco_nodes,
        threshold,
        porter: args.porter,
        chain_id,
    };

    let auther = Auther {
        url: args.attestation_endpoint,
    };

    let auth_store = AuthStore {};

    // Panic safety: we simply abort on panics and eschew any handling

    let app_state_clone = app_state.clone();
    let dkg_handle = spawn(run_forever(move || {
        // what the actual fuck
        // TODO: see if there is a better way
        let app_state = app_state_clone.clone();
        let listen_addr = args.dkg_listen_addr.clone();
        async move { run_dkg_server(app_state, listen_addr).await }
    }));

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
    tokio::try_join!(dkg_handle, derive_handle).expect("not supposed to ever exit");
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

async fn run_dkg_server(app_state: AppState, listen_addr: String) -> Result<()> {
    let app = Router::new()
        .route("/generate", post(generate::generate))
        .route("/import", post(import::import))
        .route("/export", get(export::export))
        .with_state(app_state);

    let listener = TcpListener::bind(&listen_addr)
        .await
        .context("failed to bind listener")?;

    info!("DKG listening on {}", listen_addr);
    axum::serve(listener, app).await.context("failed to serve")
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
        app.into_make_service_with_connect_info::<ScallopState>(),
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
