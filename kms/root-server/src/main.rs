use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolValue,
};
use anyhow::{Context, Result};
use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use nucypher_core::{ferveo::api::DkgPublicKey, Conditions, ProtocolObject, SessionStaticKey};
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
    #[arg(long, default_value = "0.0.0.0:1100")]
    listen_addr: String,

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

    let (taco_nodes, threshold, dkg_public_key) = get_taco_nodes(&args)
        .await
        .context("failed to fetch taco nodes")?;

    let chain_id = ProviderBuilder::new()
        .on_http(args.rpc.parse().context("failed to parse rpc url")?)
        .get_chain_id()
        .await
        .context("failed to get chain id")?;

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

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface Coordinator {
        struct G1Point {
            bytes32 word0;
            bytes16 word1;
        }

        struct Participant {
            address provider;
            bool aggregated;
            bytes transcript;
            bytes decryptionRequestStaticKey;
            // Note: Adjust __postSentinelGap size if this struct's size changes
        }

        function rituals(
            uint256 ritualId // uint256 for backward compatibility
        )
            external
            view
            returns (
                address initiator,
                uint32 initTimestamp,
                uint32 endTimestamp,
                uint16 totalTranscripts,
                uint16 totalAggregations,
                //
                address authority,
                uint16 dkgSize,
                uint16 threshold,
                bool aggregationMismatch,
                //
                address accessController,
                G1Point memory publicKey,
                bytes memory aggregatedTranscript,
                address feeModel
            );

        function getParticipants(
            uint32 ritualId,
            uint256 startIndex,
            uint256 maxParticipants,
            bool includeTranscript
        ) external view returns (Participant[] memory);
    }
}

async fn get_taco_nodes(
    args: &Args,
) -> Result<(HashMap<Address, SessionStaticKey>, u16, DkgPublicKey)> {
    let provider =
        ProviderBuilder::new().on_http(args.rpc.parse().context("failed to parse rpc url")?);
    let contract = Coordinator::new(
        args.coordinator
            .parse()
            .context("failed to parse coordinator address")?,
        provider,
    );

    let ritual = contract
        .rituals(U256::from(args.ritual))
        .call()
        .await
        .context("failed to fetch ritual")?;

    let participants = contract
        .getParticipants(args.ritual, U256::ZERO, U256::from(ritual.dkgSize), false)
        .call()
        .await
        .context("failed to get participants")?;

    let dkg_public_key = DkgPublicKey::from_bytes(&ritual.publicKey.abi_encode_packed())
        .context("failed to parse dkg public key")?;

    Ok((
        HashMap::from_iter(participants._0.into_iter().filter_map(|p| {
            Some((
                p.provider,
                SessionStaticKey::from_bytes(&p.decryptionRequestStaticKey).ok()?,
            ))
        })),
        ritual.threshold,
        dkg_public_key,
    ))
}

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
