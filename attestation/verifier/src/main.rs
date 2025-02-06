mod handler;

use std::fs;

// use actix_web::{web, App, HttpServer};
use anyhow::{Context, Result};
use axum::{routing::post, serve, Router};
use clap::Parser;
use handler::{verify_hex, verify_raw, AppState};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// path to secp256k1 private key file (e.g. /app/secp256k1.sec)
    #[arg(long)]
    secp256k1_secret: String,

    /// path to secp256k1 public key file (e.g. /app/secp256k1.pub)
    #[arg(long)]
    secp256k1_public: String,

    /// server ip (e.g. 127.0.0.1)
    #[arg(short, long)]
    ip: String,

    /// server port (e.g. 1400)
    #[arg(short, long)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let secp256k1_secret = fs::read(cli.secp256k1_secret.clone()).with_context(|| {
        format!(
            "Failed to read secp256k1_secret from {}",
            cli.secp256k1_secret
        )
    })?;
    let secp256k1_secret = secp256k1::SecretKey::from_slice(&secp256k1_secret)
        .context("unable to decode secp256k1_secret key from slice")?;

    let secp256k1_public = fs::read(cli.secp256k1_public.clone()).with_context(|| {
        format!(
            "Failed to read secp256k1_public from {}",
            cli.secp256k1_public
        )
    })?;
    let secp256k1_public: [u8; 64] = secp256k1_public
        .as_slice()
        .try_into()
        .context("invalid public key length")?;

    let app = Router::new()
        .route("/verify/raw", post(verify_raw))
        .route("/verify/hex", post(verify_hex))
        .with_state(AppState {
            secp256k1_secret,
            secp256k1_public,
        });
    let listener = tokio::net::TcpListener::bind((cli.ip.as_str(), cli.port))
        .await
        .context("failed to bind listener")?;

    println!("api server running at {}:{}", cli.ip, cli.port);

    serve(listener, app)
        .await
        .context("error while running server")
}
