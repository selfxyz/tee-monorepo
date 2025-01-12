use anyhow::{Context, Result};
use axum::{http::StatusCode, routing::get, Router};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod derive;
mod generate;
mod import;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:1100")]
    listen_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let args = Args::parse();

    let app = Router::new()
        .route("/generate", get(generate::generate))
        .route("/import", get(import::import))
        .route("/derive", get(derive::derive));

    let listener = TcpListener::bind(&args.listen_addr)
        .await
        .context("failed to bind listener")?;

    info!("Listening on {}", args.listen_addr);
    axum::serve(listener, app)
        .await
        .context("failed to serve")?;

    Ok(())
}

async fn hello() -> (StatusCode, String) {
    (StatusCode::OK, "Hello, World!".to_owned())
}

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
