use anyhow::{Context, Result};
use axum::{http::StatusCode, routing::get, Router};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();

    let app = Router::new().route("/", get(hello));

    let listener = TcpListener::bind("0.0.0.0:1100")
        .await
        .context("failed to bind listener")?;

    info!("Listening on {}", "0.0.0.0:1100");
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

async fn hello() -> (StatusCode, String) {
    (StatusCode::OK, "Hello, World!".to_owned())
}
