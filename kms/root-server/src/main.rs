use anyhow::{Context, Result};
use axum::{http::StatusCode, routing::get, Router};
use tokio::net::TcpListener;

async fn hello() -> (StatusCode, String) {
    (StatusCode::OK, "Hello, World!".to_owned())
}

#[tokio::main]
async fn main() -> Result<()> {
    let app = Router::new().route("/", get(hello));

    let listener = TcpListener::bind("0.0.0.0:1100")
        .await
        .context("failed to bind listener")?;
    axum::serve(listener, app)
        .await
        .context("failed to serve")?;

    Ok(())
}
