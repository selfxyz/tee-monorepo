use anyhow::{Context, Result};
use futures_util::StreamExt;
use reqwest::Client;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::info;

const PING_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

async fn ping_check(ip: &str) -> Result<()> {
    match timeout(
        PING_TIMEOUT,
        Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg(ip)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status(),
    )
    .await
    {
        Ok(Ok(status)) if status.success() => Ok(()),
        _ => anyhow::bail!(
            "Failed to ping {} (timeout after {} seconds)",
            ip,
            PING_TIMEOUT.as_secs()
        ),
    }
}

pub async fn stream_logs(
    ip: &str,
    start_from: Option<&str>,
    with_log_id: bool,
    quiet: bool,
) -> Result<()> {
    ping_check(ip).await?;

    let mut url = format!("http://{}:516/logs/stream", ip);
    if let Some(start_id) = start_from {
        url.push_str(&format!("?start_from={}", start_id));
    }

    let client = Client::new();
    let response = match timeout(STREAM_CONNECT_TIMEOUT, client.get(&url).send()).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => anyhow::bail!("Failed to connect to console stream: {}", e),
        Err(_) => anyhow::bail!(
            "Connection to console stream timed out after {} seconds",
            STREAM_CONNECT_TIMEOUT.as_secs()
        ),
    };

    let mut stream = response.bytes_stream();

    if !quiet {
        info!("Connected to log stream. Waiting for events...");
    }

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read log stream")?;
        if let Ok(msg) = String::from_utf8(chunk.to_vec()) {
            if let Some(log) = msg.strip_prefix("data:") {
                if log.trim().is_empty() {
                    continue;
                }

                if let Some(idx) = log.find("] ") {
                    let message = if with_log_id { log } else { &log[idx + 2..] };
                    println!("{}", message.trim_end());
                }
            }
        }
    }

    Ok(())
}
