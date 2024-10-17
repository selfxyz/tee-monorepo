use crate::logging::log_message;
use anyhow::{bail, Context};
use serde_json::Value;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{broadcast, Mutex};

pub async fn monitor_and_capture_logs(
    sse_tx: &broadcast::Sender<String>,
    enclave_log_file_path: &str,
    script_log_file_path: &str,
    target_cid: u64,
    log_counter: Arc<Mutex<u64>>,
) -> anyhow::Result<()> {
    loop {
        let enclave_id = wait_for_enclave_with_cid(target_cid)
            .await
            .context("Error in wait for enclave with cid call")?;
        let log_counter = log_counter.clone();
        log_message(
            script_log_file_path,
            &format!(
                "Enclave with CID {} detected: {}. Starting log capture.",
                target_cid, enclave_id
            ),
        )
        .await?;
        if let Err(e) = capture_logs(
            sse_tx,
            &enclave_id,
            enclave_log_file_path,
            script_log_file_path,
            log_counter,
        )
        .await
        {
            log_message(
                script_log_file_path,
                &format!(
                    "Error capturing logs for enclave {}: {}. Restarting capture.",
                    enclave_id, e
                ),
            )
            .await?;
        }
    }
}

async fn wait_for_enclave_with_cid(target_cid: u64) -> anyhow::Result<String> {
    loop {
        let output = Command::new("nitro-cli")
            .args(["describe-enclaves"])
            .output()
            .await
            .context("Failed to execute nitro-cli describe-enclaves")?;

        let stdout = String::from_utf8(output.stdout)
            .context("failed to typecast describe enclaves output to string")?;
        let enclaves: Value =
            serde_json::from_str(&stdout).context("failed to parse describe enclaves to json")?;
        if let Some(enclaves) = enclaves.as_array() {
            for enclave in enclaves {
                if let (Some(enclave_cid), Some(enclave_id)) = (
                    enclave["EnclaveCID"].as_u64(),
                    enclave["EnclaveID"].as_str(),
                ) {
                    if enclave_cid == target_cid {
                        return Ok(enclave_id.to_string());
                    }
                }
            }
        }
    }
}

async fn capture_logs(
    sse_tx: &broadcast::Sender<String>,
    enclave_id: &str,
    enclave_log_file_path: &str,
    script_log_file_path: &str,
    log_counter: Arc<Mutex<u64>>,
) -> anyhow::Result<()> {
    let mut child = Command::new("nitro-cli")
        .args(["console", "--enclave-id", enclave_id])
        .stdout(Stdio::piped())
        .spawn()
        .context("Failed to spawn nitro-cli process")?;

    // Open the file asynchronously
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(enclave_log_file_path)
        .await
        .context("Failed to open enclave log file")?;

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let mut reader = BufReader::new(stdout).lines();

    while let Some(line) = reader.next_line().await? {
        let mut log_counter = log_counter.lock().await;
        let log_entry = format!("[{}] {}", *log_counter, line);

        {
            file.write_all(log_entry.as_bytes()).await?;
            file.write_all(b"\n").await?;
            file.flush().await?;
        }

        if sse_tx.send(log_entry).is_err() {
            println!("No active SSE subscribers, skipping log transmission.");
        }

        *log_counter += 1;
    }

    let status = child.wait().await?;
    if !status.success() {
        bail!("Nitro CLI process exited with error");
    }

    log_message(script_log_file_path, "Nitro CLI process ended unexpectedly").await?;
    bail!("Nitro CLI process ended unexpectedly")
}
