use crate::logging::log_message;
use anyhow::{bail, Context};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use tokio::sync::broadcast;
use expectrl::spawn;

pub async fn monitor_and_capture_logs(
    sse_tx: &broadcast::Sender<String>,
    enclave_log_file_path: &str,
    script_log_file_path: &str,
    target_cid: u64,
) -> anyhow::Result<()> {
    loop {
        let enclave_id = wait_for_enclave_with_cid(target_cid).context("Error in wait for enclave with cid call")?;
        log_message(
            script_log_file_path,
            &format!(
                "Enclave with CID {} detected: {}. Starting log capture.",
                target_cid, enclave_id
            ),
        )?;
        if let Err(e) = capture_logs(
            sse_tx,
            &enclave_id,
            enclave_log_file_path,
            script_log_file_path,
        ) {
            log_message(
                script_log_file_path,
                &format!(
                    "Error capturing logs for enclave {}: {}. Restarting capture.",
                    enclave_id, e
                ),
            )?;
        }
    }
}

fn wait_for_enclave_with_cid(
    target_cid: u64,
) -> anyhow::Result<String> {
    loop {
        let output = Command::new("nitro-cli")
            .args(&["describe-enclaves"])
            .output()
            .context("Failed to execute nitro-cli describe-enclaves")?;

        let stdout = String::from_utf8(output.stdout).context("failed to typecast describe enclaves output to string")?;
        let enclaves: Value = serde_json::from_str(&stdout).context("failed to parse describe enclaves to json")?;
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

fn capture_logs(
    sse_tx: &broadcast::Sender<String>,
    enclave_id: &str,
    enclave_log_file_path: &str,
    script_log_file_path: &str,
) -> anyhow::Result<()> {
    let command = format!("nitro-cli console --enclave-id {}", enclave_id);
    let mut process = spawn(&command).context("Failed to spawn nitro-cli console")?;

    let mut log_id_counter: u64 = 0;
    let mut enclave_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(enclave_log_file_path)
        .context("failed to open enclave log file")?;

    loop {
        let mut buf = String::new();
        let bytes_read = process
            .read_line(&mut buf)
            .context("failed to read line from nitro console")?;
        if bytes_read == 0 {
            break;
        }

        let log_entry = format!("[{}] {}", log_id_counter, buf.trim());

        if let Err(e) = sse_tx.send(log_entry.clone()) {
            log_message(
                script_log_file_path,
                &format!("No active SSE subscribers, skipping log transmission: {}", e),
            )?;
        }

        writeln!(enclave_file, "{}", log_entry).context("Error writing to enclave file")?;
        enclave_file.flush().context("Error flushing log file")?;

        log_id_counter += 1;
    }

    log_message(script_log_file_path, "Nitro CLI process ended unexpectedly")?;
    bail!("Nitro CLI process ended unexpectedly")
}
