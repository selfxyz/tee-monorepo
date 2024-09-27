// src/enclave_monitor.rs
use crate::logging::log_message;
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::sync::broadcast;
use std::io::Write;

pub fn monitor_and_capture_logs(
    tx: &mpsc::Sender<String>,
    sse_tx: &broadcast::Sender<String>,
    script_log_file: &str,
    log_id_counter: &Arc<Mutex<u64>>,
    target_cid: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match wait_for_enclave_with_cid(target_cid, script_log_file) {
            Ok(enclave_id) => {
                log_message(
                    script_log_file,
                    &format!(
                        "Enclave with CID {} detected: {}. Starting log capture.",
                        target_cid, enclave_id
                    ),
                )?;
                if let Err(e) = capture_logs(
                    tx,
                    sse_tx,
                    &enclave_id,
                    script_log_file,
                    log_id_counter,
                ) {
                    log_message(
                        script_log_file,
                        &format!(
                            "Error capturing logs for enclave {}: {}. Restarting capture.",
                            enclave_id, e
                        ),
                    )?;
                }
            }
            Err(e) => {
                log_message(
                    script_log_file,
                    &format!("Error waiting for enclave with CID {}: {}", target_cid, e),
                )?;
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

fn wait_for_enclave_with_cid(
    target_cid: u64,
    script_log_file: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    loop {
        let output = Command::new("nitro-cli")
            .args(&["describe-enclaves"])
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8(output.stdout)?;
                let enclaves: Value = serde_json::from_str(&stdout)?;
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
            Err(e) => {
                log_message(
                    script_log_file,
                    &format!("Failed to execute nitro-cli describe-enclaves: {}", e),
                )?;
            }
        }

        thread::sleep(Duration::from_secs(1));
    }
}

fn capture_logs(
    tx: &mpsc::Sender<String>,
    sse_tx: &broadcast::Sender<String>,
    enclave_id: &str,
    script_log_file: &str,
    log_id_counter: &Arc<Mutex<u64>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let child = Command::new("nitro-cli")
        .args(&["console", "--enclave-id", enclave_id])
        .stdout(Stdio::piped())
        .spawn();

    match child {
        Ok(mut child) => {
            let stdout = child.stdout.take().expect("Failed to capture stdout");
            let reader = BufReader::new(stdout);

            for line in reader.lines() {
                let line = line?;

                let mut log_id = log_id_counter.lock().unwrap();
                let log_entry = format!("[{}] {}", *log_id, line);

                if let Err(e) = tx.send(log_entry.clone()) {
                    log_message(
                        script_log_file,
                        &format!("Error sending log to channel: {}", e),
                    )?;
                }

                match sse_tx.send(log_entry.clone()) {
                    Ok(_) => {}
                    Err(_) => {
                        println!("No active SSE subscribers, skipping log transmission.");
                    }
                }

                *log_id += 1;
            }

            log_message(script_log_file, "Nitro CLI process ended unexpectedly")?;
            Err("Nitro CLI process ended unexpectedly".into())
        }
        Err(e) => {
            log_message(
                script_log_file,
                &format!("Failed to start nitro-cli process: {}", e),
            )?;
            Err(e.into())
        }
    }
}

pub fn save_logs_to_file(
    rx: mpsc::Receiver<String>,
    enclave_log_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(enclave_log_file)?;

    for log in rx {
        if let Err(e) = writeln!(file, "{}", log) {
            eprintln!("Error writing log to file: {}", e);
        }
        if let Err(e) = file.flush() {
            eprintln!("Error flushing log file: {}", e);
        }
    }

    Ok(())
}
