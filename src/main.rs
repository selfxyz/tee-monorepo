use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader, Write, ErrorKind};
use std::sync::{mpsc, Arc, Mutex};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use std::fs::OpenOptions;
use tokio::sync::broadcast;
use warp::Filter;
use chrono::Local;
use clap::Parser;
use serde_json::json; 

const TARGET_CID: u64 = 18;  // Equivalent to 88 in hexadecimal

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the enclave log file
    #[clap(short, long, value_parser)]
    enclave_log_file: String,

    /// Path to the script log file
    #[clap(short, long, value_parser)]
    script_log_file: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    clear_log_file(&args.enclave_log_file)?;
    clear_log_file(&args.script_log_file)?;

    let (tx, rx) = mpsc::channel();
    let (sse_tx, _) = broadcast::channel(100);

    log_message(&args.script_log_file, "Starting script...")?;

    // Shared log_id counter (initially 1)
    let log_id_counter = Arc::new(Mutex::new(1));
    let log_id_counter_clone = Arc::clone(&log_id_counter);

    // Spawn a thread to monitor for the specific enclave and capture logs
    let sse_tx_clone = sse_tx.clone();
    let enclave_log_file_clone = args.enclave_log_file.clone();
    let script_log_file_clone = args.script_log_file.clone();
    thread::spawn(move || {
        loop {
            if let Err(e) = monitor_and_capture_logs(&tx, &sse_tx_clone, &enclave_log_file_clone, &script_log_file_clone, &log_id_counter_clone) {
                log_message(&script_log_file_clone, &format!("Error in monitor_and_capture_logs: {}. Retrying...", e)).unwrap();
                thread::sleep(Duration::from_secs(5));
            }
        }
    });

    // Spawn a thread to save logs to file
    let enclave_log_file_clone = args.enclave_log_file.clone();
    thread::spawn(move || {
        if let Err(e) = save_logs_to_file(rx, &enclave_log_file_clone) {
            eprintln!("Error saving logs to file: {}", e);
        }
    });

    // Set up HTTP server for fetching all logs
    let enclave_log_file_clone = args.enclave_log_file.clone();

    let logs = warp::path("logs")
    .and(warp::query::<HashMap<String, String>>()) // Handle query params
    .map(move |params: HashMap<String, String>| {
        // Extract log_id and offset from query params
        let log_id = params.get("log_id").and_then(|id| id.parse::<u64>().ok()).unwrap_or(1);
        let offset = params.get("offset").and_then(|off| off.parse::<usize>().ok()).unwrap_or(10);
        
        // Fetch the logs
        match fetch_logs_with_offset(&enclave_log_file_clone, log_id, offset) {
            Ok(logs) => warp::reply::json(&logs),  // Return logs as JSON
            Err(_) => {
                // Return an error message in JSON format
                warp::reply::json(&json!({"error": "Failed to retrieve logs."}))
            }
        }
    });

    // Set up SSE endpoint for streaming logs
    let sse = warp::path("stream")
        .and(warp::get())
        .map(move || {
            let sse_rx = sse_tx.subscribe();
            let stream = async_stream::stream! {
                let mut sse_rx = sse_rx;
                while let Ok(msg) = sse_rx.recv().await {
                    yield Ok::<_, warp::Error>(warp::sse::Event::default().data(msg));
                }
            };
            warp::sse::reply(warp::sse::keep_alive().stream(stream))
        });

    let routes = logs.or(sse);

    log_message(&args.script_log_file, "Server started at http://localhost:515")?;
    log_message(&args.script_log_file, "SSE endpoint: http://localhost:515/stream")?;

    warp::serve(routes).run(([127, 0, 0, 1], 515)).await;

    Ok(())
}

fn monitor_and_capture_logs(tx: &mpsc::Sender<String>, sse_tx: &broadcast::Sender<String>, enclave_log_file: &str, script_log_file: &str, log_id_counter: &Arc<Mutex<u64>>) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match wait_for_enclave_with_cid(TARGET_CID, script_log_file) {
            Ok(enclave_id) => {
                log_message(script_log_file, &format!("Enclave with CID {} detected: {}. Starting log capture.", TARGET_CID, enclave_id))?;
                if let Err(e) = capture_logs(tx, sse_tx, &enclave_id, enclave_log_file, script_log_file, log_id_counter) {
                    log_message(script_log_file, &format!("Error capturing logs for enclave {}: {}. Restarting capture.", enclave_id, e))?;
                }
            }
            Err(e) => {
                log_message(script_log_file, &format!("Error waiting for enclave with CID {}: {}", TARGET_CID, e))?;
                thread::sleep(Duration::from_secs(5));  // Retry after some delay
            }
        }
    }
}

fn wait_for_enclave_with_cid(target_cid: u64, script_log_file: &str) -> Result<String, Box<dyn std::error::Error>> {
    loop {
        let output = Command::new("nitro-cli")
            .args(&["describe-enclaves"])
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8(output.stdout)?;
                let enclaves: serde_json::Value = serde_json::from_str(&stdout)?;
                if let Some(enclaves) = enclaves.as_array() {
                    for enclave in enclaves {
                        if let (Some(enclave_cid), Some(enclave_id)) = (enclave["EnclaveCID"].as_u64(), enclave["EnclaveID"].as_str()) {
                            if enclave_cid == target_cid {
                                return Ok(enclave_id.to_string());
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log_message(script_log_file, &format!("Failed to execute nitro-cli describe-enclaves: {}", e))?;
            }
        }

        thread::sleep(Duration::from_secs(1));
    }
}
fn capture_logs(tx: &mpsc::Sender<String>, sse_tx: &broadcast::Sender<String>, enclave_id: &str, _enclave_log_file: &str, script_log_file: &str, log_id_counter: &Arc<Mutex<u64>>) -> Result<(), Box<dyn std::error::Error>> {
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

                // Lock and update log_id
                let mut log_id = log_id_counter.lock().unwrap();
                let log_entry = format!("[{}] {}", *log_id, line); // Store log in [log_id] message format
                
                // Send log to the mpsc channel for saving to file
                if let Err(e) = tx.send(log_entry.clone()) {
                    log_message(script_log_file, &format!("Error sending log to channel: {}", e))?;
                }

                // Send log to SSE channel
                match sse_tx.send(log_entry.clone()) {
                    Ok(_) => { /* Successfully sent to SSE */ }
                    Err(broadcast::error::SendError(_)) => {
                        println!("No active SSE subscribers, skipping log transmission.");
                    }
                }

                // Increment the log_id
                *log_id += 1;
            }

            log_message(script_log_file, "Nitro CLI process ended unexpectedly")?;
            Err("Nitro CLI process ended unexpectedly".into())
        }
        Err(e) => {
            log_message(script_log_file, &format!("Failed to start nitro-cli process: {}", e))?;
            Err(e.into())
        }
    }
}

fn save_logs_to_file(rx: mpsc::Receiver<String>, enclave_log_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
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

// Helper function to log script-specific logs
fn log_message(script_log_file: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(script_log_file)?;

    // Get the current time in a human-readable format
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");

    // Write the log message with the timestamp
    writeln!(file, "[{}] {}", now, message)?;
    file.flush()?;
    Ok(())
}

// Helper function to clear a log file
fn clear_log_file(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    match OpenOptions::new().write(true).truncate(true).open(file_path) {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e.into())
            }
        }
    }
}

// Helper function to fetch logs
fn fetch_logs_with_offset(enclave_log_file: &str, log_id: u64, offset: usize) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let start_log_id = if log_id > offset as u64 {
        log_id - offset as u64
    } else {
        1  // If the calculated start log_id is less than 1, start from the first log
    };
    
    let file = std::fs::File::open(enclave_log_file)?;
    let reader = BufReader::new(file);
    
    let mut logs: Vec<serde_json::Value> = Vec::with_capacity(offset);

    for line in reader.lines().flatten() {
        // Parse each line in the [log_id] message format
        if let Some((log_id_str, message)) = line.split_once("] ") {
            let log_id_str = log_id_str.trim_start_matches('[');
            if let Ok(current_log_id) = log_id_str.parse::<u64>() {
                // Start collecting logs when we hit start_log_id
                if current_log_id >= start_log_id {
                    // Create a JSON object for each log (with log_id and message fields)
                    let log_entry = json!({
                        "log_id": current_log_id,
                        "message": message
                    });
                    logs.push(log_entry);
                }

                // Stop if we collected enough logs
                if logs.len() >= offset {
                    break;
                }
            }
        }
    }
    
    Ok(logs)
}

