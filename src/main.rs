mod args;
mod enclave_monitor;
mod http_server;
mod logging;

use args::Args;
use clap::Parser;
use enclave_monitor::{monitor_and_capture_logs, save_logs_to_file};
use logging::{clear_log_file, log_message};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::sync::broadcast;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    clear_log_file(&args.enclave_log_file)?;
    clear_log_file(&args.script_log_file)?;

    let (tx, rx) = mpsc::channel();
    let (sse_tx, _) = broadcast::channel(100);

    log_message(&args.script_log_file, "Starting script...")?;

    let log_id_counter = Arc::new(Mutex::new(1));

    {
        let tx = tx.clone();
        let sse_tx = sse_tx.clone();
        let script_log_file = args.script_log_file.clone();
        let log_id_counter = Arc::clone(&log_id_counter);
        let target_cid = args.target_cid;

        thread::spawn(move || {
            loop {
                if let Err(e) = monitor_and_capture_logs(
                    &tx,
                    &sse_tx,
                    &script_log_file,
                    &log_id_counter,
                    target_cid,
                ) {
                    log_message(
                        &script_log_file,
                        &format!("Error in monitor_and_capture_logs: {}. Retrying...", e),
                    )
                    .unwrap();
                    thread::sleep(Duration::from_secs(1));
                }
            }
        });
    }

    {
        let enclave_log_file = args.enclave_log_file.clone();
        thread::spawn(move || {
            if let Err(e) = save_logs_to_file(rx, &enclave_log_file) {
                eprintln!("Error saving logs to file: {}", e);
            }
        });
    }

    let routes = http_server::create_routes(args.enclave_log_file.clone(), sse_tx.clone());

    log_message(
        &args.script_log_file,
        "Server started at http://localhost:515",
    )?;
    log_message(
        &args.script_log_file,
        "SSE endpoint: http://localhost:515/stream",
    )?;

    warp::serve(routes).run(([0, 0, 0, 0], args.server_port)).await;

    Ok(())
}
