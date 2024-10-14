mod args;
mod enclave_monitor;
mod http_server;
mod logging;

use anyhow::Context;
use args::Args;
use clap::Parser;
use enclave_monitor::monitor_and_capture_logs;
use logging::{clear_log_file, log_message};
use tokio::sync::broadcast;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    clear_log_file(&args.enclave_log_file).context("failed to clear enclave log file at startup")?;
    clear_log_file(&args.script_log_file).context("failed to clear debug log file at startup")?;

    let (sse_tx, _) = broadcast::channel(100);

    log_message(&args.script_log_file, "Starting script...")?;

    {
        let sse_tx = sse_tx.clone();
        let script_log_file = args.script_log_file.clone();
        let enclave_log_file = args.enclave_log_file.clone();
        let target_cid = args.target_cid;

        tokio::task::spawn(async move {
            loop {
                if let Err(e) = monitor_and_capture_logs(
                    &sse_tx,
                    &enclave_log_file,
                    &script_log_file,
                    target_cid,
                ).await { // Ensure you await the async function
                    let _ = log_message(
                        &script_log_file,
                        &format!("Error in monitor_and_capture_logs: {}. Retrying...", e),
                    ).inspect_err(|e| eprintln!("Failed to log message: {}", e));
                }
            }
        });    
    }

    let routes = http_server::create_routes(args.enclave_log_file.clone(), sse_tx.clone());

    log_message(
        &args.script_log_file,
        "Server started. SSE endpoint: <host>/logs/stream",
    )?;
    println!("running port {}", args.port);

    warp::serve(routes).run(([0, 0, 0, 0], args.port)).await;

    Ok(())
}
