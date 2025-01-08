mod args;
mod enclave_monitor;
mod http_server;
mod logging;

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use anyhow::Context;
use args::Args;
use clap::Parser;
use enclave_monitor::monitor_and_capture_logs;
use logging::{clear_log_file, log_message};
use tokio::sync::broadcast;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let log_counter = Arc::new(AtomicU64::new(0));

    clear_log_file(&args.enclave_log_file_path)
        .await
        .context("failed to clear enclave log file at startup")?;
    clear_log_file(&args.script_log_file_path)
        .await
        .context("failed to clear debug log file at startup")?;

    let (sse_tx, _) = broadcast::channel(100);

    log_message(&args.script_log_file_path, "Starting script...").await?;

    {
        let sse_tx = sse_tx.clone();
        let script_log_file = args.script_log_file_path.clone();
        let enclave_log_file = args.enclave_log_file_path.clone();
        let target_cid = args.target_cid;
        let log_counter = Arc::clone(&log_counter);

        tokio::task::spawn(async move {
            if let Err(e) = monitor_and_capture_logs(
                &sse_tx,
                &enclave_log_file,
                &script_log_file,
                target_cid,
                log_counter,
            )
            .await
            {
                // Ensure you await the async function
                let _ = log_message(
                    &script_log_file,
                    &format!("Error in monitor_and_capture_logs: {}. Retrying...", e),
                )
                .await;
            }
        });
    }

    let routes = http_server::create_routes(
        args.enclave_log_file_path.clone(),
        sse_tx.clone(),
        log_counter,
    );

    log_message(
        &args.script_log_file_path,
        "Server started. SSE endpoint: <host>/logs/stream",
    )
    .await?;
    println!("running port {}", args.port);

    warp::serve(routes).run(([0, 0, 0, 0], args.port)).await;

    Ok(())
}
