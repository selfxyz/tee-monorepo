mod args;
mod enclave_monitor;
mod http_server;
mod logging;

use anyhow::Context;
use args::Args;
use clap::Parser;
use enclave_monitor::monitor_and_capture_logs;
use logging::{clear_log_file, log_message};
use std::sync::{atomic::AtomicU64, Arc};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let log_counter = Arc::new(AtomicU64::new(1));

    // Clear log files at startup
    for path in [&args.enclave_log_file_path, &args.script_log_file_path] {
        clear_log_file(path)
            .await
            .with_context(|| format!("failed to clear log file: {}", path))?;
    }

    log_message(&args.script_log_file_path, "Starting script...").await?;

    // Spawn log monitoring task
    tokio::task::spawn({
        let script_log = args.script_log_file_path.clone();
        let enclave_log = args.enclave_log_file_path.clone();
        let counter = Arc::clone(&log_counter);

        async move {
            if let Err(e) =
                monitor_and_capture_logs(&enclave_log, &script_log, args.target_cid, counter).await
            {
                let _ = log_message(
                    &script_log,
                    &format!("Error in monitor_and_capture_logs: {}. Retrying...", e),
                )
                .await;
            }
        }
    });

    // Start HTTP server
    let routes = http_server::create_routes(
        args.enclave_log_file_path.to_owned(),
        args.script_log_file_path.to_owned(),
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
