use anyhow::{Context, Result};
use clap::Args;
use std::process::Command;
use std::process::Stdio;
use std::io::{BufRead, BufReader};
use std::thread;
use portpicker::pick_unused_port;
use tracing::info;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Args)]
pub struct DevArgs {}

fn cleanup_container(container_id: &str) {
    info!("Cleaning up container...");
    if let Err(e) = Command::new("docker")
        .arg("rm")
        .arg("-f")
        .arg(container_id)
        .output() {
        eprintln!("Failed to cleanup container: {}", e);
    }
}

fn stream_logs(container_id: String, running: Arc<AtomicBool>) {
    thread::spawn(move || {
        let logs = Command::new("docker")
            .arg("logs")
            .arg("-f")
            .arg(&container_id)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut child = match logs {
            Ok(child) => child,
            Err(e) => {
                eprintln!("Failed to start log streaming: {}", e);
                return;
            }
        };

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Stream stdout
        let stdout_running = running.clone();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if !stdout_running.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(line) = line {
                    println!("{}", line);
                }
            }
        });

        // Stream stderr
        let stderr_running = running.clone();
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if !stderr_running.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(line) = line {
                    eprintln!("{}", line);
                }
            }
        });
    });
}

pub async fn run_dev(_args: DevArgs) -> Result<()> {
    // Check if worker.js exists in current directory
    let worker_path = std::env::current_dir()?.join("worker.js");
    if !worker_path.exists() {
        anyhow::bail!("worker.js not found in current directory");
    }

    // Get absolute path
    let worker_abs_path = worker_path
        .canonicalize()
        .context("Failed to get absolute path of worker.js")?;

    // Find a free port
    let port = pick_unused_port().context("No free ports available")?;
    
    info!("Starting development server on port {}", port);

    let output = Command::new("docker")
        .arg("run")
        .arg("-d")
        .arg("-p")
        .arg(format!("{}:8080", port))
        .arg("-v")
        .arg(format!("{}:/app/worker.js", worker_abs_path.display()))
        .arg("sagarparker/serverless_workerd")
        .output()
        .context("Failed to start docker container")?;

    if !output.status.success() {
        anyhow::bail!("Failed to start docker container");
    }

    let container_id = String::from_utf8(output.stdout)
        .context("Failed to read container ID")?
        .trim()
        .to_string();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let container_id_clone = container_id.clone();

    // Start log streaming
    stream_logs(container_id.clone(), running.clone());

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        cleanup_container(&container_id_clone);
    })?;

    // Keep the main thread running until we receive a signal
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    Ok(())
}