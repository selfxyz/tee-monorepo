use anyhow::Context;
use chrono::Local;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncWriteExt, ErrorKind};

pub async fn log_message(log_file: &str, message: &str) -> anyhow::Result<()> {
    // Create OpenOptions
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .await
        .context("Failed to open enclave log file")?;

    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let log_message = format!("[{}] {}", now, message);

    file.write_all(log_message.as_bytes())
        .await
        .context("failed to write log to debug log file")?;
    file.write_all(b"\n").await?;
    file.flush()
        .await
        .context("failed to flush all changes from buffer to log file")?;
    Ok(())
}

pub async fn clear_log_file(file_path: &str) -> anyhow::Result<()> {
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(file_path)
        .await
        .map(|_| ())
        .or_else(|e| {
            if e.kind() == ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e).context("Failed to clear the log file")
            }
        })
}
