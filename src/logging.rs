use anyhow::Context;
use chrono::Local;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};

pub fn log_message(log_file: &str, message: &str) -> anyhow::Result<()> {
    // Create OpenOptions
    let mut options = OpenOptions::new();
    options.create(true).append(true);

    // Open the file with the specified options
    let mut file = options.open(log_file).context("failed to open debug log file")?;

    // Get the current time in a human-readable format
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");

    // Write the log message with the timestamp
    writeln!(file, "[{}] {}", now, message).context("failed to write log to debug log file")?;
    file.flush().context("failed to flush all changes from buffer to log file")?;
    Ok(())
}


pub fn clear_log_file(file_path: &str) -> anyhow::Result<()> {
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
