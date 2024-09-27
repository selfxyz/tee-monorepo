use chrono::Local;
use std::fs::{OpenOptions, Permissions};
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub fn log_message(log_file: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Create OpenOptions
    let mut options = OpenOptions::new();
    options.create(true).append(true);

    // On Unix platforms, set the file mode (permissions) when creating the file
    #[cfg(unix)]
    {
        use std::path::Path;
        if !Path::new(log_file).exists() {
            options.mode(0o666);
        }
    }

    // Open the file with the specified options
    let mut file = options.open(log_file)?;

    // On Unix platforms, set the permissions explicitly
    #[cfg(unix)]
    {
        let metadata = file.metadata()?;
        let mut permissions = metadata.permissions();

        // Set permissions to 0o666
        permissions.set_mode(0o666);
        file.set_permissions(permissions)?;
    }

    // Get the current time in a human-readable format
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");

    // Write the log message with the timestamp
    writeln!(file, "[{}] {}", now, message)?;
    file.flush()?;
    Ok(())
}


pub fn clear_log_file(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
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
