use crate::types::Dependency;
use anyhow::Result;
use tracing::{error, info};
use std::process::Command;

pub fn run_doctor() -> Result<()> {
    let mut has_error = false;
    let mut error_msg = String::new();

    // Check Docker
    if let Err(e) = check_dependency(Dependency::Docker) {
        has_error = true;
        error_msg.push_str(&format!("{}\n", e));
    }

    // Check Nix
    if let Err(e) = check_dependency(Dependency::Nix) {
        has_error = true;
        error_msg.push_str(&format!("{}\n", e));
    }

    // Check Nix trusted user
    if let Err(e) = check_nix_trusted_user() {
        has_error = true;
        error_msg.push_str(&format!("{}\n", e));
    }

    if has_error {
        Err(anyhow::anyhow!(error_msg.trim().to_string()))
    } else {
        Ok(())
    }
}

fn check_dependency(dep: Dependency) -> Result<()> {
    if Command::new(dep.command())
        .arg("--version")
        .output()
        .is_err()
    {
        error!(
            "{} is not installed. Please install it from {} and try again",
            dep.name(),
            dep.install_url()
        );
        return Err(anyhow::anyhow!("{} is required but not found", dep.name()));
    } else {
        info!("{} is installed ✓", dep.name());
    }
    Ok(())
}

fn check_nix_trusted_user() -> Result<()> {
    let output = Command::new("nix")
        .args(["config", "show", "trusted-users"])
        .output()
        .map_err(|_| anyhow::anyhow!("Failed to get nix trusted users"))?;

    if !output.status.success() {
        error!("Failed to get nix trusted users");
        return Err(anyhow::anyhow!("Failed to get nix trusted users"));
    }

    let trusted_users = String::from_utf8(output.stdout)
        .map_err(|_| anyhow::anyhow!("Failed to parse nix trusted users output"))?;

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .map_err(|_| anyhow::anyhow!("Failed to get current username"))?;

    if !trusted_users.contains(&username) {
        error!(
            "Current user '{}' is not in nix trusted-users. To fix this:\n\
            1. Edit /etc/nix/nix.conf with sudo:\n\
               $ sudo nano /etc/nix/nix.conf\n\
            2. Add your username to trusted-users line (create if doesn't exist):\n\
               trusted-users = root {}\n\
            3. Restart nix-daemon:\n\
               $ sudo systemctl restart nix-daemon",
            username, username
        );
        return Err(anyhow::anyhow!("Nix trusted-users check failed"));
    }

    info!("Current user is in nix trusted-users list ✓");
    Ok(())
}
