use crate::types::Platform;
use anyhow::{Context, Result};
use tracing::info;
use std::process::{Command, Stdio};
use std::io::{BufReader, BufRead};

pub fn build_oyster_image(
    platform: Platform,
    docker_compose: &str,
    docker_images: &Option<Vec<String>>,
    output: &str,
    commit_ref: &str,
) -> Result<()> {
    // Check if the current user is in the nix trusted-users list
    info!("Checking if the current user is in the nix trusted-users list");
    check_trusted_user()?;

    info!("Building oyster-cvm image with:");
    info!("  Platform: {}", platform.as_str());
    info!("  Docker compose: {}", docker_compose);
    info!("  Commit ref: {}", commit_ref);
    
    let docker_images_list = docker_images
        .as_ref()
        .map(|images| images.join(" "))
        .unwrap_or_default();

    info!("  Docker images: {}", docker_images_list);

    let nix_expr = format!(
        r#"((builtins.getFlake "github:marlinprotocol/oyster-monorepo?rev={}").packages.{}.sdks.docker-enclave.override {{compose={};dockerImages=[{}];}}).default"#,
        commit_ref,
        platform.nix_arch(),
        docker_compose,
        docker_images_list
    );

    let mut cmd = Command::new("nix")
        .args([
            "build",
            "--impure",
            "--system",
            platform.nix_arch(),
            "--expr",
            &nix_expr,
            "-vL",
            "--out-link",
            output,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .context("Failed to execute Nix build command")?;
    
    let stdout = cmd.stdout.take().unwrap();
    let stdout_reader = BufReader::new(stdout);

    // Stream nix output through tracing with .context()?
    for line_result in stdout_reader.lines() {
        let line = line_result.context("Failed to read line from stdout")?;
        info!(target: "nix", "{}", line);
    }

    Ok(())
}


fn check_trusted_user() -> Result<()> {
    let output = Command::new("nix")
        .args(["config", "show", "trusted-users"])
        .output()
        .context("Failed to get nix trusted users")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("Failed to get nix trusted users"));
    }

    let trusted_users = String::from_utf8(output.stdout)
        .context("Failed to parse nix trusted users output")?;

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .context("Failed to get current username")?;

    if !trusted_users.contains(&username) {
        return Err(anyhow::anyhow!(
            "Current user '{}' is not in nix trusted-users. To fix this:\n\
            1. Edit /etc/nix/nix.conf with sudo:\n\
               $ sudo nano /etc/nix/nix.conf\n\
            2. Add your username to trusted-users line (create if doesn't exist):\n\
               trusted-users = root {}\n\
            3. Restart nix-daemon:\n\
               $ sudo systemctl restart nix-daemon",
            username, username
        ));
    }

    Ok(())
}
