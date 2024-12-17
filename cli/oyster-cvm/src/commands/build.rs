use crate::types::Platform;
use anyhow::{Context, Result};
use log::info;
use std::process::Command;

pub fn build_enclave_image(
    platform: Platform,
    docker_compose: &str,
    docker_images: &[String],
    output: &str,
) -> Result<()> {
    info!("Building enclave image with:");
    info!("  Platform: {}", platform.as_str());
    info!("  Docker compose: {}", docker_compose);
    info!("  Docker images: {}", docker_images.join(", "));

    let docker_images_list = docker_images.join(" ");

    let nix_expr = format!(
        r#"((builtins.getFlake "github:marlinprotocol/oyster-monorepo").packages.{}.sdks.docker-enclave.override {{compose={};dockerImages=[{}];}}).default"#,
        platform.nix_arch(),
        docker_compose,
        docker_images_list
    );

    let status = Command::new("nix")
        .args([
            "build",
            "--impure",
            "--expr",
            &nix_expr,
            "-vL",
            "--out-link",
            output,
        ])
        .status()
        .context("Failed to execute Nix build command")?;

    if status.success() {
        info!("Build successful: {}", output);
        Ok(())
    } else {
        Err(anyhow::anyhow!("Build failed"))
    }
}
