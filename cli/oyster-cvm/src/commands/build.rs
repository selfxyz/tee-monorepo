use crate::types::Platform;
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use tracing::info;

pub fn build_oyster_image(
    platform: Platform,
    docker_compose: &str,
    docker_images: &[String],
    output: &str,
    commit_ref: &str,
) -> Result<()> {
    info!("Building oyster-cvm image with:");
    info!("  Platform: {}", platform.as_str());
    info!("  Docker compose: {}", docker_compose);
    info!("  Commit ref: {}", commit_ref);

    let docker_images_list = docker_images.join(" ");
    if !docker_images_list.is_empty() {
        info!("  Docker images: {}", docker_images_list);
    }

    let nix_expr = format!(
        r#"((builtins.getFlake "github:marlinprotocol/oyster-monorepo?rev={}").packages.{}.musl.sdks.docker-enclave.override {{compose={};dockerImages=[{}];}}).default"#,
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

    info!("Build finished");

    Ok(())
}
