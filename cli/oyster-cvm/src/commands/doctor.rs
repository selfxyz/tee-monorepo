use crate::types::Dependency;
use anyhow::Result;
use log::{error, info};
use std::process::Command;

pub fn run_doctor() -> Result<()> {
    check_dependency(Dependency::Docker)?;
    check_dependency(Dependency::Nix)?;
    Ok(())
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
