use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::Parser;
use oyster::attestation::{verify as verify_attestation, AttestationExpectations};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    // path to attestation doc hex string file
    #[arg(long)]
    attestation: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let attestation = fs::read_to_string(&cli.attestation).context(format!(
        "Failed to read attestation hex string from {}",
        cli.attestation
    ))?;
    let attestation =
        hex::decode(attestation).context("Failed to decode attestation hex string")?;

    let decoded = verify_attestation(
        &attestation,
        AttestationExpectations {
            age: Some((
                300000,
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as usize,
            )),
            ..Default::default()
        },
    )
    .context("Failed to verify the attestation doc")?;

    println!("{:?}", decoded);

    Ok(())
}
