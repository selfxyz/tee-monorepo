use clap::Parser;
use oyster::attestation::{get, verify, AttestationExpectations};
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// endpoint of the attestation server (http://<ip:port>)
    #[clap(short, long, value_parser)]
    endpoint: String,

    /// expected pcr0
    #[arg(long)]
    pcr0: String,

    /// expected pcr1
    #[arg(long)]
    pcr1: String,

    /// expected pcr2
    #[arg(long)]
    pcr2: String,

    /// maximum age of attestation (in milliseconds)
    #[arg(short, long)]
    max_age: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let pcrs: [[u8; 48]; 3] = [
        hex::decode(cli.pcr0)?.as_slice().try_into()?,
        hex::decode(cli.pcr1)?.as_slice().try_into()?,
        hex::decode(cli.pcr2)?.as_slice().try_into()?,
    ];
    let attestation_doc = get(cli.endpoint.parse()?).await?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as usize;
    let decoded = verify(
        attestation_doc,
        AttestationExpectations {
            age: Some((cli.max_age, now)),
            pcrs: Some(pcrs),
            ..Default::default()
        },
    )?;
    println!("verification successful: {:?}", decoded);

    Ok(())
}
