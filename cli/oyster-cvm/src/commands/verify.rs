use anyhow::{Context, Result};
use tracing::info;

use oyster::{get_attestation_doc, verify};

pub async fn verify_image(
    pcr1: &String, 
    pcr2: &String, 
    pcr3: &String, 
    cpu: &String, 
    memory: &String,
    enclave_ip: &String, 
    attestation_port: &u16,
    max_age: &usize
) -> Result<()> {
    let attestation_endpoint = format!("http://{}:{}", enclave_ip, attestation_port);
    let attestation_doc = get_attestation_doc(attestation_endpoint.parse()?)
        .await
        .context("Failed to get attestation document from enclave")?;

    let pub_key = verify(
        attestation_doc,
        vec![pcr1.clone(), pcr2.clone(), pcr3.clone()],
        cpu.parse().context("Failed to parse CPU value")?,
        memory.parse().context("Failed to parse memory value")?,
        *max_age,
    ).context("Failed to verify attestation document")?;

    info!("Public key verified from enclave attestation");
    info!("PCR values: PCR1={}, PCR2={}, PCR3={}", pcr1, pcr2, pcr3);
    info!("CPU: {}, Memory: {}", cpu, memory);
    info!("Public key: {:?}", pub_key);
    Ok(())
}
