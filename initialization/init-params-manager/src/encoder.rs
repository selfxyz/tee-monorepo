use std::{
    fs,
    path::{Component, PathBuf},
};

use anyhow::{bail, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use libsodium_sys::{crypto_box_SEALBYTES, crypto_box_seal, sodium_init};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Args {
    /// Init params list, supports the following forms:
    /// `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:utf8:<string>`
    /// `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:file:<local path>`
    #[arg(long)]
    init_params: Vec<String>,

    /// KMS public endpoint
    #[arg(long)]
    kms_endpoint: String,

    /// PCR0
    #[arg(long)]
    pcr0: String,

    /// PCR1
    #[arg(long)]
    pcr1: String,

    /// PCR2
    #[arg(long)]
    pcr2: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    run().inspect_err(|e| error!("{e:?}"))
}

fn run() -> Result<()> {
    // parse args
    let args = Args::parse();

    // SAFETY: no params, return value is checked properly
    if unsafe { sodium_init() } < 0 {
        bail!("failed to init libsodium");
    }

    // process in two passes since digest is needed to fetch public key

    // compute digest
    let digest = args
        .init_params
        .iter()
        .map(|param| {
            // extract components
            let param_components = param.splitn(5, ":").collect::<Vec<_>>();
            let should_attest = param_components[1] == "1";

            if !should_attest {
                return Ok(None);
            }

            // everything should be normal components, no root or current or parent dirs
            if PathBuf::from(param_components[0])
                .components()
                .any(|x| !matches!(x, Component::Normal(_)))
            {
                bail!("invalid path")
            }

            let enclave_path = PathBuf::from("/init-params/".to_owned() + param_components[0]);
            let should_encrypt = param_components[2] == "1";
            let contents = match param_components[3] {
                "utf8" => param_components[4].as_bytes().to_vec(),
                "file" => fs::read(param_components[4]).context("failed to read file")?,
                _ => bail!("unknown param type"),
            };

            info!(
                path = param_components[0],
                should_attest, should_encrypt, "digest"
            );

            // compute individual digest
            let mut hasher = Sha256::new();
            hasher.update(enclave_path.as_os_str().len().to_le_bytes());
            hasher.update(enclave_path.as_os_str().as_encoded_bytes());
            hasher.update(contents.len().to_le_bytes());
            hasher.update(contents);

            Ok(Some(hasher.finalize()))
        })
        .collect::<Result<Vec<_>>>()
        .context("failed to compute individual digest")?
        .into_iter()
        .flatten()
        // accumulate futher into a single hash
        .fold(Sha256::new(), |mut hasher, param_hash| {
            hasher.update(param_hash);
            hasher
        })
        .finalize();

    // fetch key
    let pk = fetch_encryption_key(
        &args.kms_endpoint,
        &args.pcr0,
        &args.pcr1,
        &args.pcr2,
        &hex::encode(digest),
    )
    .context("failed to fetch key")?;

    // prepare init params
    let params = args
        .init_params
        .iter()
        .map(|param| {
            // extract components
            let param_components = param.splitn(5, ":").collect::<Vec<_>>();
            let should_attest = param_components[1] == "1";
            let should_encrypt = param_components[2] == "1";
            let contents = match param_components[3] {
                "utf8" => param_components[4].as_bytes().to_vec(),
                "file" => fs::read(param_components[4]).context("failed to read file")?,
                _ => bail!("unknown param type"),
            };

            info!(
                path = param_components[0],
                should_attest, should_encrypt, "param"
            );

            // encrypt if needed
            let final_contents = if should_encrypt {
                let mut final_contents = vec![0u8; contents.len() + crypto_box_SEALBYTES as usize];
                // SAFETY: buffer is big enough for the encrypted message
                // pk is the right size
                unsafe {
                    crypto_box_seal(
                        final_contents.as_mut_ptr(),
                        contents.as_ptr(),
                        contents.len() as u64,
                        pk.as_ptr(),
                    )
                };
                final_contents
            } else {
                contents
            };

            let init_param = InitParam {
                path: param_components[0].to_owned(),
                contents: BASE64_STANDARD.encode(final_contents),
                should_attest,
                should_decrypt: should_encrypt,
            };

            Ok(init_param)
        })
        .collect::<Result<Vec<_>>>()
        .context("failed to build init params")?;

    // create final init params
    let init_params = InitParamsList {
        digest: BASE64_STANDARD.encode(digest),
        params,
    };

    let json =
        serde_json::to_string_pretty(&init_params).context("failed to serialize init params")?;

    info!("JSON: {}", json);
    info!("BASE64: {}", BASE64_STANDARD.encode(json));

    Ok(())
}

fn fetch_encryption_key(
    endpoint: &str,
    pcr0: &str,
    pcr1: &str,
    pcr2: &str,
    user_data: &str,
) -> Result<[u8; 32]> {
    Ok(ureq::get(endpoint.to_owned() + "/derive/x25519/public")
        .query("pcr0", pcr0)
        .query("pcr1", pcr1)
        .query("pcr2", pcr2)
        .query("user_data", user_data)
        .query("path", "oyster.init-params")
        .call()
        .context("failed to call derive server")?
        .body_mut()
        .read_to_vec()
        .context("failed to read body")?
        .as_slice()
        .try_into()
        .context("failed to parse reponse")?)
}

#[derive(Serialize)]
struct InitParam {
    path: String,
    contents: String, // base64 encoded
    should_attest: bool,
    should_decrypt: bool,
}

#[derive(Serialize)]
struct InitParamsList {
    digest: String, // base64 encoded
    params: Vec<InitParam>,
}
