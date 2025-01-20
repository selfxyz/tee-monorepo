use alloy::{
    hex,
    primitives::keccak256,
    signers::{local::PrivateKeySigner, SignerSync},
};
use anyhow::{Context, Result};
use axum::{extract::State, http::StatusCode};
use clap::Parser;
use nucypher_core::{
    encrypt_for_dkg, ferveo::api::DkgPublicKey, AccessControlPolicy, Conditions, ProtocolObject,
    ThresholdMessageKit,
};
use rand::{rngs::OsRng, RngCore};

#[derive(Clone)]
struct AppState {
    signer: PrivateKeySigner,
    conditions: Conditions,
    dkg_public_key: DkgPublicKey,
}

fn encrypt(
    message: &[u8],
    conditions: &Conditions,
    dkg_public_key: DkgPublicKey,
    auth_signer: PrivateKeySigner,
) -> Result<String> {
    // encrypt
    let (ciphertext, auth_data) =
        encrypt_for_dkg(message, &dkg_public_key, &conditions).context("encrypt failed")?;

    // calculate header hash
    let header_hash = keccak256(
        bincode::serialize(&ciphertext.header().context("failed to get header")?)
            .context("failed to serialize header")?,
    );

    // sign the header hash
    let authorization = auth_signer
        .sign_message_sync(header_hash.as_slice())
        .context("signing failed")?
        .as_bytes()
        .into();

    // create access control policy
    let acp = AccessControlPolicy {
        auth_data,
        authorization,
    };

    // create message kit
    let message_kit = ThresholdMessageKit { ciphertext, acp };

    Ok(hex::encode(message_kit.to_bytes()))
}

// generate new randomness and encyrpt it against the DKG key
async fn generate(State(state): State<AppState>) -> (StatusCode, String) {
    // generate randomness
    let mut randomness = [0u8; 64];
    OsRng.fill_bytes(randomness.as_mut());

    // generate encrypted message
    let Ok(encrypted) = encrypt(
        &randomness,
        &state.conditions,
        state.dkg_public_key,
        state.signer,
    ) else {
        // NOTE: Explicitly do not do anything with the error message
        // lest it leaks something about the encryption process
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to encrypt\n".into(),
        );
    };

    (StatusCode::OK, encrypted)
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// DKG listening address
    #[arg(long, default_value = "0.0.0.0:1100")]
    listen_addr: String,

    /// Path to file with private key signer
    #[arg(long, default_value = "/app/secp256k1.sec")]
    signer: String,

    /// Condition string for the key
    #[arg(long)]
    condition: String,

    /// DKG ceremony public key
    #[arg(long)]
    dkg_public_key: String,
}

fn main() {
    println!("Hello, world!");
}
