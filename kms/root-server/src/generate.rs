use alloy::{
    primitives::keccak256,
    signers::{local::PrivateKeySigner, SignerSync},
};
use anyhow::{Context, Result};
use axum::{extract::State, http::StatusCode};
use nucypher_core::{
    encrypt_for_dkg, ferveo::api::DkgPublicKey, AccessControlPolicy, Conditions, ProtocolObject,
    ThresholdMessageKit,
};
use rand::{rngs::OsRng, RngCore};

use crate::AppState;

// generate new randomness and encyrpt it against the DKG key
pub async fn generate(State(state): State<AppState>) -> (StatusCode, String) {
    // check if randomness already exists
    let guard = state.randomness.lock().unwrap();
    if guard.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            "randomness already exists\n".into(),
        );
    }
    drop(guard);

    // generate randomness
    let mut randomness = vec![0u8; 512].into_boxed_slice();
    OsRng.fill_bytes(randomness.as_mut());

    // generate encrypted message
    let Ok(encrypted) = crate::taco::encrypt(
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

    // set randomness and encrypted
    let mut randomness_guard = state.randomness.lock().unwrap();
    let mut encrypted_guard = state.encrypted.lock().unwrap();
    *randomness_guard = Some(randomness);
    *encrypted_guard = encrypted.clone();
    drop(encrypted_guard);
    drop(randomness_guard);

    (StatusCode::OK, encrypted)
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
