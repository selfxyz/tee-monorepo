use axum::{extract::State, http::StatusCode};

use crate::AppState;

// import encrypted randomness
pub async fn import(State(state): State<AppState>, encrypted: String) -> (StatusCode, String) {
    let Ok(encrypted_bytes) = hex::decode(&encrypted) else {
        return (StatusCode::BAD_REQUEST, "failed to decode payload\n".into());
    };

    let Ok(randomness) = crate::taco::decrypt(
        &encrypted_bytes,
        state.ritual,
        &state.taco_nodes,
        state.threshold,
        &state.porter,
        &state.signer,
        state.chain_id,
    )
    .await
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to decrypt payload\n".into(),
        );
    };

    // set randomness and encrypted
    let mut randomness_guard = state.randomness.lock().unwrap();
    let mut encrypted_guard = state.encrypted.lock().unwrap();
    *randomness_guard = Some(randomness);
    *encrypted_guard = encrypted;
    drop(encrypted_guard);
    drop(randomness_guard);

    (StatusCode::OK, "Done\n".into())
}
