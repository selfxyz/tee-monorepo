use axum::{extract::State, http::StatusCode};

use crate::AppState;

// import encrypted randomness
pub async fn import(State(state): State<AppState>, encrypted: String) -> (StatusCode, String) {
    let Ok(encrypted_bytes) = hex::decode(&encrypted) else {
        return (StatusCode::BAD_REQUEST, "failed to decode payload\n".into());
    };

    let randomness = vec![0u8; 512].into_boxed_slice();
    // TODO: decrypt

    // set randomness and encrypted
    let mut randomness_guard = state.randomness.lock().unwrap();
    let mut encrypted_guard = state.encrypted.lock().unwrap();
    *randomness_guard = Some(randomness);
    *encrypted_guard = encrypted;
    drop(encrypted_guard);
    drop(randomness_guard);

    (StatusCode::OK, "Done\n".into())
}
