use axum::{extract::State, http::StatusCode};
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
    let encrypted = vec![0u8; 512].into_boxed_slice();
    // TODO: call nucypher

    // set randomness and encrypted
    let mut randomness_guard = state.randomness.lock().unwrap();
    let mut encrypted_guard = state.encrypted.lock().unwrap();
    *randomness_guard = Some(randomness);
    *encrypted_guard = encrypted;
    drop(encrypted_guard);
    drop(randomness_guard);

    (StatusCode::OK, "Done\n".into())
}
