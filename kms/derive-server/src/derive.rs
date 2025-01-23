use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha512;

use crate::AppState;

// derivation format:
// 1 byte
//
// why no version?
// the current version is immutable
// new versions will need to obtain new randomness
// the PCRs of the current version are the version

#[derive(Deserialize)]
struct Params {
    path: String,
}

// derive keys based on derivation path
pub async fn derive(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 64]) {
    let Ok(mut mac) = Hmac::<Sha512>::new_from_slice(&state.randomness) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, [0; 64]);
    };
    mac.update(params.path.as_bytes());

    let derived_key = mac.finalize().into_bytes().into();

    (StatusCode::OK, derived_key)
}
