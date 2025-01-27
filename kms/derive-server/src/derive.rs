use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use kms_derive_utils::derive_path_seed;
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
pub struct Params {
    path: String,
}

// derive keys based on derivation path
pub async fn derive(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 64]) {
    let derived_key = derive_path_seed(state.randomness, params.path.as_bytes());

    (StatusCode::OK, derived_key)
}
