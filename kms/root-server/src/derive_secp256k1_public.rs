use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
};
use hmac::{Hmac, Mac};
use kms_derive_utils::{derive_enclave_seed, derive_path_seed, to_secp256k1_public};
use oyster::axum::ScallopState;
use serde::Deserialize;
use sha2::Sha512;

use crate::{scallop::AuthStoreState, AppState};

#[derive(Deserialize)]
struct Params {
    pcr0: String,
    pcr1: String,
    pcr2: String,
    user_data: String,
    path: String,
}

// derive public key based on params
pub async fn derive_secp256k1_public(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 64]) {
    let Ok(pcr0) = hex::decode(params.pcr0) else {
        return (StatusCode::BAD_REQUEST, [0; 64]);
    };
    let Ok(pcr1) = hex::decode(params.pcr1) else {
        return (StatusCode::BAD_REQUEST, [0; 64]);
    };
    let Ok(pcr2) = hex::decode(params.pcr2) else {
        return (StatusCode::BAD_REQUEST, [0; 64]);
    };
    let Ok(user_data) = hex::decode(params.user_data) else {
        return (StatusCode::BAD_REQUEST, [0; 64]);
    };
    if user_data.len() > 65535 {
        return (StatusCode::BAD_REQUEST, [0; 64]);
    }

    let enclave_key = derive_enclave_seed(state.randomness, &pcr0, &pcr1, &pcr2, &user_data);
    let path_key = derive_path_seed(enclave_key, params.path.as_bytes());
    let public = to_secp256k1_public(path_key);

    (StatusCode::OK, public)
}
