use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use kms_derive_utils::{derive_enclave_seed, derive_path_seed, to_secp256k1_ethereum_address};
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
pub struct Params {
    pcr0: String,
    pcr1: String,
    pcr2: String,
    user_data: String,
    path: String,
}

// derive public key based on params
pub async fn derive_secp256k1_address_ethereum(
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, String) {
    let Ok(pcr0) = hex::decode(params.pcr0) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    let Ok(pcr1) = hex::decode(params.pcr1) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    let Ok(pcr2) = hex::decode(params.pcr2) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    let Ok(user_data) = hex::decode(params.user_data) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    if user_data.len() > 65535 {
        return (StatusCode::BAD_REQUEST, String::new());
    }

    let enclave_key = derive_enclave_seed(state.randomness, &pcr0, &pcr1, &pcr2, &user_data);
    let path_key = derive_path_seed(enclave_key, params.path.as_bytes());
    let address = to_secp256k1_ethereum_address(path_key);

    (StatusCode::OK, address)
}
