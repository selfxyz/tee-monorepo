use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
};
use kms_derive_utils::derive_enclave_seed_contract;
use oyster::axum::ScallopState;
use serde::Deserialize;

use crate::{scallop::AuthStoreState, AppState};

#[derive(Deserialize)]
pub struct Params {
    address: String,
}

// derive keys after verifying attestations
pub async fn derive(
    ConnectInfo(scallop_state): ConnectInfo<ScallopState<AuthStoreState>>,
    State(state): State<AppState>,
    Query(params): Query<Params>,
) -> (StatusCode, [u8; 64]) {
    // TODO: Verify if key is verified on the contract

    let derived_key =
        derive_enclave_seed_contract(state.randomness, state.chain_id, &params.address);

    (StatusCode::OK, derived_key)
}
