use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
};

use crate::{scallop::ScallopState, AppState};

// derive keys after verifying attestations
pub async fn derive(
    ConnectInfo(scallop_state): ConnectInfo<ScallopState>,
    State(state): State<AppState>,
) -> (StatusCode, [u8; 64]) {
    // safe to unwrap since the server should always have an authstore
    let (pcrs, user_data) = scallop_state.0.unwrap();

    // TODO: derive key
    let derived_key = [0u8; 64];

    (StatusCode::OK, derived_key)
}
