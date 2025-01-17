use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
};
use hmac::{Hmac, Mac};
use oyster::axum::ScallopState;
use sha2::Sha512;

use crate::{scallop::AuthStoreState, AppState};

// derivation format:
// 1 byte
//
// why no version?
// the current version is immutable
// new versions will need to obtain new randomness
// the PCRs of the current version are the version

// derive keys after verifying attestations
pub async fn derive(
    ConnectInfo(scallop_state): ConnectInfo<ScallopState<AuthStoreState>>,
    State(state): State<AppState>,
) -> (StatusCode, [u8; 64]) {
    let Some(randomness) = state.randomness.lock().unwrap().clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, [0; 64]);
    };

    // safe to unwrap since the server should always have an authstore
    let (pcrs, user_data) = scallop_state.0.unwrap();

    if user_data.len() > 65535 {
        return (StatusCode::BAD_REQUEST, [0; 64]);
    }

    let Ok(mut mac) = Hmac::<Sha512>::new_from_slice(&randomness) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, [0; 64]);
    };
    mac.update(&pcrs[0]);
    mac.update(&pcrs[1]);
    mac.update(&pcrs[2]);
    mac.update(&(user_data.len() as u16).to_be_bytes());
    mac.update(&user_data);

    let derived_key = mac.finalize().into_bytes().into();

    (StatusCode::OK, derived_key)
}
