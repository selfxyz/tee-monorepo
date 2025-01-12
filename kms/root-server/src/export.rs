use axum::{extract::State, http::StatusCode};

use crate::AppState;

pub async fn export(State(state): State<AppState>) -> (StatusCode, String) {
    (StatusCode::OK, state.encrypted.lock().unwrap().clone())
}
