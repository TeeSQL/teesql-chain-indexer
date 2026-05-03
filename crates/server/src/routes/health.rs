//! `GET /v1/health` — liveness. Unsigned. Cheap; called by the
//! Phala health probe and by external monitoring.

use axum::extract::State;
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use crate::state::MultiChainState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub uptime_seconds: u64,
    pub version: &'static str,
}

pub async fn health(State(state): State<Arc<MultiChainState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        uptime_seconds: state.started_at.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION"),
    })
}
