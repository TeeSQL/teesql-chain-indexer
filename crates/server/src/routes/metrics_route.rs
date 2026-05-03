//! `GET /v1/metrics` — Prometheus text format.
//!
//! Counters / gauges live behind atomics in [`crate::metrics::Metrics`].
//! Each is recorded by the matching subsystem: `events_*` by the
//! ingest worker (Agent 3), `sse_*` by [`crate::sse`], `signer_*` by
//! the envelope builder, etc. The route here just renders the
//! current snapshot.

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use std::sync::Arc;

use crate::metrics::Metrics;

pub async fn metrics(State(metrics): State<Arc<Metrics>>) -> (HeaderMap, String) {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (headers, metrics.render())
}
