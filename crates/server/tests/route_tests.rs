//! Route-handler integration tests for the chain-agnostic surface.
//!
//! Per the audit's P1-8 finding, no HTTP route handler had any unit
//! coverage. The full surface comes in three tiers:
//!
//!   1. Chain-agnostic, signer-only (`/v1/health`, `/v1/attestation`,
//!      `/`): testable in-process with a tower::oneshot call against
//!      the assembled router. No Postgres needed; the env-override
//!      Signer path bypasses dstack. These tests are NOT `#[ignore]`-
//!      gated — they run as part of the default `cargo test` pass.
//!
//!   2. Per-chain reads that hit the EventStore (clusters/*, events/*,
//!      chains/*): require a real Postgres pool with the
//!      chain-indexer's schema applied. Filed as a v0.4.0 followup —
//!      needs a sqlx::test or testcontainers harness; one row of
//!      coverage there is worth the infra setup but it doesn't fit
//!      this round.
//!
//!   3. SSE long-poll: needs a worker thread + broadcast bus; covered
//!      end-to-end at the application level by the existing dns-
//!      controller `indexer_sse` tests, which mock the indexer side
//!      with wiremock.
//!
//! These tests cover Tier 1 thoroughly; the gaps in Tier 2 and Tier 3
//! are documented inline.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tokio::sync::broadcast;
use tower::ServiceExt;

use teesql_chain_indexer_attest::{AttestConfig, Signer};
use teesql_chain_indexer_server::metrics::Metrics;
use teesql_chain_indexer_server::state::{MultiChainState, ServerConfig};

/// Build a Signer in env-override mode for tests. Bypasses dstack;
/// boot quote is empty; signer_address is the keccak256-derived
/// address of the override key. Async because `Signer::from_dstack`
/// is async — calling it via a nested `block_on` inside a
/// `#[tokio::test]` panics ("cannot start a runtime from within a
/// runtime"), so callers must `.await` from inside the test's runtime.
async fn override_signer(env: &str) -> Arc<Signer> {
    std::env::set_var(
        env,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    let cfg = AttestConfig {
        kms_purpose: "test".into(),
        kms_path: String::new(),
        override_key_env: env.into(),
        response_lifetime_s: 300,
    };
    let signer = Signer::from_dstack(&cfg).await.unwrap();
    std::env::remove_var(env);
    Arc::new(signer)
}

/// Build a chain-agnostic-only MultiChainState — no per-chain entries,
/// since the routes we test here don't index into `by_shortname`.
/// Per-chain routes that do (clusters/*, events/*) get a 404 from this
/// state, which is itself an asserted behavior.
async fn build_chain_agnostic_state(env: &str) -> Arc<MultiChainState> {
    Arc::new(MultiChainState {
        by_shortname: Arc::new(HashMap::new()),
        signer: override_signer(env).await,
        started_at: Instant::now(),
    })
}

fn build_router(state: Arc<MultiChainState>) -> axum::Router {
    let metrics = Metrics::new();
    teesql_chain_indexer_server::build_router(state, metrics)
}

async fn body_to_json(body: Body) -> Value {
    let collected = body.collect().await.expect("collect body").to_bytes();
    serde_json::from_slice(&collected).expect("parse JSON body")
}

// ── /v1/health (chain-agnostic, unsigned) ──────────────────────────

/// Happy path: GET /v1/health returns 200 with the documented
/// envelope shape (status / uptime_seconds / version).
#[tokio::test]
async fn health_returns_ok_with_status_and_uptime_and_version() {
    let state = build_chain_agnostic_state("TEESQL_CI_HEALTH_ROUTE_OK").await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_json(resp.into_body()).await;
    assert_eq!(body["status"], "ok");
    assert!(
        body.get("uptime_seconds").and_then(Value::as_u64).is_some(),
        "uptime_seconds present and integer: {body}"
    );
    let version = body
        .get("version")
        .and_then(Value::as_str)
        .expect("version present");
    assert!(!version.is_empty(), "version non-empty");
}

/// `/v1/health` is an unsigned route — the response must NOT carry the
/// signed-envelope shape (`data`/`as_of`/`attestation`). Keeping it
/// unsigned is a load-bearing design choice: health probes from
/// Phala / external monitoring shouldn't pay the signing cost on every
/// hit. Pin so a refactor that wraps it in `build_signed` trips here.
#[tokio::test]
async fn health_response_is_unsigned() {
    let state = build_chain_agnostic_state("TEESQL_CI_HEALTH_UNSIGNED").await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_to_json(resp.into_body()).await;
    assert!(
        body.get("attestation").is_none(),
        "health is unsigned: {body}"
    );
    assert!(body.get("data").is_none(), "health is unsigned: {body}");
}

/// Wrong method → 405 (axum's typed-router default). Pinned because
/// some external probes hit endpoints with HEAD; we want the failure
/// to be a clean 405 rather than a 200 of the wrong shape.
#[tokio::test]
async fn health_rejects_non_get_methods() {
    let state = build_chain_agnostic_state("TEESQL_CI_HEALTH_405").await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ── /v1/attestation (chain-agnostic, unsigned) ─────────────────────

/// `/v1/attestation` returns the signer address + boot quote. In
/// env-override mode the boot quote is empty (signaling
/// `attestation_disabled`); the signer_address is still required.
#[tokio::test]
async fn attestation_returns_signer_address_and_empty_boot_quote_in_override_mode() {
    let state = build_chain_agnostic_state("TEESQL_CI_ATTEST_OVERRIDE").await;
    let signer_address = format!(
        "0x{}",
        hex::encode(state.signer.signer_address().as_slice())
    );
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/attestation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_to_json(resp.into_body()).await;
    assert_eq!(
        body["signer_address"].as_str().unwrap().to_lowercase(),
        signer_address.to_lowercase(),
        "signer address matches Signer::signer_address()"
    );
    // Override mode: boot quote is empty.
    assert_eq!(body["quote_b64"], "");
}

/// Like `/v1/health`, the `/v1/attestation` endpoint is unsigned —
/// the boot quote IS the attestation; wrapping it in another envelope
/// would be misleading.
#[tokio::test]
async fn attestation_response_is_unsigned() {
    let state = build_chain_agnostic_state("TEESQL_CI_ATTEST_UNSIGNED").await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/attestation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_to_json(resp.into_body()).await;
    assert!(
        body.get("attestation").is_none(),
        "attestation is unsigned: {body}"
    );
}

// ── / (root info banner) ───────────────────────────────────────────

/// `GET /` returns the unsigned service-info banner. Catch-all that
/// gives operators a friendly first-hit landing instead of a 404.
#[tokio::test]
async fn root_returns_service_info_banner() {
    let state = build_chain_agnostic_state("TEESQL_CI_ROOT_BANNER").await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_to_json(resp.into_body()).await;
    assert_eq!(body["service"], "teesql-chain-indexer");
    assert!(body.get("version").is_some());
    assert!(body.get("docs").is_some());
    assert!(body.get("api").is_some());
}

// ── /v1/chains (chain-agnostic) ────────────────────────────────────

/// `/v1/chains` is documented as chain-agnostic, but iterates every
/// per-chain AppState in `by_shortname` to build the summaries — and
/// that path hits the DB. With an empty `by_shortname` (our test
/// state) the response is an empty list. Validate the wire shape so a
/// future refactor can't accidentally drop the `chains` field.
#[tokio::test]
async fn chains_list_returns_empty_for_zero_chains() {
    let state = build_chain_agnostic_state("TEESQL_CI_CHAINS_EMPTY").await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/chains")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_to_json(resp.into_body()).await;
    let arr = body
        .get("chains")
        .and_then(Value::as_array)
        .expect("chains field is array");
    assert!(arr.is_empty(), "no chains configured: {body}");
}

// ── 404 surface ────────────────────────────────────────────────────

/// Per-chain routes 404 cleanly when the requested `:chain` isn't in
/// the state map. Without the DB-aware setup we can't test the
/// happy-path of this surface, but we CAN pin that an unknown chain
/// yields a clean error rather than a panic.
#[tokio::test]
async fn unknown_per_chain_route_404s_cleanly() {
    let state = build_chain_agnostic_state("TEESQL_CI_UNKNOWN_CHAIN").await;
    let app = build_router(state);

    // /v1/<unknown-chain>/chain — chain "ethereum" isn't configured.
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/ethereum/chain")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Either 404 (typed router miss) or 4xx with an error body — we
    // only care that we don't 5xx (panic) or 200 (silent success).
    let status = resp.status();
    assert!(status.is_client_error(), "expected 4xx, got {}", status);

    let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
    let body_str = String::from_utf8_lossy(&bytes);
    // Either an empty body (raw 404) or a JSON error envelope — both
    // are valid; the assertion is just "not a panic backtrace".
    assert!(
        body_str.is_empty()
            || serde_json::from_str::<Value>(&body_str).is_ok()
            || body_str.contains("not found")
            || body_str.contains("unknown"),
        "expected clean error body, got: {body_str}"
    );
}

/// A path that doesn't exist at all (not `:chain` shaped) → 404.
#[tokio::test]
async fn nonexistent_route_returns_404() {
    let state = build_chain_agnostic_state("TEESQL_CI_NONEXISTENT").await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/totally-not-a-route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── /v1/metrics (Prometheus) ───────────────────────────────────────

/// The Prometheus metrics route is mounted on the same router; verify
/// it returns the text/plain content type Prometheus expects, with a
/// 200 even before any metrics have been recorded.
#[tokio::test]
async fn metrics_route_returns_prometheus_text() {
    let state = build_chain_agnostic_state("TEESQL_CI_METRICS_ROUTE").await;
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    // Prometheus exposition format — text/plain (or
    // application/openmetrics-text; either is fine for the consumer).
    assert!(
        ct.starts_with("text/plain") || ct.contains("openmetrics"),
        "unexpected metrics content-type: {ct}"
    );
}

// Suppress unused-import warning when the broadcast bus isn't actually
// needed in the chain-agnostic state — a future test that simulates a
// per-chain AppState will need it.
#[allow(dead_code)]
fn _broadcast_bus() -> broadcast::Sender<()> {
    broadcast::channel::<()>(16).0
}

#[allow(dead_code)]
fn _server_config_default() -> ServerConfig {
    ServerConfig::default()
}
