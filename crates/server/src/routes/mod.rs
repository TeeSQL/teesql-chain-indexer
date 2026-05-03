//! Wires every spec §7.1 endpoint into a single `axum::Router`.
//! Path parameters are extracted by the typed `Path<...>` shapes
//! defined in each route module so tests can reuse them.
//!
//! Layering:
//! - The full `Router` carries the [`MultiChainState`] in
//!   `with_state`. Per-chain handlers look up `:chain` in the state's
//!   `by_shortname` map; chain-agnostic ones (health, attestation,
//!   chains list, metrics) just read the shared signer + metrics
//!   handles.
//! - `tower_http` adds CORS (open in v1; spec §2 says "v1 is open
//!   access"), gzip compression on read responses, and a default
//!   `request-id` header so consumers can correlate across the
//!   sidecar fleet.
//! - The metrics router is mounted on the same path the spec
//!   advertises (`/v1/metrics`); a separate `Arc<Metrics>` state is
//!   threaded into it so the rest of the routes don't need to carry
//!   the metrics handle.

use std::sync::Arc;

use axum::{routing::get, Router};
use tower_http::cors::CorsLayer;

use crate::metrics::Metrics;
use crate::state::MultiChainState;

pub mod attestation;
pub mod chains;
pub mod clusters;
pub mod common;
pub mod events;
pub mod factories;
pub mod health;
pub mod metrics_route;
pub mod proof;

/// Build the public REST router. The caller mounts it at `/`; every
/// path is namespaced under `/v1/...` already.
pub fn router(state: Arc<MultiChainState>, metrics: Arc<Metrics>) -> Router {
    let v1 = Router::new()
        // Chain-agnostic
        .route("/health", get(health::health))
        .route("/attestation", get(attestation::attestation))
        .route("/chains", get(chains::list_chains))
        // Per-chain reads
        .route("/:chain/chain", get(chains::get_chain))
        .route(
            "/:chain/factories/:addr/clusters",
            get(factories::list_factory_clusters),
        )
        .route(
            "/:chain/factories/:addr/contains",
            get(factories::factory_contains),
        )
        .route("/:chain/clusters/:addr", get(clusters::cluster_overview))
        .route(
            "/:chain/clusters/:addr/leader",
            get(clusters::cluster_leader),
        )
        .route(
            "/:chain/clusters/:addr/leader/proof",
            get(proof::cluster_leader_proof),
        )
        .route(
            "/:chain/clusters/:addr/members",
            get(clusters::cluster_members),
        )
        .route(
            "/:chain/clusters/:addr/members/proof",
            get(proof::cluster_members_proof),
        )
        .route(
            "/:chain/clusters/:addr/members/:member_id",
            get(clusters::cluster_member),
        )
        .route(
            "/:chain/clusters/:addr/lifecycle",
            get(clusters::cluster_lifecycle),
        )
        .route(
            "/:chain/clusters/:addr/lifecycle/proof",
            get(proof::cluster_lifecycle_proof),
        )
        .route("/:chain/clusters/:addr/events", get(events::list_events))
        .route("/:chain/clusters/:addr/events/sse", get(events::sse_events))
        // Verification companion to bare SSE frames (spec §7.3): a
        // consumer receives the bare event over SSE for low-latency
        // fan-out and follows up with this signed-envelope lookup
        // when it needs cryptographic proof of a specific event id.
        .route("/:chain/events/:id", get(events::get_event_by_id))
        .with_state(state.clone());

    let metrics_router = Router::new()
        .route("/metrics", get(metrics_route::metrics))
        .with_state(metrics);

    Router::new()
        .nest("/v1", v1.merge(metrics_router))
        .layer(CorsLayer::permissive())
}
