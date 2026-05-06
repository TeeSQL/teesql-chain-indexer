//! axum HTTP + SSE routes and gRPC mirror under
//! `teesql.chain_indexer.v1`. Every signed read endpoint wraps its
//! payload in the spec §7.1 envelope and is independently verifiable
//! via the attestation surface defined in spec §4.
//!
//! Public entry points:
//!
//! - [`build_router`] — assembles the REST + SSE surface for axum.
//! - [`build_grpc_service`] — assembles the tonic service trait
//!   implementation; callers hand it to `tonic::transport::Server`.
//! - [`spawn_listen_worker`] — bridges Postgres
//!   `LISTEN chain_indexer_events` onto the broadcast bus the SSE
//!   and gRPC streaming handlers subscribe to.
//!
//! All shared types live in [`state`]; per-domain trait objects come
//! from `teesql-chain-indexer-{core,views,attest}` directly.

pub mod as_of;
pub mod envelope;
pub mod error;
pub mod grpc;
pub mod metrics;
pub mod query;
pub mod routes;
pub mod sse;
pub mod state;

use std::sync::Arc;

use axum::Router;

use grpc::proto::chain_indexer_server::ChainIndexerServer;
use grpc::ChainIndexerService;
use metrics::Metrics;
use state::MultiChainState;

pub use sse::{spawn_control_listen_worker, spawn_listen_worker};

/// Assemble the REST + SSE router. Mount at `/`; every path is
/// already namespaced under `/v1/...`.
pub fn build_router(state: Arc<MultiChainState>, metrics: Arc<Metrics>) -> Router {
    routes::router(state, metrics)
}

/// Wrap [`ChainIndexerService`] in the tonic-generated server type
/// ready for `tonic::transport::Server::add_service`.
pub fn build_grpc_service(state: Arc<MultiChainState>) -> ChainIndexerServer<ChainIndexerService> {
    ChainIndexerServer::new(ChainIndexerService::new(state))
}
