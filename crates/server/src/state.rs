//! Shared state plumbed into every axum handler + tonic method.
//!
//! Holds the Postgres-backed event store, the response signer, the
//! per-endpoint materialized-view dispatch table, and the broadcast
//! sender that fans the Postgres `LISTEN chain_indexer_events`
//! channel out to every active SSE connection.
//!
//! A second mpsc channel (held by `Ingestor` in
//! `core::ingest`) is bridged into the same broadcast so subscribers
//! see events at sub-millisecond latency without a Postgres round-
//! trip — the LISTEN path is still kept as a safety net for cross-
//! process producers (multi-instance HA, eventually).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::broadcast;

use teesql_chain_indexer_attest::Signer;
use teesql_chain_indexer_core::{ingest::NotifyEvent, store::EventStore, views::View};

/// Per-server runtime configuration. Kept separate from the
/// chain-indexer's binary-level `Config` so the server crate stays
/// transport-only.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// SSE connection cap. Enforced by the route layer; the broadcast
    /// channel itself doesn't bound subscribers, only buffered frames
    /// per subscriber.
    pub sse_max_connections: usize,
    /// Per-source-IP rps cap applied via tower governor. 0 disables.
    pub rate_limit_rps: u32,
    /// Lifetime of a signed response in seconds; threaded through to
    /// `Signer::sign(...)`. Mirrors `[attestation].response_lifetime_s`
    /// from the binary config.
    pub response_lifetime_s: u64,
    /// Default chain shortname used when a request omits the path
    /// segment (used only by gRPC stream methods that take the
    /// shortname as a field). REST always carries it in the URL.
    pub default_chain: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            sse_max_connections: 1000,
            rate_limit_rps: 50,
            response_lifetime_s: 300,
            default_chain: "base".to_string(),
        }
    }
}

/// One [`AppState`] per chain. The route layer's `:chain` segment
/// indexes into a [`MultiChainState`] to recover the right
/// AppState before invoking the handler.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<EventStore>,
    pub signer: Arc<Signer>,

    /// Materialized-view dispatchers, keyed on `View::name()`. The
    /// route layer looks the view up by endpoint-name string ("leader"
    /// / "members" / "lifecycle"); every replay/apply flows through
    /// the same trait impl so REST and gRPC don't drift.
    pub views: Arc<HashMap<&'static str, Arc<dyn View>>>,

    /// Broadcast sender fanned out to every SSE connection. Two
    /// producers feed it: (a) the in-process bridge from
    /// `core::Ingestor`'s mpsc, (b) the Postgres LISTEN worker. See
    /// `crate::sse::spawn_listen_worker`.
    pub sse_tx: broadcast::Sender<NotifyEvent>,

    pub config: ServerConfig,

    /// Process boot time — used by the unsigned `/v1/health` route
    /// to render `uptime_seconds`.
    pub started_at: Instant,
}

/// Multi-chain wrapper. The router resolves `:chain` against this
/// map before invoking a handler; if missing, the route layer
/// returns 404 with `unknown chain`. One Postgres pool per chain
/// keeps connection-budget accounting honest at the indexer level.
#[derive(Clone)]
pub struct MultiChainState {
    pub by_shortname: Arc<HashMap<String, AppState>>,
    /// The signer is shared across all chains (one process = one
    /// app_id = one KMS-derived signing key). Carried separately so
    /// chain-agnostic routes (`/v1/health`, `/v1/attestation`,
    /// `/v1/chains`, `/v1/metrics`) can reach it without picking an
    /// arbitrary AppState.
    pub signer: Arc<Signer>,
    pub started_at: Instant,
}

impl MultiChainState {
    pub fn lookup(&self, chain: &str) -> Option<&AppState> {
        self.by_shortname.get(chain)
    }
}
