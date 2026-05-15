//! Materializers for cluster state. Each `View` consumes decoded
//! events and updates a summary table (`cluster_leader`,
//! `cluster_members`, `cluster_lifecycle`) inline with ingestion;
//! re-runnable from the `events` log if a view ever drifts.
//!
//! The three views also implement a `replay()` path that reconstructs
//! their state at an arbitrary historical `as_of_block` from the
//! event log directly — that's what backs `?as_of_block=N` on the
//! HTTP API. Replay is purely additive: it only reads from `events`
//! and `blocks`, never from the materialized tables.
//!
pub mod compose_hashes;
pub mod decoded;
pub mod leader;
pub mod lifecycle;
pub mod members;

pub use compose_hashes::ComposeHashesView;
pub use leader::LeaderView;
pub use lifecycle::LifecycleView;
pub use members::MembersView;
pub use teesql_chain_indexer_core::{decode::DecodedEvent, store::EventStore, views::View};

/// Construct the canonical set of materializer views the indexer
/// drives. Order is irrelevant — `apply()` is dispatched by event
/// kind, so every view filters down to its own concern at the top
/// of `apply()`.
pub fn all_views() -> Vec<Box<dyn View>> {
    vec![
        Box::new(LeaderView::new()),
        Box::new(MembersView::new()),
        Box::new(LifecycleView::new()),
        Box::new(ComposeHashesView::new()),
    ]
}

/// Build a `DecodedEvent` from a fetched-for-replay row. Replay paths
/// pull only the columns they need (`block_number`, `log_index`,
/// `decoded_kind`, `decoded`) and surface them through a synthetic
/// `DecodedEvent` so the in-memory replay logic is testable directly
/// against `Vec<DecodedEvent>` fixtures. Tx-hash / block-hash / topic
/// fields are zeroed because the in-memory replay never reads them.
pub(crate) fn synthetic_event(
    chain_id: i32,
    cluster: [u8; 20],
    block_number: u64,
    log_index: i32,
    kind: String,
    decoded_payload: Option<serde_json::Value>,
) -> DecodedEvent {
    DecodedEvent {
        chain_id,
        contract: cluster,
        block_number,
        block_hash: [0u8; 32],
        log_index,
        tx_hash: [0u8; 32],
        topic0: [0u8; 32],
        topics_rest: Vec::new(),
        data: Vec::new(),
        kind: Some(kind),
        decoded: decoded_payload,
    }
}
