//! View trait — materialised state derived from the event log.
//!
//! Spec §3.2 carves the indexer into "core" (decoders + raw-event sink)
//! and "views" (per-cluster derived state: leader, members, lifecycle).
//! This trait is the seam between the two: an Ingestor inside core knows
//! nothing about leaders or members, only that it must call
//! `View.apply()` after every event upsert and `View.replay()` on
//! demand for `?as_of_block=N` reads.

use crate::decode::DecodedEvent;
use crate::store::EventStore;

/// Materialised view over the event log. Implementations live in the
/// `teesql-views` crate (or any consumer's equivalent).
///
/// Both methods take `&self` so a view can be `Box<dyn View>`-shared
/// across the ingest worker and the read path. State must live in
/// Postgres (read via `store.pool()`), not in the View struct, so
/// historical replay produces deterministic answers regardless of
/// which process serves the read.
#[async_trait::async_trait]
pub trait View: Send + Sync {
    /// Apply one event to the view's materialised tables. Called inline
    /// from the ingest loop AFTER `events` has the row, so the view can
    /// safely read other events back from the same transaction context
    /// if needed.
    ///
    /// **Idempotency required.** WS replay on reconnect, the
    /// `INSERT ... ON CONFLICT DO NOTHING` dedup pattern, and reorg
    /// rollback + replay all call `apply` more than once for the same
    /// `(block_hash, log_index)`. Implementations must produce the same
    /// final state regardless of how many times they see the event.
    async fn apply(&self, store: &EventStore, event: &DecodedEvent) -> anyhow::Result<()>;

    /// Rebuild the view's answer for one `(chain_id, cluster)` pair as
    /// it would have been at `as_of_block`. Backs the
    /// `?as_of_block=N` historical query path (spec §5.2).
    ///
    /// Reads only from `events` filtered by `block_number <= as_of_block`
    /// AND `removed = false`; never touches the live materialised tables.
    /// Returns the JSON payload that the read endpoint serves under
    /// the response envelope's `data` field.
    async fn replay(
        &self,
        store: &EventStore,
        chain_id: i32,
        cluster: [u8; 20],
        as_of_block: u64,
    ) -> anyhow::Result<serde_json::Value>;

    /// Stable view name — written to `historical_query_cache.endpoint`
    /// and used as the path segment in the read API (e.g. "leader" →
    /// `GET /v1/:chain/clusters/:addr/leader`).
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_trait_object_is_send_sync() {
        // Compile-time check: Box<dyn View> must be Send + Sync so the
        // Ingestor can hold it across awaits.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn View>>();
    }
}
