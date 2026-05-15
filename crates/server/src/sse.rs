//! SSE handler + Postgres `LISTEN chain_indexer_events` worker.
//!
//! SSE frames are intentionally **bare** (no per-frame signed
//! envelope) to keep fan-out latency in the single-digit-millisecond
//! range. Consumers that need cryptographic verification of a
//! specific event fetch the signed shape via
//! `GET /v1/:chain/events/:id` (see [`crate::routes::events`]) — the
//! REST companion documented in spec §7.3 returns the same row
//! wrapped in the standard signed envelope.
//!
//! Wire envelope per `network-architecture-unified.md §9.1` carries
//! `id`, `block_number`, `log_index`, `tx_hash`, `kind`, `decoded`,
//! `removed`, and `as_of`. `removed` is the reorg-rollback flag
//! propagated verbatim from the `events` row — fabric uses it to
//! evict cached admissions whose underlying chain commitment has
//! been rolled back, instead of waiting for the next 10-minute
//! RPC audit (§8). `as_of` carries the indexer's
//! `{finalized_block, block_timestamp, ...}` cursor so consumers
//! can run the §5.4 freshness gate
//! (`head_block - as_of.finalized_block <= LAG_MAX`, `now -
//! as_of.block_timestamp <= AGE_MAX`) on every admission-critical
//! frame without an extra REST round-trip.
//!
//! The handler builds a stream of `axum::response::sse::Event` frames
//! that combines two sources:
//!
//! 1. **Replay** — on connect, every event in `events` with `id >
//!    last_seen` matching the per-connection filter is read out of
//!    Postgres in id order and emitted as an SSE frame. This catches
//!    consumers up after a reconnect (`Last-Event-ID` header) or a
//!    cold start (`?since=<id>`). Reorged rows (`removed = true`)
//!    are included in the replay stream so a reconnecting consumer
//!    learns about rollbacks that landed during the disconnect.
//!
//! 2. **Live** — once replay drains, the handler subscribes to a
//!    `tokio::sync::broadcast::Receiver<NotifyEvent>` held by
//!    [`AppState::sse_tx`]. The broadcast bus is fed by two
//!    producers running in parallel: an in-process bridge from the
//!    `Ingestor` mpsc (zero-latency intra-process) and a
//!    `spawn_listen_worker` task that translates Postgres
//!    `LISTEN chain_indexer_events` notifications onto the same bus.
//!    Either producer is sufficient on its own; running both keeps
//!    the path open for cross-process producers without changing the
//!    handler. When the same event arrives on the bus via both
//!    paths (or overlaps between replay and the live tail), the
//!    per-connection [`RecentIds`] cache deduplicates by `event_id`
//!    so the consumer sees exactly one frame per id.
//!
//! Each emitted SSE frame carries `id: <event_id>` so a reconnecting
//! client's `Last-Event-ID` header is sufficient to resume.
//! `KeepAlive::new()` heartbeats every 15s so intermediate proxies
//! don't drop idle connections.

use std::collections::{HashSet, VecDeque};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

use crate::as_of::{self, AsOf, Safety};
use crate::error::ApiError;
use crate::routes::clusters::ClusterPath;
use crate::routes::events::parse_kinds;
use crate::state::MultiChainState;
use teesql_chain_indexer_core::ingest::{ControlNotifyEvent, NotifyEvent};
use teesql_chain_indexer_core::store::EventStore;

/// Per-connection recent-event-id cache used to deduplicate frames
/// when the same `event_id` arrives via more than one path on the
/// shared broadcast bus (in-proc Ingestor channel + Postgres LISTEN
/// worker), or when a live notify overlaps a row already covered by
/// the connection's replay backlog.
///
/// FIFO eviction at [`Self::CAP`]; the chain-indexer's per-cluster
/// event rate is single-digit per minute even at peak, so 1024
/// covers many minutes of overlap window. Memory cost is bounded —
/// 1024 ids × ~16 bytes = ~16 KB per open connection.
pub(crate) struct RecentIds {
    set: HashSet<i64>,
    order: VecDeque<i64>,
}

impl RecentIds {
    pub(crate) const CAP: usize = 1024;

    pub(crate) fn new() -> Self {
        Self {
            set: HashSet::with_capacity(Self::CAP),
            order: VecDeque::with_capacity(Self::CAP),
        }
    }

    /// Returns `true` on the first observation of `id` (caller should
    /// emit), `false` when the id is already in the recent window
    /// (caller skips). Inserts the id into the FIFO and evicts the
    /// oldest entry when the window grows past [`Self::CAP`].
    pub(crate) fn observe(&mut self, id: i64) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > Self::CAP {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            }
        }
        true
    }
}

#[derive(Deserialize, Default, Clone)]
pub struct SseQuery {
    pub since: Option<i64>,
    pub kind: Option<String>,
}

/// `GET /v1/:chain/clusters/:addr/events/sse`.
pub async fn sse_handler(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<ClusterPath>,
    Query(q): Query<SseQuery>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let app = crate::routes::common::resolve_chain(&state, &p.chain)?.clone();
    let cluster = crate::routes::common::parse_address(&p.addr)?;
    let kinds = parse_kinds(q.kind.as_deref()).unwrap_or_default();

    // Resume cursor: header beats query so an EventSource auto-reconnect
    // (which sets Last-Event-ID) overrides the original ?since.
    let since = parse_last_event_id(&headers).or(q.since).unwrap_or(0);

    let filter = SseFilter {
        cluster,
        kinds: Arc::new(kinds),
    };

    let store = app.store.clone();
    let pool = app.store.pool().clone();
    let chain_id = app.store.chain_id();
    let live_rx = app.sse_tx.subscribe();

    let stream = async_stream::stream! {
        let mut last_id = since;
        let mut recent = RecentIds::new();
        // Snapshot the indexer's `as_of` cursor and refresh it
        // alongside each backlog chunk / live frame. Cold-start
        // failure is non-fatal: frames emit with `as_of: null` so
        // consumers can fail-closed on admission paths while still
        // receiving the event coordinates.
        let mut cached_as_of: Option<AsOf> = snapshot_as_of(&store).await;

        // ---- 1. Replay backlog ----
        loop {
            match read_backlog(&pool, chain_id, &filter, last_id, 500).await {
                Ok(rows) if rows.is_empty() => break,
                Ok(rows) => {
                    if let Some(fresh) = snapshot_as_of(&store).await {
                        cached_as_of = Some(fresh);
                    }
                    for row in rows {
                        let id = row.id;
                        if !recent.observe(id) {
                            continue;
                        }
                        last_id = id;
                        let value = serialize_event_row(&row, cached_as_of.as_ref());
                        match build_event_frame(id, &value) {
                            Ok(frame) => yield Ok::<Event, Infallible>(frame),
                            Err(e) => {
                                tracing::warn!(error = %e, "drop SSE backlog frame");
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "SSE backlog read failed");
                    yield Ok::<Event, Infallible>(
                        Event::default().comment(format!("backlog error: {e}")),
                    );
                    return;
                }
            }
        }

        // ---- 2. Live tail ----
        let mut live = BroadcastStream::new(live_rx);
        while let Some(item) = live.next().await {
            match item {
                Ok(ev) => {
                    if !filter.matches(&ev) {
                        continue;
                    }
                    // Pre-fetch dedup: skip the row fetch entirely
                    // when this id already went out via the other
                    // broadcast producer (in-proc Ingestor channel +
                    // LISTEN worker both fire) or via replay.
                    if !recent.observe(ev.event_id) {
                        continue;
                    }
                    match read_row_by_id(&pool, chain_id, &filter, ev.event_id).await {
                        Ok(Some(row)) => {
                            let id = row.id;
                            last_id = id;
                            if let Some(fresh) = snapshot_as_of(&store).await {
                                cached_as_of = Some(fresh);
                            }
                            let value = serialize_event_row(&row, cached_as_of.as_ref());
                            match build_event_frame(id, &value) {
                                Ok(frame) => yield Ok::<Event, Infallible>(frame),
                                Err(e) => {
                                    tracing::warn!(error = %e, "drop SSE live frame");
                                }
                            }
                        }
                        Ok(None) => {
                            // Notify arrived but no row matches the
                            // SSE filter (cluster scope). Skip.
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "SSE live row fetch failed");
                        }
                    }
                }
                Err(_lagged) => {
                    // Subscriber lagged out of the broadcast buffer. We
                    // catch up by re-reading the backlog from `last_id`
                    // and resume the live tail with the same receiver.
                    match read_backlog(&pool, chain_id, &filter, last_id, 500).await {
                        Ok(rows) => {
                            if let Some(fresh) = snapshot_as_of(&store).await {
                                cached_as_of = Some(fresh);
                            }
                            for row in rows {
                                let id = row.id;
                                if !recent.observe(id) {
                                    continue;
                                }
                                last_id = id;
                                let value = serialize_event_row(&row, cached_as_of.as_ref());
                                if let Ok(frame) = build_event_frame(id, &value) {
                                    yield Ok::<Event, Infallible>(frame);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "SSE post-lag backlog read failed");
                        }
                    }
                }
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text(":keepalive"),
    ))
}

#[derive(Clone)]
struct SseFilter {
    cluster: [u8; 20],
    kinds: Arc<Vec<String>>,
}

impl SseFilter {
    fn matches(&self, ev: &NotifyEvent) -> bool {
        if ev.cluster != self.cluster {
            return false;
        }
        if self.kinds.is_empty() {
            return true;
        }
        self.kinds.iter().any(|k| k == &ev.kind)
    }
}

#[derive(Debug)]
struct EventRow {
    id: i64,
    block_number: i64,
    log_index: i32,
    tx_hash: Vec<u8>,
    decoded_kind: Option<String>,
    decoded: Option<Value>,
    removed: bool,
}

async fn read_backlog(
    pool: &sqlx::PgPool,
    chain_id: i32,
    filter: &SseFilter,
    after_id: i64,
    limit: i64,
) -> Result<Vec<EventRow>, ApiError> {
    let kinds: Vec<String> = filter.kinds.as_ref().clone();
    // `removed = true` rows are forwarded so fabric can react to
    // reorgs without waiting for the next 10-minute RPC audit
    // (`network-architecture-unified.md §9.1`).
    let rows = sqlx::query(
        "SELECT id, block_number, log_index, tx_hash, decoded_kind, decoded, removed
         FROM events
         WHERE chain_id = $1
           AND contract = $2
           AND id > $3
           AND ($4::text[] = '{}' OR decoded_kind = ANY($4))
         ORDER BY id
         LIMIT $5",
    )
    .bind(chain_id)
    .bind(&filter.cluster[..])
    .bind(after_id)
    .bind(&kinds)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(ApiError::from)?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(EventRow {
            id: row.try_get("id").map_err(ApiError::from)?,
            block_number: row.try_get("block_number").map_err(ApiError::from)?,
            log_index: row.try_get("log_index").map_err(ApiError::from)?,
            tx_hash: row.try_get("tx_hash").map_err(ApiError::from)?,
            decoded_kind: row.try_get("decoded_kind").map_err(ApiError::from)?,
            decoded: row.try_get("decoded").map_err(ApiError::from)?,
            removed: row.try_get("removed").map_err(ApiError::from)?,
        });
    }
    Ok(out)
}

async fn read_row_by_id(
    pool: &sqlx::PgPool,
    chain_id: i32,
    filter: &SseFilter,
    id: i64,
) -> Result<Option<EventRow>, ApiError> {
    // No `removed = false` filter — reorged rows are forwarded with
    // `removed: true` so live consumers see rollbacks as the live
    // notify or replay surfaces them.
    let row = sqlx::query(
        "SELECT id, block_number, log_index, tx_hash, decoded_kind, decoded, removed
         FROM events
         WHERE chain_id = $1 AND id = $2 AND contract = $3",
    )
    .bind(chain_id)
    .bind(id)
    .bind(&filter.cluster[..])
    .fetch_optional(pool)
    .await
    .map_err(ApiError::from)?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(EventRow {
        id: row.try_get("id").map_err(ApiError::from)?,
        block_number: row.try_get("block_number").map_err(ApiError::from)?,
        log_index: row.try_get("log_index").map_err(ApiError::from)?,
        tx_hash: row.try_get("tx_hash").map_err(ApiError::from)?,
        decoded_kind: row.try_get("decoded_kind").map_err(ApiError::from)?,
        decoded: row.try_get("decoded").map_err(ApiError::from)?,
        removed: row.try_get("removed").map_err(ApiError::from)?,
    }))
}

/// Snapshot the indexer's finalized cursor for inclusion in SSE
/// frames. Maps to the §5.4 freshness gate: consumers compute
/// `head_block - as_of.finalized_block <= LAG_MAX` and
/// `now - as_of.block_timestamp <= AGE_MAX` to decide whether the
/// indexer's view of chain state is fresh enough for admission.
///
/// Returns `None` on cold start (no blocks ingested yet) or any
/// transient resolver failure. The handler embeds `as_of: null`
/// in that case so consumers can fail-closed on admission paths
/// while still seeing the event coordinates.
async fn snapshot_as_of(store: &EventStore) -> Option<AsOf> {
    match as_of::resolve(store, Safety::Finalized, None).await {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::debug!(error = %e, "SSE as_of snapshot unavailable; emitting as_of=null");
            None
        }
    }
}

fn serialize_event_row(row: &EventRow, as_of: Option<&AsOf>) -> Value {
    let as_of_value = as_of.map(AsOf::to_json).unwrap_or(Value::Null);
    json!({
        "id": row.id,
        "block_number": row.block_number,
        "log_index": row.log_index,
        "tx_hash": format!("0x{}", hex::encode(&row.tx_hash)),
        "kind": row.decoded_kind,
        "decoded": row.decoded,
        "removed": row.removed,
        "as_of": as_of_value,
    })
}

fn build_event_frame(id: i64, value: &Value) -> Result<Event, anyhow::Error> {
    let body = serde_json::to_string(value)?;
    Ok(Event::default().id(id.to_string()).data(body))
}

fn parse_last_event_id(headers: &HeaderMap) -> Option<i64> {
    headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
}

// ---- Postgres LISTEN worker ----
//
// Long-lived task: opens a dedicated `PgListener` to the same pool,
// subscribes to `chain_indexer_events`, and forwards every notify
// payload onto the broadcast bus shared with the in-process
// Ingestor mpsc bridge. Failure to parse a payload is logged and
// dropped — the listener does not crash the worker.

/// Spawn the LISTEN→broadcast bridge. Caller keeps the join handle if
/// it wants to await completion on shutdown; the runtime drops it
/// at process exit otherwise.
pub fn spawn_listen_worker(
    pool: sqlx::PgPool,
    sender: broadcast::Sender<NotifyEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match listen_loop(&pool, &sender).await {
                Ok(()) => {
                    tracing::warn!("LISTEN loop exited cleanly; restarting");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "LISTEN loop errored; restarting in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    })
}

async fn listen_loop(
    pool: &sqlx::PgPool,
    sender: &broadcast::Sender<NotifyEvent>,
) -> Result<(), sqlx::Error> {
    let mut listener = sqlx::postgres::PgListener::connect_with(pool).await?;
    listener.listen("chain_indexer_events").await?;
    while let Some(notification) = listener.try_recv().await? {
        let payload = notification.payload();
        // `NotifyEvent`'s serde representation matches the pg_notify
        // payload byte-for-byte (cluster as 0x-hex string). The earlier
        // intermediate `NotifyPayload` shape was redundant and
        // accumulated drift from the producer side; deserializing
        // straight into `NotifyEvent` keeps producer + consumer locked
        // to a single canonical wire form.
        match serde_json::from_str::<NotifyEvent>(payload) {
            Ok(ev) => {
                // Best-effort send. No subscribers → drop on the floor.
                let _ = sender.send(ev);
            }
            Err(e) => {
                tracing::warn!(error = %e, payload, "drop unparseable LISTEN payload");
            }
        }
    }
    Ok(())
}

// ---- Control-plane LISTEN worker (Track D3) -------------------------
//
// Twin of `spawn_listen_worker` for the dedicated
// `chain_indexer_control` channel. The store's `notify_control` fires
// `ControlNotifyEvent` payloads; this bridges them onto a separate
// broadcast bus the per-cluster control SSE handler subscribes to.
// Keeping the buses separate prevents the `/events/sse` consumers
// from having to filter every per-instruction × per-member ack out
// of their feed.

/// Spawn the LISTEN→broadcast bridge for `chain_indexer_control`.
pub fn spawn_control_listen_worker(
    pool: sqlx::PgPool,
    sender: broadcast::Sender<ControlNotifyEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match control_listen_loop(&pool, &sender).await {
                Ok(()) => {
                    tracing::warn!("control LISTEN loop exited cleanly; restarting");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "control LISTEN loop errored; restarting in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    })
}

async fn control_listen_loop(
    pool: &sqlx::PgPool,
    sender: &broadcast::Sender<ControlNotifyEvent>,
) -> Result<(), sqlx::Error> {
    let mut listener = sqlx::postgres::PgListener::connect_with(pool).await?;
    listener.listen("chain_indexer_control").await?;
    while let Some(notification) = listener.try_recv().await? {
        let payload = notification.payload();
        match serde_json::from_str::<ControlNotifyEvent>(payload) {
            Ok(ev) => {
                let _ = sender.send(ev);
            }
            Err(e) => {
                tracing::warn!(error = %e, payload, "drop unparseable control LISTEN payload");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// First observation emits, second is suppressed. Mirrors the
    /// in-proc-Ingestor + Postgres-LISTEN double-delivery scenario:
    /// both producers push a `NotifyEvent` with the same `event_id`
    /// onto the broadcast bus; the SSE handler must surface exactly
    /// one frame to the consumer.
    #[test]
    fn recent_ids_dedups_repeat_observation() {
        let mut r = RecentIds::new();
        assert!(r.observe(42), "first observation emits");
        assert!(!r.observe(42), "duplicate is suppressed");
        assert!(r.observe(43), "distinct id passes");
        assert!(!r.observe(43), "second distinct id also dedups");
    }

    /// Past `CAP` distinct ids the oldest entry is evicted from the
    /// FIFO and re-observing it counts as a fresh emit. This bounds
    /// per-connection memory at ~16 KB while still covering many
    /// minutes of overlap window at TeeSQL fleet event rates.
    #[test]
    fn recent_ids_evicts_oldest_past_cap() {
        let mut r = RecentIds::new();
        // Fill the window with 0..CAP.
        for i in 0..(RecentIds::CAP as i64) {
            assert!(r.observe(i));
        }
        // The oldest (0) is still present; pushing a fresh id evicts it.
        assert!(!r.observe(0), "0 is still in the window");
        assert!(r.observe(RecentIds::CAP as i64), "fresh id pushes past cap");
        assert!(r.observe(0), "0 was evicted; re-observing emits");
    }

    fn sample_row(removed: bool, kind: &str) -> EventRow {
        EventRow {
            id: 17,
            block_number: 45_491_234,
            log_index: 3,
            tx_hash: vec![0xab; 32],
            decoded_kind: Some(kind.to_string()),
            decoded: Some(json!({"memberId": "0x01", "wgPubkey": "0x02"})),
            removed,
        }
    }

    fn sample_as_of() -> AsOf {
        AsOf {
            block_number: 45_491_222,
            block_hash: "0x".to_string() + &"cd".repeat(32),
            block_timestamp: 1_777_771_500,
            finalized_block: 45_491_222,
            safety: Safety::Finalized,
        }
    }

    /// Per `network-architecture-unified.md §9.1`, every admission-
    /// critical SSE frame must carry `id`, `block_number`, `log_index`,
    /// `tx_hash`, `kind`, `decoded`, `removed`, and `as_of`. Missing
    /// any of these in the serialized envelope is a contract break.
    #[test]
    fn serialize_event_row_emits_admission_critical_keys() {
        let row = sample_row(false, "MemberWgPubkeySetV2");
        let as_of = sample_as_of();
        let v = serialize_event_row(&row, Some(&as_of));
        let obj = v.as_object().expect("envelope is an object");
        for key in [
            "id",
            "block_number",
            "log_index",
            "tx_hash",
            "kind",
            "decoded",
            "removed",
            "as_of",
        ] {
            assert!(obj.contains_key(key), "envelope missing key `{key}`");
        }
        assert_eq!(obj["id"].as_i64(), Some(17));
        assert_eq!(obj["block_number"].as_i64(), Some(45_491_234));
        assert_eq!(obj["log_index"].as_i64(), Some(3));
        assert_eq!(
            obj["tx_hash"].as_str(),
            Some(format!("0x{}", "ab".repeat(32)).as_str())
        );
        assert_eq!(obj["kind"].as_str(), Some("MemberWgPubkeySetV2"));
        assert_eq!(obj["removed"].as_bool(), Some(false));
    }

    /// Reorged rows survive server-side filtering and reach the
    /// consumer with `removed: true` so fabric can evict cached
    /// admissions without waiting for the §8 10-minute RPC audit.
    #[test]
    fn serialize_event_row_forwards_removed_true() {
        let row = sample_row(true, "MemberWgPubkeySetV2");
        let v = serialize_event_row(&row, Some(&sample_as_of()));
        assert_eq!(
            v["removed"].as_bool(),
            Some(true),
            "removed=true must be forwarded verbatim, not filtered"
        );
    }

    /// `as_of` carries the indexer's `finalized_block` +
    /// `block_timestamp` cursor so consumers can run the §5.4
    /// freshness gate (`head_block - as_of.finalized_block <= 24`,
    /// `now - as_of.block_timestamp <= 300`) on every frame.
    #[test]
    fn serialize_event_row_attaches_as_of_freshness_fields() {
        let row = sample_row(false, "MemberWgPubkeySetV2");
        let as_of = sample_as_of();
        let v = serialize_event_row(&row, Some(&as_of));
        let as_of_obj = v
            .get("as_of")
            .and_then(Value::as_object)
            .expect("as_of present as object");
        assert_eq!(
            as_of_obj["finalized_block"].as_u64(),
            Some(45_491_222),
            "freshness gate needs finalized_block"
        );
        assert_eq!(
            as_of_obj["block_timestamp"].as_u64(),
            Some(1_777_771_500),
            "freshness gate needs block_timestamp"
        );
    }

    /// Cold-start path: until the indexer has finalized a block we
    /// emit `as_of: null` rather than dropping the event. Consumers
    /// fail-closed on admission paths but still see the coordinates.
    #[test]
    fn serialize_event_row_emits_null_as_of_on_cold_start() {
        let row = sample_row(false, "ComposeHashAllowed");
        let v = serialize_event_row(&row, None);
        assert!(
            v.get("as_of").is_some_and(Value::is_null),
            "as_of must be present as JSON null when snapshot is unavailable"
        );
        assert_eq!(v["kind"].as_str(), Some("ComposeHashAllowed"));
    }

    /// The serializer is kind-agnostic — each V2 event kind round-
    /// trips through the envelope verbatim, since the SSE layer
    /// reads `events.decoded_kind` straight from the row written by
    /// the W1-002 V2 decoders.
    #[test]
    fn serialize_event_row_carries_v2_event_kinds() {
        let as_of = sample_as_of();
        for kind in [
            "MemberWgPubkeySetV2",
            "ComposeHashAllowed",
            "ComposeHashRemoved",
            "TcbDegraded",
        ] {
            let row = sample_row(false, kind);
            let v = serialize_event_row(&row, Some(&as_of));
            assert_eq!(
                v["kind"].as_str(),
                Some(kind),
                "{kind} must be forwarded as-is"
            );
        }
    }

    /// The SQL filter accepts the V2 kinds CSV without parser-side
    /// rejection. (Wire-shape regression check; the query itself
    /// runs against Postgres in integration tests.)
    #[test]
    fn parse_kinds_accepts_v2_event_kinds() {
        let parsed = parse_kinds(Some(
            "MemberWgPubkeySetV2,ComposeHashAllowed,ComposeHashRemoved,TcbDegraded",
        ))
        .expect("non-empty kind list parses");
        assert_eq!(
            parsed,
            vec![
                "MemberWgPubkeySetV2".to_string(),
                "ComposeHashAllowed".to_string(),
                "ComposeHashRemoved".to_string(),
                "TcbDegraded".to_string(),
            ]
        );
    }
}
