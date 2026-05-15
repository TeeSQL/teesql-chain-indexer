//! `cluster_compose_hashes` materializer — driven by
//! `ComposeHashAllowed` / `ComposeHashRemoved` (and the legacy
//! `ComposeHashAdded` synonym emitted by pre-rename dstack contracts).
//!
//! Per unified-network-design §4.2, the cluster's set of acceptable
//! MRTDs is the canonical allowlist that fabric uses for admission.
//! The on-chain model is monotonic: `addComposeHash` emits
//! `ComposeHashAllowed`, `removeComposeHash` emits
//! `ComposeHashRemoved`. The materialized view tracks one row per
//! `(chain_id, cluster_address, compose_hash)` with `allowed_at` /
//! `removed_at` block timestamps; a hash that has been re-added after
//! removal flips `removed_at` back to NULL.
//!
//! ## Stale-replay invariant
//!
//! Each row carries the `(block_number, log_index)` coordinates of
//! the most-recent event applied (`last_event_block`,
//! `last_event_log_index`). On every incoming event the materializer
//! compares the incoming coordinates against the stored pair before
//! flipping `removed_at`:
//!
//! - An allow strictly newer than the stored coordinates may clear
//!   `removed_at` (a genuine re-allow after a removal).
//! - An allow at or older than the stored coordinates is treated as
//!   a stale replay — `allowed_at` still picks up the `LEAST` clamp
//!   (so the canonical first-allow timestamp is preserved), but
//!   `removed_at` is left untouched. This closes the security bug
//!   where a WS-replayed duplicate `ComposeHashAllowed` arriving
//!   after a `ComposeHashRemoved` could reactivate a revoked MRTD.
//! - A remove strictly newer than the stored coordinates stamps
//!   `removed_at = block_ts`; older removes are no-ops via the same
//!   tuple comparison.
//!
//! The `allowed_at` / `removed_at` order-independent clamps
//! (`LEAST` / `GREATEST`) remain as before; the tuple comparison is
//! a strict gate layered on top of those for the
//! `removed_at = NULL` reactivation transition specifically.

use std::collections::{BTreeMap, HashMap};

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use sqlx::Row;

use crate::decoded;
use teesql_chain_indexer_core::{decode::DecodedEvent, store::EventStore, views::View};

pub struct ComposeHashesView;

impl ComposeHashesView {
    pub fn new() -> Self {
        ComposeHashesView
    }
}

impl Default for ComposeHashesView {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl View for ComposeHashesView {
    fn name(&self) -> &'static str {
        "compose_hashes"
    }

    async fn apply(&self, store: &EventStore, event: &DecodedEvent) -> Result<()> {
        match event.kind.as_deref() {
            // `ComposeHashAdded` is the legacy event name dstack
            // contracts emitted before the W0-001 rename; the new
            // `ComposeHashAllowed` carries identical wire layout.
            // Both route through the same apply path so the
            // materialized table is correct across the rename
            // boundary.
            Some("ComposeHashAllowed") | Some("ComposeHashAdded") => {
                apply_compose_hash_allowed(store, event).await
            }
            Some("ComposeHashRemoved") => apply_compose_hash_removed(store, event).await,
            _ => Ok(()),
        }
    }

    async fn replay(
        &self,
        store: &EventStore,
        chain_id: i32,
        cluster: [u8; 20],
        as_of_block: u64,
    ) -> Result<serde_json::Value> {
        let as_of_i64 = i64::try_from(as_of_block).context("as_of_block overflows i64")?;
        let rows = sqlx::query(
            "SELECT e.block_number, e.log_index, e.decoded_kind, e.decoded, b.block_ts \
             FROM events e \
             JOIN blocks b ON b.chain_id = e.chain_id AND b.number = e.block_number \
             WHERE e.chain_id = $1 AND e.contract = $2 AND e.removed = false \
               AND e.block_number <= $3 \
               AND e.decoded_kind IN ('ComposeHashAllowed', 'ComposeHashAdded', 'ComposeHashRemoved') \
             ORDER BY e.block_number, e.log_index",
        )
        .bind(chain_id)
        .bind(&cluster[..])
        .bind(as_of_i64)
        .fetch_all(store.pool())
        .await
        .context("fetch compose-hash events for replay")?;

        let mut events: Vec<DecodedEvent> = Vec::with_capacity(rows.len());
        let mut block_ts: HashMap<u64, i64> = HashMap::new();
        for row in rows {
            let block_number: i64 = row.try_get("block_number")?;
            let log_index: i32 = row.try_get("log_index")?;
            let kind: String = row.try_get("decoded_kind")?;
            let decoded_payload: Option<serde_json::Value> = row.try_get("decoded")?;
            let ts: i64 = row.try_get("block_ts")?;
            block_ts.insert(block_number as u64, ts);
            events.push(crate::synthetic_event(
                chain_id,
                cluster,
                block_number as u64,
                log_index,
                kind,
                decoded_payload,
            ));
        }

        replay_in_memory(&events, &block_ts, as_of_block)
    }
}

async fn apply_compose_hash_allowed(store: &EventStore, event: &DecodedEvent) -> Result<()> {
    let payload = event
        .decoded
        .as_ref()
        .ok_or_else(|| anyhow!("ComposeHashAllowed event has no decoded payload"))?;
    let compose_hash = decoded::member_id(payload, "composeHash")?;
    let allowed_at = lookup_block_ts(store, event.chain_id, event.block_number).await?;
    let event_block = i64::try_from(event.block_number).context("block_number overflows i64")?;
    let event_log_index = event.log_index;

    // `LEAST` clamp on `allowed_at` is order-independent (the
    // canonical first-allow timestamp wins), so it runs every time.
    //
    // The `removed_at` clear and `last_event_*` advance are gated on
    // a strict `(EXCLUDED.block, EXCLUDED.log_index) > (stored, ...)`
    // tuple comparison — only an allow strictly newer than the most
    // recent applied event re-activates the row. A NULL stored
    // coordinate (no prior event, or pre-migration row) is treated
    // as "always older" via `COALESCE`, so the very first event
    // wins unconditionally. This closes the security bug where a
    // duplicate `ComposeHashAllowed` re-delivered after a
    // `ComposeHashRemoved` would otherwise reactivate the revoked
    // MRTD.
    sqlx::query(
        "INSERT INTO cluster_compose_hashes \
            (chain_id, cluster_address, compose_hash, allowed_at, removed_at, \
             last_event_block, last_event_log_index) \
         VALUES ($1, $2, $3, $4, NULL, $5, $6) \
         ON CONFLICT (chain_id, cluster_address, compose_hash) DO UPDATE SET \
             allowed_at = LEAST(cluster_compose_hashes.allowed_at, EXCLUDED.allowed_at), \
             removed_at = CASE \
                 WHEN (EXCLUDED.last_event_block, EXCLUDED.last_event_log_index) \
                    > (COALESCE(cluster_compose_hashes.last_event_block, -1), \
                       COALESCE(cluster_compose_hashes.last_event_log_index, -1)) \
                 THEN NULL \
                 ELSE cluster_compose_hashes.removed_at \
             END, \
             last_event_block = CASE \
                 WHEN (EXCLUDED.last_event_block, EXCLUDED.last_event_log_index) \
                    > (COALESCE(cluster_compose_hashes.last_event_block, -1), \
                       COALESCE(cluster_compose_hashes.last_event_log_index, -1)) \
                 THEN EXCLUDED.last_event_block \
                 ELSE cluster_compose_hashes.last_event_block \
             END, \
             last_event_log_index = CASE \
                 WHEN (EXCLUDED.last_event_block, EXCLUDED.last_event_log_index) \
                    > (COALESCE(cluster_compose_hashes.last_event_block, -1), \
                       COALESCE(cluster_compose_hashes.last_event_log_index, -1)) \
                 THEN EXCLUDED.last_event_log_index \
                 ELSE cluster_compose_hashes.last_event_log_index \
             END, \
             updated_at = now()",
    )
    .bind(event.chain_id)
    .bind(&event.contract[..])
    .bind(&compose_hash[..])
    .bind(allowed_at)
    .bind(event_block)
    .bind(event_log_index)
    .execute(store.pool())
    .await
    .context("upsert cluster_compose_hashes for ComposeHashAllowed")?;

    Ok(())
}

async fn apply_compose_hash_removed(store: &EventStore, event: &DecodedEvent) -> Result<()> {
    let payload = event
        .decoded
        .as_ref()
        .ok_or_else(|| anyhow!("ComposeHashRemoved event has no decoded payload"))?;
    let compose_hash = decoded::member_id(payload, "composeHash")?;
    let removed_at = lookup_block_ts(store, event.chain_id, event.block_number).await?;
    let event_block = i64::try_from(event.block_number).context("block_number overflows i64")?;
    let event_log_index = event.log_index;

    // Mirror-symmetric to the allow path: `removed_at` is stamped
    // only when the incoming coordinates are strictly newer than
    // anything previously applied. A `GREATEST` clamp on
    // `removed_at` itself would suffice to defeat WS-replay
    // duplicates of the SAME remove, but it isn't enough on its
    // own — without the tuple comparison the row's
    // `last_event_block` / `last_event_log_index` would drift away
    // from the true latest event and the allow path could no longer
    // detect a stale duplicate allow. Both columns must be updated
    // by the same comparison so the pair stays consistent.
    sqlx::query(
        "INSERT INTO cluster_compose_hashes \
            (chain_id, cluster_address, compose_hash, allowed_at, removed_at, \
             last_event_block, last_event_log_index) \
         VALUES ($1, $2, $3, NULL, $4, $5, $6) \
         ON CONFLICT (chain_id, cluster_address, compose_hash) DO UPDATE SET \
             removed_at = CASE \
                 WHEN (EXCLUDED.last_event_block, EXCLUDED.last_event_log_index) \
                    > (COALESCE(cluster_compose_hashes.last_event_block, -1), \
                       COALESCE(cluster_compose_hashes.last_event_log_index, -1)) \
                 THEN EXCLUDED.removed_at \
                 ELSE cluster_compose_hashes.removed_at \
             END, \
             last_event_block = CASE \
                 WHEN (EXCLUDED.last_event_block, EXCLUDED.last_event_log_index) \
                    > (COALESCE(cluster_compose_hashes.last_event_block, -1), \
                       COALESCE(cluster_compose_hashes.last_event_log_index, -1)) \
                 THEN EXCLUDED.last_event_block \
                 ELSE cluster_compose_hashes.last_event_block \
             END, \
             last_event_log_index = CASE \
                 WHEN (EXCLUDED.last_event_block, EXCLUDED.last_event_log_index) \
                    > (COALESCE(cluster_compose_hashes.last_event_block, -1), \
                       COALESCE(cluster_compose_hashes.last_event_log_index, -1)) \
                 THEN EXCLUDED.last_event_log_index \
                 ELSE cluster_compose_hashes.last_event_log_index \
             END, \
             updated_at = now()",
    )
    .bind(event.chain_id)
    .bind(&event.contract[..])
    .bind(&compose_hash[..])
    .bind(removed_at)
    .bind(event_block)
    .bind(event_log_index)
    .execute(store.pool())
    .await
    .context("upsert cluster_compose_hashes for ComposeHashRemoved")?;

    Ok(())
}

async fn lookup_block_ts(store: &EventStore, chain_id: i32, block_number: u64) -> Result<i64> {
    let block_i64 = i64::try_from(block_number).context("block_number overflows i64")?;
    let row = sqlx::query("SELECT block_ts FROM blocks WHERE chain_id = $1 AND number = $2")
        .bind(chain_id)
        .bind(block_i64)
        .fetch_optional(store.pool())
        .await
        .context("look up block_ts for compose-hash event")?;
    match row {
        Some(r) => Ok(r.try_get::<i64, _>("block_ts")?),
        None => Err(anyhow!(
            "blocks row missing for chain_id={} block_number={} — core's ingest pipeline must upsert blocks before events",
            chain_id,
            block_number
        )),
    }
}

#[derive(Debug, Default, Clone)]
struct ComposeHashRow {
    allowed_at: Option<i64>,
    removed_at: Option<i64>,
    /// `(block_number, log_index)` of the most-recent event applied
    /// to this row. Compared as a tuple before flipping `removed_at`
    /// on allow or stamping it on remove; mirrors the SQL apply
    /// path's stale-replay-cannot-reactivate invariant.
    last_event: Option<(u64, i32)>,
}

impl ComposeHashRow {
    fn to_json(&self, compose_hash: &[u8; 32]) -> serde_json::Value {
        json!({
            "composeHash": decoded::hex0x(compose_hash),
            "allowedAt": self.allowed_at,
            "removedAt": self.removed_at,
            "active": self.allowed_at.is_some() && self.removed_at.is_none(),
        })
    }
}

/// In-memory replay over a pre-fetched event stream. Output is keyed
/// by compose-hash in lex order (BTreeMap) so the JSON is
/// deterministic regardless of event delivery order. Consumers that
/// only want the live set should filter `active == true`; the full
/// audit trail (including removed hashes) is exposed so a downstream
/// "hash was once allowed, when?" probe doesn't have to scan events
/// directly.
pub fn replay_in_memory(
    events: &[DecodedEvent],
    block_ts: &HashMap<u64, i64>,
    as_of_block: u64,
) -> Result<serde_json::Value> {
    let mut hashes: BTreeMap<[u8; 32], ComposeHashRow> = BTreeMap::new();

    for event in events {
        if event.block_number > as_of_block {
            continue;
        }
        let payload = match event.decoded.as_ref() {
            Some(p) => p,
            None => continue,
        };
        let ts = block_ts.get(&event.block_number).copied();
        let incoming_coord = (event.block_number, event.log_index);

        match event.kind.as_deref() {
            // Treat legacy `ComposeHashAdded` as a synonym for the
            // post-rename `ComposeHashAllowed` so historical events
            // emitted before the W0-001 contract rename converge to
            // the same active-set state on replay.
            Some("ComposeHashAllowed") | Some("ComposeHashAdded") => {
                let compose_hash = decoded::member_id(payload, "composeHash")?;
                let row = hashes.entry(compose_hash).or_default();
                // `allowed_at` clamp is order-independent: the
                // canonical first-allow timestamp wins regardless
                // of delivery order.
                row.allowed_at = match (row.allowed_at, ts) {
                    (Some(prev), Some(new)) => Some(prev.min(new)),
                    (Some(prev), None) => Some(prev),
                    (None, Some(new)) => Some(new),
                    (None, None) => None,
                };
                // Strict tuple comparison: only an allow strictly
                // newer than the most-recent event clears
                // `removed_at`. A duplicate older allow
                // re-delivered after a removal must NOT
                // reactivate the row.
                let is_newer = match row.last_event {
                    Some(prev) => incoming_coord > prev,
                    None => true,
                };
                if is_newer {
                    row.removed_at = None;
                    row.last_event = Some(incoming_coord);
                }
            }
            Some("ComposeHashRemoved") => {
                let compose_hash = decoded::member_id(payload, "composeHash")?;
                let row = hashes.entry(compose_hash).or_default();
                let is_newer = match row.last_event {
                    Some(prev) => incoming_coord > prev,
                    None => true,
                };
                if is_newer {
                    row.removed_at = ts;
                    row.last_event = Some(incoming_coord);
                }
            }
            _ => continue,
        }
    }

    let rows_json: Vec<serde_json::Value> = hashes.iter().map(|(h, row)| row.to_json(h)).collect();
    Ok(json!({ "composeHashes": rows_json }))
}
