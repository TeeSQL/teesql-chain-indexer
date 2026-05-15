//! `cluster_compose_hashes` materializer — driven by
//! `ComposeHashAllowed` / `ComposeHashRemoved`.
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
//! Re-application of the same event (WS replay, HA double-write) is
//! idempotent: the upsert clamps `allowed_at` to the earliest seen
//! and `removed_at` to the latest, so out-of-order delivery still
//! converges to the chain-canonical state.

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
            Some("ComposeHashAllowed") => apply_compose_hash_allowed(store, event).await,
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
               AND e.decoded_kind IN ('ComposeHashAllowed', 'ComposeHashRemoved') \
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

    // `LEAST` clamp on `allowed_at` so an out-of-order replay that
    // delivers a later allow before the original first-add doesn't
    // backdate the row. Re-allowing a previously-removed hash clears
    // `removed_at` so fabric's allowlist view picks the row back up
    // without an explicit "re-allowed" event kind.
    sqlx::query(
        "INSERT INTO cluster_compose_hashes \
            (chain_id, cluster_address, compose_hash, allowed_at, removed_at) \
         VALUES ($1, $2, $3, $4, NULL) \
         ON CONFLICT (chain_id, cluster_address, compose_hash) DO UPDATE SET \
             allowed_at = LEAST(cluster_compose_hashes.allowed_at, EXCLUDED.allowed_at), \
             removed_at = NULL, \
             updated_at = now()",
    )
    .bind(event.chain_id)
    .bind(&event.contract[..])
    .bind(&compose_hash[..])
    .bind(allowed_at)
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

    // `GREATEST` on `removed_at` so a later re-removal sticks even
    // when an out-of-order replay delivers an earlier removal first.
    // If the row doesn't exist yet (removal observed before its
    // matching add — out-of-order ingest), insert a sparse row with
    // a NULL `allowed_at` so the audit trail remains complete.
    sqlx::query(
        "INSERT INTO cluster_compose_hashes \
            (chain_id, cluster_address, compose_hash, allowed_at, removed_at) \
         VALUES ($1, $2, $3, NULL, $4) \
         ON CONFLICT (chain_id, cluster_address, compose_hash) DO UPDATE SET \
             removed_at = GREATEST(\
                 COALESCE(cluster_compose_hashes.removed_at, EXCLUDED.removed_at), \
                 EXCLUDED.removed_at\
             ), \
             updated_at = now()",
    )
    .bind(event.chain_id)
    .bind(&event.contract[..])
    .bind(&compose_hash[..])
    .bind(removed_at)
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

        match event.kind.as_deref() {
            Some("ComposeHashAllowed") => {
                let compose_hash = decoded::member_id(payload, "composeHash")?;
                let row = hashes.entry(compose_hash).or_default();
                row.allowed_at = match (row.allowed_at, ts) {
                    (Some(prev), Some(new)) => Some(prev.min(new)),
                    (Some(prev), None) => Some(prev),
                    (None, Some(new)) => Some(new),
                    (None, None) => None,
                };
                row.removed_at = None;
            }
            Some("ComposeHashRemoved") => {
                let compose_hash = decoded::member_id(payload, "composeHash")?;
                let row = hashes.entry(compose_hash).or_default();
                row.removed_at = match (row.removed_at, ts) {
                    (Some(prev), Some(new)) => Some(prev.max(new)),
                    (Some(prev), None) => Some(prev),
                    (None, Some(new)) => Some(new),
                    (None, None) => None,
                };
            }
            _ => continue,
        }
    }

    let rows_json: Vec<serde_json::Value> = hashes.iter().map(|(h, row)| row.to_json(h)).collect();
    Ok(json!({ "composeHashes": rows_json }))
}
