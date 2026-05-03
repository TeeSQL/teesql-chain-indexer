//! `cluster_lifecycle` materializer — driven by `ClusterDestroyed`.
//!
//! Storage row: `(chain_id, cluster_address, destroyed_at)` where
//! `destroyed_at IS NULL` means active. The contract emits
//! `ClusterDestroyed` exactly once per cluster, so the apply path is
//! a single upsert; re-application via WS replay is idempotent
//! because the block timestamp is stable across re-deliveries of
//! the same event.
//!
//! The decoded payload itself carries no fields the materializer
//! needs (`event ClusterDestroyed(uint256 timestamp)` is decoded
//! by Agent 2 to `{}` per the integration brief — the on-chain
//! `timestamp` arg duplicates `block.timestamp`, and we use the
//! canonical `blocks.block_ts` instead so the materialized table
//! stays in lock-step with whatever timestamp the events table
//! commits to).

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use sqlx::Row;

use teesql_chain_indexer_core::{decode::DecodedEvent, store::EventStore, views::View};

pub struct LifecycleView;

impl LifecycleView {
    pub fn new() -> Self {
        LifecycleView
    }
}

impl Default for LifecycleView {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl View for LifecycleView {
    fn name(&self) -> &'static str {
        "lifecycle"
    }

    async fn apply(&self, store: &EventStore, event: &DecodedEvent) -> Result<()> {
        if event.kind.as_deref() != Some("ClusterDestroyed") {
            return Ok(());
        }
        let block_i64 =
            i64::try_from(event.block_number).context("event.block_number overflows i64")?;
        let destroyed_at: i64 = sqlx::query("SELECT block_ts FROM blocks WHERE chain_id = $1 AND number = $2")
            .bind(event.chain_id)
            .bind(block_i64)
            .fetch_optional(store.pool())
            .await
            .context("look up block_ts for ClusterDestroyed")?
            .ok_or_else(|| anyhow!(
                "blocks row missing for chain_id={} block_number={} — core's ingest pipeline must upsert blocks before events",
                event.chain_id, event.block_number
            ))?
            .try_get("block_ts")?;

        sqlx::query(
            "INSERT INTO cluster_lifecycle \
                (chain_id, cluster_address, destroyed_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (chain_id, cluster_address) DO UPDATE SET \
                 destroyed_at = EXCLUDED.destroyed_at, \
                 updated_at   = now()",
        )
        .bind(event.chain_id)
        .bind(&event.contract[..])
        .bind(destroyed_at)
        .execute(store.pool())
        .await
        .context("upsert cluster_lifecycle")?;

        Ok(())
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
            "SELECT e.block_number, e.log_index, b.block_ts \
             FROM events e \
             JOIN blocks b ON b.chain_id = e.chain_id AND b.number = e.block_number \
             WHERE e.chain_id = $1 AND e.contract = $2 AND e.removed = false \
               AND e.block_number <= $3 AND e.decoded_kind = 'ClusterDestroyed' \
             ORDER BY e.block_number, e.log_index \
             LIMIT 1",
        )
        .bind(chain_id)
        .bind(&cluster[..])
        .bind(as_of_i64)
        .fetch_all(store.pool())
        .await
        .context("fetch ClusterDestroyed for replay")?;

        let mut events: Vec<DecodedEvent> = Vec::with_capacity(rows.len());
        let mut block_ts: HashMap<u64, i64> = HashMap::new();
        for row in rows {
            let block_number: i64 = row.try_get("block_number")?;
            let log_index: i32 = row.try_get("log_index")?;
            let ts: i64 = row.try_get("block_ts")?;
            block_ts.insert(block_number as u64, ts);
            events.push(crate::synthetic_event(
                chain_id,
                cluster,
                block_number as u64,
                log_index,
                "ClusterDestroyed".to_string(),
                Some(serde_json::json!({})),
            ));
        }

        replay_in_memory(&events, &block_ts, as_of_block)
    }
}

/// In-memory replay. The first `ClusterDestroyed <= as_of_block` wins —
/// the on-chain contract emits it at most once per cluster, so anything
/// past the first occurrence in event order would be a chain anomaly,
/// not normal traffic.
pub fn replay_in_memory(
    events: &[DecodedEvent],
    block_ts: &HashMap<u64, i64>,
    as_of_block: u64,
) -> Result<serde_json::Value> {
    for event in events {
        if event.block_number > as_of_block {
            continue;
        }
        if event.kind.as_deref() != Some("ClusterDestroyed") {
            continue;
        }
        if let Some(&ts) = block_ts.get(&event.block_number) {
            return Ok(json!({ "destroyedAt": ts }));
        }
    }
    Ok(json!({ "destroyedAt": serde_json::Value::Null }))
}
