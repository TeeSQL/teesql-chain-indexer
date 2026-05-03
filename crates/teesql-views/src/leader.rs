//! `cluster_leader` materializer — driven by `LeaderClaimed`.
//!
//! Storage row: `(chain_id, cluster_address, member_id, epoch, as_of_block)`.
//! Update rule: replace only when the incoming `epoch` is *strictly* greater
//! than the stored value. Strict inequality is what protects against
//! out-of-order WS replay and reorg-driven re-application — equal-epoch
//! events are no-ops, lower-epoch events are no-ops.
//!
//! When equal-epoch events disagree on `memberId` we log a warning;
//! that's an invariant the on-chain logic should rule out (an epoch
//! is the leader-claim's monotone counter and only the winning claim
//! should ever surface), but if it ever fires we want to know.

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use sqlx::Row;
use tracing::warn;

use crate::decoded;
use teesql_chain_indexer_core::{decode::DecodedEvent, store::EventStore, views::View};

pub struct LeaderView;

impl LeaderView {
    pub fn new() -> Self {
        LeaderView
    }
}

impl Default for LeaderView {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl View for LeaderView {
    fn name(&self) -> &'static str {
        "leader"
    }

    async fn apply(&self, store: &EventStore, event: &DecodedEvent) -> Result<()> {
        if event.kind.as_deref() != Some("LeaderClaimed") {
            return Ok(());
        }
        let decoded_payload = event
            .decoded
            .as_ref()
            .ok_or_else(|| anyhow!("LeaderClaimed event has no decoded payload"))?;

        let member_id = decoded::member_id(decoded_payload, "memberId")?;
        let epoch = decoded::uint_as_i64(decoded_payload, "epoch")?;
        let as_of_block =
            i64::try_from(event.block_number).context("event.block_number overflows i64")?;

        let result = sqlx::query(
            "INSERT INTO cluster_leader \
                (chain_id, cluster_address, member_id, epoch, as_of_block) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (chain_id, cluster_address) DO UPDATE SET \
                 member_id   = EXCLUDED.member_id, \
                 epoch       = EXCLUDED.epoch, \
                 as_of_block = EXCLUDED.as_of_block, \
                 updated_at  = now() \
             WHERE cluster_leader.epoch < EXCLUDED.epoch",
        )
        .bind(event.chain_id)
        .bind(&event.contract[..])
        .bind(&member_id[..])
        .bind(epoch)
        .bind(as_of_block)
        .execute(store.pool())
        .await
        .context("upsert into cluster_leader")?;

        if result.rows_affected() == 0 {
            // The conflict path's predicate skipped the update. Either
            // (a) the incoming epoch is < existing — silent no-op (replay
            // safety), or (b) equal epoch with possibly-different memberId
            // — a warning case worth surfacing.
            let existing = sqlx::query(
                "SELECT member_id, epoch FROM cluster_leader \
                 WHERE chain_id = $1 AND cluster_address = $2",
            )
            .bind(event.chain_id)
            .bind(&event.contract[..])
            .fetch_optional(store.pool())
            .await
            .context("read cluster_leader for warning check")?;

            if let Some(row) = existing {
                let existing_member: Vec<u8> = row.try_get("member_id")?;
                let existing_epoch: i64 = row.try_get("epoch")?;
                if existing_epoch == epoch && existing_member != member_id.as_slice() {
                    warn!(
                        chain_id = event.chain_id,
                        cluster = %decoded::hex0x(&event.contract),
                        epoch,
                        existing_member = %decoded::hex0x(&existing_member),
                        new_member = %decoded::hex0x(&member_id),
                        "LeaderClaimed at equal epoch but different memberId"
                    );
                }
            }
        }
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
            "SELECT block_number, log_index, decoded \
             FROM events \
             WHERE chain_id = $1 AND contract = $2 AND removed = false \
               AND block_number <= $3 AND decoded_kind = 'LeaderClaimed' \
             ORDER BY block_number, log_index",
        )
        .bind(chain_id)
        .bind(&cluster[..])
        .bind(as_of_i64)
        .fetch_all(store.pool())
        .await
        .context("fetch LeaderClaimed events for replay")?;

        let events: Vec<DecodedEvent> = rows
            .into_iter()
            .map(|row| -> Result<DecodedEvent> {
                let block_number: i64 = row.try_get("block_number")?;
                let log_index: i32 = row.try_get("log_index")?;
                let decoded_payload: Option<serde_json::Value> = row.try_get("decoded")?;
                Ok(crate::synthetic_event(
                    chain_id,
                    cluster,
                    block_number as u64,
                    log_index,
                    "LeaderClaimed".to_string(),
                    decoded_payload,
                ))
            })
            .collect::<Result<_>>()?;

        replay_in_memory(&events, as_of_block)
    }
}

/// In-memory replay over a pre-fetched event stream. Pulled out so it's
/// directly testable without a Postgres handle.
pub fn replay_in_memory(events: &[DecodedEvent], as_of_block: u64) -> Result<serde_json::Value> {
    let mut current: Option<([u8; 32], i64)> = None;

    for event in events {
        if event.block_number > as_of_block {
            continue;
        }
        if event.kind.as_deref() != Some("LeaderClaimed") {
            continue;
        }
        let payload = match event.decoded.as_ref() {
            Some(p) => p,
            None => continue,
        };
        let member = decoded::member_id(payload, "memberId")?;
        let epoch = decoded::uint_as_i64(payload, "epoch")?;

        match current {
            Some((existing_member, existing_epoch)) if epoch <= existing_epoch => {
                if epoch == existing_epoch && existing_member != member {
                    warn!(
                        chain_id = event.chain_id,
                        epoch,
                        existing_member = %decoded::hex0x(&existing_member),
                        new_member = %decoded::hex0x(&member),
                        "replay observed equal-epoch LeaderClaimed with disagreeing memberId"
                    );
                }
            }
            _ => current = Some((member, epoch)),
        }
    }

    Ok(match current {
        Some((member, epoch)) => json!({
            "memberId": decoded::hex0x(&member),
            "epoch": epoch,
            "asOfBlock": as_of_block,
        }),
        None => json!({
            "memberId": decoded::hex0x(&[0u8; 32]),
            "epoch": 0_i64,
            "asOfBlock": as_of_block,
        }),
    })
}
