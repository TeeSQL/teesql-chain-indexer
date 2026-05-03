//! `cluster_members` materializer — driven by `MemberRegistered`,
//! `PublicEndpointUpdated`, and `MemberRetired`.
//!
//! Each event touches a different subset of the row's columns:
//!
//! - `MemberRegistered` upserts the registration-time fields
//!   (instance_id, passthrough, dns_label, registered_at). It must
//!   leave `public_endpoint` and `retired_at` untouched on conflict
//!   so a `PublicEndpointUpdated` or `MemberRetired` that landed
//!   first isn't clobbered when WS replay or HA double-write
//!   re-delivers `MemberRegistered`.
//!
//! - `PublicEndpointUpdated` writes only `public_endpoint`. If the
//!   row doesn't exist (out-of-order arrival or a stub-creating
//!   replay), we insert a sparse row and emit a warning so the
//!   gap is visible in logs.
//!
//! - `MemberRetired` writes only `retired_at`. If the row doesn't
//!   exist we emit a warning and drop the event — there's no row
//!   to back-stamp.
//!
//! Block timestamps for `registered_at` / `retired_at` come from the
//! `blocks` row keyed by `(chain_id, block_number)`. The blocks row
//! is upserted by core's ingest pipeline before the event row hits
//! the table, so the lookup is always present in steady-state.

use std::collections::{BTreeMap, HashMap};

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use sqlx::Row;
use tracing::warn;

use crate::decoded;
use teesql_chain_indexer_core::{decode::DecodedEvent, store::EventStore, views::View};

pub struct MembersView;

impl MembersView {
    pub fn new() -> Self {
        MembersView
    }
}

impl Default for MembersView {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl View for MembersView {
    fn name(&self) -> &'static str {
        "members"
    }

    async fn apply(&self, store: &EventStore, event: &DecodedEvent) -> Result<()> {
        match event.kind.as_deref() {
            Some("MemberRegistered") => apply_member_registered(store, event).await,
            Some("PublicEndpointUpdated") => apply_public_endpoint_updated(store, event).await,
            Some("MemberRetired") => apply_member_retired(store, event).await,
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
               AND e.decoded_kind IN ('MemberRegistered', 'PublicEndpointUpdated', 'MemberRetired') \
             ORDER BY e.block_number, e.log_index",
        )
        .bind(chain_id)
        .bind(&cluster[..])
        .bind(as_of_i64)
        .fetch_all(store.pool())
        .await
        .context("fetch member events for replay")?;

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

async fn apply_member_registered(store: &EventStore, event: &DecodedEvent) -> Result<()> {
    let payload = event
        .decoded
        .as_ref()
        .ok_or_else(|| anyhow!("MemberRegistered event has no decoded payload"))?;

    let member_id = decoded::member_id(payload, "memberId")?;
    let instance_id = decoded::address(payload, "instanceId")?;
    let passthrough = decoded::address(payload, "passthrough")?;
    let dns_label = decoded::string(payload, "dnsLabel")?.to_string();
    let registered_at = lookup_block_ts(store, event.chain_id, event.block_number).await?;

    sqlx::query(
        "INSERT INTO cluster_members \
            (chain_id, cluster_address, member_id, instance_id, passthrough, dns_label, registered_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (chain_id, cluster_address, member_id) DO UPDATE SET \
             instance_id   = EXCLUDED.instance_id, \
             passthrough   = EXCLUDED.passthrough, \
             dns_label     = EXCLUDED.dns_label, \
             registered_at = EXCLUDED.registered_at, \
             updated_at    = now()",
    )
    .bind(event.chain_id)
    .bind(&event.contract[..])
    .bind(&member_id[..])
    .bind(&instance_id[..])
    .bind(&passthrough[..])
    .bind(&dns_label)
    .bind(registered_at)
    .execute(store.pool())
    .await
    .context("upsert into cluster_members for MemberRegistered")?;

    Ok(())
}

async fn apply_public_endpoint_updated(store: &EventStore, event: &DecodedEvent) -> Result<()> {
    let payload = event
        .decoded
        .as_ref()
        .ok_or_else(|| anyhow!("PublicEndpointUpdated event has no decoded payload"))?;

    let member_id = decoded::member_id(payload, "memberId")?;
    let public_endpoint = match decoded::bytes_as_utf8_text(payload, "publicEndpoint")? {
        Ok(text) => text,
        Err(hex_repr) => {
            warn!(
                chain_id = event.chain_id,
                cluster = %decoded::hex0x(&event.contract),
                member = %decoded::hex0x(&member_id),
                "publicEndpoint bytes are not valid UTF-8; storing hex repr"
            );
            hex_repr
        }
    };

    let row = sqlx::query(
        "INSERT INTO cluster_members \
            (chain_id, cluster_address, member_id, public_endpoint) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (chain_id, cluster_address, member_id) DO UPDATE SET \
             public_endpoint = EXCLUDED.public_endpoint, \
             updated_at      = now() \
         RETURNING (xmax = 0) AS inserted",
    )
    .bind(event.chain_id)
    .bind(&event.contract[..])
    .bind(&member_id[..])
    .bind(&public_endpoint)
    .fetch_one(store.pool())
    .await
    .context("upsert public_endpoint")?;

    let inserted: bool = row.try_get("inserted")?;
    if inserted {
        warn!(
            chain_id = event.chain_id,
            cluster = %decoded::hex0x(&event.contract),
            member = %decoded::hex0x(&member_id),
            "PublicEndpointUpdated arrived before MemberRegistered; inserted stub row"
        );
    }
    Ok(())
}

async fn apply_member_retired(store: &EventStore, event: &DecodedEvent) -> Result<()> {
    let payload = event
        .decoded
        .as_ref()
        .ok_or_else(|| anyhow!("MemberRetired event has no decoded payload"))?;

    let member_id = decoded::member_id(payload, "memberId")?;
    let retired_at = lookup_block_ts(store, event.chain_id, event.block_number).await?;

    let result = sqlx::query(
        "UPDATE cluster_members \
         SET retired_at = $1, updated_at = now() \
         WHERE chain_id = $2 AND cluster_address = $3 AND member_id = $4 \
           AND (retired_at IS NULL OR retired_at = $1)",
    )
    .bind(retired_at)
    .bind(event.chain_id)
    .bind(&event.contract[..])
    .bind(&member_id[..])
    .execute(store.pool())
    .await
    .context("update cluster_members.retired_at")?;

    if result.rows_affected() == 0 {
        // Either the member row doesn't exist (out-of-order) or the
        // retire is already recorded with the same block_ts (replay
        // no-op). Distinguish via a follow-up read so the warning is
        // only emitted in the genuinely-missing case.
        let exists = sqlx::query(
            "SELECT 1 FROM cluster_members \
             WHERE chain_id = $1 AND cluster_address = $2 AND member_id = $3",
        )
        .bind(event.chain_id)
        .bind(&event.contract[..])
        .bind(&member_id[..])
        .fetch_optional(store.pool())
        .await
        .context("probe cluster_members for MemberRetired warning check")?;

        if exists.is_none() {
            warn!(
                chain_id = event.chain_id,
                cluster = %decoded::hex0x(&event.contract),
                member = %decoded::hex0x(&member_id),
                "MemberRetired arrived for an unknown member — dropped"
            );
        }
    }
    Ok(())
}

async fn lookup_block_ts(store: &EventStore, chain_id: i32, block_number: u64) -> Result<i64> {
    let block_i64 = i64::try_from(block_number).context("block_number overflows i64")?;
    let row = sqlx::query("SELECT block_ts FROM blocks WHERE chain_id = $1 AND number = $2")
        .bind(chain_id)
        .bind(block_i64)
        .fetch_optional(store.pool())
        .await
        .context("look up block_ts")?;

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
struct MemberRow {
    instance_id: Option<[u8; 20]>,
    passthrough: Option<[u8; 20]>,
    dns_label: Option<String>,
    public_endpoint: Option<String>,
    registered_at: Option<i64>,
    retired_at: Option<i64>,
}

impl MemberRow {
    fn to_json(&self, member_id: &[u8; 32]) -> serde_json::Value {
        json!({
            "memberId": decoded::hex0x(member_id),
            "instanceId": self.instance_id.as_ref().map(|b| decoded::hex0x(b)),
            "passthrough": self.passthrough.as_ref().map(|b| decoded::hex0x(b)),
            "dnsLabel": self.dns_label,
            "publicEndpoint": self.public_endpoint,
            "registeredAt": self.registered_at,
            "retiredAt": self.retired_at,
        })
    }
}

/// In-memory replay over a pre-fetched event stream + block-timestamp
/// map. Sorted by `member_id` (lex order over the bytes32) for
/// deterministic JSON output regardless of insertion order.
pub fn replay_in_memory(
    events: &[DecodedEvent],
    block_ts: &HashMap<u64, i64>,
    as_of_block: u64,
) -> Result<serde_json::Value> {
    let mut members: BTreeMap<[u8; 32], MemberRow> = BTreeMap::new();

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
            Some("MemberRegistered") => {
                let member_id = decoded::member_id(payload, "memberId")?;
                let instance_id = decoded::address(payload, "instanceId")?;
                let passthrough = decoded::address(payload, "passthrough")?;
                let dns_label = decoded::string(payload, "dnsLabel")?.to_string();

                let row = members.entry(member_id).or_default();
                row.instance_id = Some(instance_id);
                row.passthrough = Some(passthrough);
                row.dns_label = Some(dns_label);
                row.registered_at = ts;
                // public_endpoint and retired_at left untouched (idempotent
                // under replay; matches the SQL apply path).
            }
            Some("PublicEndpointUpdated") => {
                let member_id = decoded::member_id(payload, "memberId")?;
                let endpoint = match decoded::bytes_as_utf8_text(payload, "publicEndpoint")? {
                    Ok(text) => text,
                    Err(hex_repr) => {
                        warn!(
                            chain_id = event.chain_id,
                            member = %decoded::hex0x(&member_id),
                            "replay: publicEndpoint not UTF-8; using hex repr"
                        );
                        hex_repr
                    }
                };

                let existed = members.contains_key(&member_id);
                let row = members.entry(member_id).or_default();
                row.public_endpoint = Some(endpoint);
                if !existed {
                    warn!(
                        chain_id = event.chain_id,
                        member = %decoded::hex0x(&member_id),
                        "replay: PublicEndpointUpdated before MemberRegistered; stub row"
                    );
                }
            }
            Some("MemberRetired") => {
                let member_id = decoded::member_id(payload, "memberId")?;
                if let Some(row) = members.get_mut(&member_id) {
                    row.retired_at = ts;
                } else {
                    warn!(
                        chain_id = event.chain_id,
                        member = %decoded::hex0x(&member_id),
                        "replay: MemberRetired for unknown member — dropped"
                    );
                }
            }
            _ => continue,
        }
    }

    let members_json: Vec<serde_json::Value> =
        members.iter().map(|(id, row)| row.to_json(id)).collect();
    Ok(json!({ "members": members_json }))
}
