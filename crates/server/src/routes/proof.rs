//! `.../proof` companion endpoints — spec §4.1 cross-check protocol.
//!
//! For each materialized view (leader, members, lifecycle) we expose
//! a sibling `/proof` route that returns the underlying chain events
//! the answer was derived from. A skeptical consumer can replay the
//! events through their own copy of the materializer logic and verify
//! they get the same answer, without re-implementing the indexer.
//!
//! Each event row in the response body has the shape
//!
//! ```json
//! { "block_number", "log_index", "tx_hash", "topic0", "topics_rest",
//!   "data", "decoded_kind", "decoded" }
//! ```
//!
//! `removed=true` rows are filtered out (they're reorged-away events
//! not part of canonical history). The whole response is wrapped in
//! the standard signed envelope.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde_json::{json, Value};
use sqlx::Row;

use crate::error::ApiError;
use crate::query::RawQuery;
use crate::routes::clusters::{endpoint, ClusterPath};
use crate::routes::common::{build_signed, parse_address};
use crate::state::AppState;
use crate::state::MultiChainState;

pub async fn cluster_leader_proof(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<ClusterPath>,
    Query(raw): Query<RawQuery>,
) -> Result<Json<Value>, ApiError> {
    proof_handler(state, p, raw, endpoint::LEADER).await
}

pub async fn cluster_members_proof(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<ClusterPath>,
    Query(raw): Query<RawQuery>,
) -> Result<Json<Value>, ApiError> {
    proof_handler(state, p, raw, endpoint::MEMBERS).await
}

pub async fn cluster_lifecycle_proof(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<ClusterPath>,
    Query(raw): Query<RawQuery>,
) -> Result<Json<Value>, ApiError> {
    proof_handler(state, p, raw, endpoint::LIFECYCLE).await
}

async fn proof_handler(
    state: Arc<MultiChainState>,
    path: ClusterPath,
    raw: RawQuery,
    endpoint_name: &'static str,
) -> Result<Json<Value>, ApiError> {
    let cluster = parse_address(&path.addr)?;
    let common = raw.parse()?;
    let env = build_signed(
        &state,
        &path.chain,
        common,
        None,
        move |app, as_of, _common| async move {
            let kinds = kinds_for_endpoint(endpoint_name);
            let events = read_events(&app, cluster, &kinds, as_of.block_number).await?;
            Ok(json!({
                "endpoint": endpoint_name,
                "cluster": format!("0x{}", hex::encode(cluster)),
                "events": events,
            }))
        },
    )
    .await?;
    Ok(Json(env))
}

/// Per-endpoint event-kind selector. The indexer's materializers
/// derive each materialized table from the same kind set, so the
/// proof endpoint can reproduce the consumer's reconstruction by
/// returning exactly those rows.
fn kinds_for_endpoint(endpoint: &str) -> Vec<&'static str> {
    match endpoint {
        endpoint::LEADER => vec!["LeaderClaimed", "LeaderRevoked"],
        endpoint::MEMBERS => vec![
            "MemberRegistered",
            "MemberRetired",
            "InstanceIdUpdated",
            "PublicEndpointUpdated",
        ],
        endpoint::LIFECYCLE => vec!["ClusterDestroyed"],
        _ => vec![],
    }
}

async fn read_events(
    app: &AppState,
    cluster: [u8; 20],
    kinds: &[&str],
    upto_block: u64,
) -> Result<Vec<Value>, ApiError> {
    let chain_id = app.store.chain_id();
    let kinds_owned: Vec<String> = kinds.iter().map(|s| s.to_string()).collect();
    let rows = sqlx::query(
        "SELECT block_number, log_index, tx_hash, topic0, topics_rest, data,
                decoded_kind, decoded
         FROM events
         WHERE chain_id = $1
           AND contract = $2
           AND removed = false
           AND block_number <= $3
           AND ($4::text[] = '{}' OR decoded_kind = ANY($4))
         ORDER BY block_number, log_index",
    )
    .bind(chain_id)
    .bind(&cluster[..])
    .bind(upto_block as i64)
    .bind(&kinds_owned)
    .fetch_all(app.store.pool())
    .await
    .map_err(ApiError::from)?;
    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let block_number: i64 = row.try_get("block_number").map_err(ApiError::from)?;
        let log_index: i32 = row.try_get("log_index").map_err(ApiError::from)?;
        let tx_hash: Vec<u8> = row.try_get("tx_hash").map_err(ApiError::from)?;
        let topic0: Vec<u8> = row.try_get("topic0").map_err(ApiError::from)?;
        let topics_rest: Vec<u8> = row.try_get("topics_rest").map_err(ApiError::from)?;
        let data: Vec<u8> = row.try_get("data").map_err(ApiError::from)?;
        let decoded_kind: Option<String> = row.try_get("decoded_kind").map_err(ApiError::from)?;
        let decoded: Option<Value> = row.try_get("decoded").map_err(ApiError::from)?;
        events.push(json!({
            "block_number": block_number,
            "log_index": log_index,
            "tx_hash": format!("0x{}", hex::encode(tx_hash)),
            "topic0": format!("0x{}", hex::encode(topic0)),
            "topics_rest": format!("0x{}", hex::encode(topics_rest)),
            "data": format!("0x{}", hex::encode(data)),
            "decoded_kind": decoded_kind,
            "decoded": decoded,
        }));
    }
    Ok(events)
}
