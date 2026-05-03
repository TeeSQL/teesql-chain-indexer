//! `/v1/:chain/clusters/:addr/events`, `.../events/sse`, and the
//! per-chain `/v1/:chain/events/:id` single-event lookup.
//!
//! `/events` is the paginated raw event log for a cluster. `/events/sse`
//! is the long-lived push channel that bridges Postgres
//! `LISTEN chain_indexer_events` (and the in-process broadcast bus
//! fed by core::Ingestor) to a per-connection filter. The SSE handler
//! body lives in [`crate::sse`]; this module owns the route shape
//! and shared helpers like the kind-csv parser.
//!
//! [`get_event_by_id`] is the verification companion to bare SSE
//! frames — consumers receive the bare event from the SSE stream
//! (sub-millisecond fan-out) and follow up with `GET /v1/:chain/
//! events/:id` only when they need the full RFC-8785 / ECDSA
//! envelope. See spec §7.3.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::error::ApiError;
use crate::query::RawQuery;
use crate::routes::clusters::ClusterPath;
use crate::routes::common::{build_signed, parse_address};
use crate::state::{AppState, MultiChainState};

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(flatten)]
    pub common: RawQuery,
    pub since: Option<i64>,
    pub kind: Option<String>,
    pub limit: Option<u32>,
}

/// Path shape for `GET /v1/:chain/events/:id`. axum's `Path` extractor
/// fills these from the URL pattern in route registration order.
#[derive(Deserialize)]
pub struct EventByIdPath {
    pub chain: String,
    pub id: i64,
}

pub async fn list_events(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<ClusterPath>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let cluster = parse_address(&p.addr)?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let kinds = parse_kinds(q.kind.as_deref());
    let since = q.since;
    let common = q.common.parse()?;

    let env = build_signed(
        &state,
        &p.chain,
        common,
        None,
        move |app, as_of, _common| async move {
            let events = fetch_paginated(
                &app,
                cluster,
                since,
                kinds.as_deref(),
                limit,
                as_of.block_number,
            )
            .await?;
            let next_since = next_since_from(&events);
            Ok(json!({
                "cluster": format!("0x{}", hex::encode(cluster)),
                "events": events,
                "limit": limit,
                "next_since": next_since,
            }))
        },
    )
    .await?;
    Ok(Json(env))
}

/// `GET /v1/:chain/events/:id` — verification companion to bare SSE
/// frames (spec §7.3). Returns the single event row identified by
/// `events.id`, wrapped in the standard signed envelope per spec
/// §7.1. Parses `:id` as `i64`; returns 404 when no row matches.
///
/// Unlike the cluster-scoped `/events` listing this surface does NOT
/// filter `removed = true` — a reorged event still resolves so
/// consumers can see the `removed: true` flag in the payload and
/// react. The signed envelope's `as_of` reflects the request's
/// safety / `as_of_block` per the standard query params.
pub async fn get_event_by_id(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<EventByIdPath>,
    Query(raw): Query<RawQuery>,
) -> Result<Json<Value>, ApiError> {
    let common = raw.parse()?;
    let id = p.id;
    let env = build_signed(
        &state,
        &p.chain,
        common,
        None,
        move |app, _as_of, _common| async move {
            let payload = fetch_event_by_id(&app, id).await?;
            Ok(payload)
        },
    )
    .await?;
    Ok(Json(env))
}

/// Shared row-fetch + JSON-shape helper used by both the REST
/// `get_event_by_id` handler and its gRPC mirror in [`crate::grpc`].
/// `pub(crate)` so the gRPC layer doesn't re-implement the query.
pub(crate) async fn fetch_event_by_id(app: &AppState, id: i64) -> Result<Value, ApiError> {
    let chain_id = app.store.chain_id();
    let row = sqlx::query(
        "SELECT id, contract, block_number, log_index, tx_hash, decoded_kind, decoded, removed
         FROM events
         WHERE chain_id = $1 AND id = $2",
    )
    .bind(chain_id)
    .bind(id)
    .fetch_optional(app.store.pool())
    .await
    .map_err(ApiError::from)?;
    let Some(row) = row else {
        return Err(ApiError::not_found(format!("event id {id} not found")));
    };
    let event_id: i64 = row.try_get("id").map_err(ApiError::from)?;
    let contract: Vec<u8> = row.try_get("contract").map_err(ApiError::from)?;
    let block_number: i64 = row.try_get("block_number").map_err(ApiError::from)?;
    let log_index: i32 = row.try_get("log_index").map_err(ApiError::from)?;
    let tx_hash: Vec<u8> = row.try_get("tx_hash").map_err(ApiError::from)?;
    let decoded_kind: Option<String> = row.try_get("decoded_kind").map_err(ApiError::from)?;
    let decoded: Option<Value> = row.try_get("decoded").map_err(ApiError::from)?;
    let removed: bool = row.try_get("removed").map_err(ApiError::from)?;
    Ok(json!({
        "event_id": event_id,
        "contract": format!("0x{}", hex::encode(contract)),
        "block_number": block_number,
        "log_index": log_index,
        "tx_hash": format!("0x{}", hex::encode(tx_hash)),
        "kind": decoded_kind,
        "decoded": decoded,
        "removed": removed,
    }))
}

/// Public CSV parser used by both the REST list path and the SSE
/// handler in [`crate::sse`].
pub fn parse_kinds(s: Option<&str>) -> Option<Vec<String>> {
    let raw = s?;
    let kinds: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if kinds.is_empty() {
        None
    } else {
        Some(kinds)
    }
}

async fn fetch_paginated(
    app: &AppState,
    cluster: [u8; 20],
    since: Option<i64>,
    kinds: Option<&[String]>,
    limit: u32,
    upto_block: u64,
) -> Result<Vec<Value>, ApiError> {
    let chain_id = app.store.chain_id();
    let kinds_owned: Vec<String> = kinds.map(|k| k.to_vec()).unwrap_or_default();
    let since = since.unwrap_or(0);
    let limit_i64 = limit as i64;
    let rows = sqlx::query(
        "SELECT id, block_number, log_index, tx_hash, decoded_kind, decoded
         FROM events
         WHERE chain_id = $1
           AND contract = $2
           AND removed = false
           AND id > $3
           AND block_number <= $4
           AND ($5::text[] = '{}' OR decoded_kind = ANY($5))
         ORDER BY id
         LIMIT $6",
    )
    .bind(chain_id)
    .bind(&cluster[..])
    .bind(since)
    .bind(upto_block as i64)
    .bind(&kinds_owned)
    .bind(limit_i64)
    .fetch_all(app.store.pool())
    .await
    .map_err(ApiError::from)?;
    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row.try_get("id").map_err(ApiError::from)?;
        let block_number: i64 = row.try_get("block_number").map_err(ApiError::from)?;
        let log_index: i32 = row.try_get("log_index").map_err(ApiError::from)?;
        let tx_hash: Vec<u8> = row.try_get("tx_hash").map_err(ApiError::from)?;
        let decoded_kind: Option<String> = row.try_get("decoded_kind").map_err(ApiError::from)?;
        let decoded: Option<Value> = row.try_get("decoded").map_err(ApiError::from)?;
        events.push(json!({
            "id": id,
            "block_number": block_number,
            "log_index": log_index,
            "tx_hash": format!("0x{}", hex::encode(tx_hash)),
            "kind": decoded_kind,
            "decoded": decoded,
        }));
    }
    Ok(events)
}

fn next_since_from(events: &[Value]) -> Option<i64> {
    events
        .last()
        .and_then(|e| e.get("id"))
        .and_then(Value::as_i64)
}

// Re-export the SSE handler so the router can reach it through a
// single import path matching the rest of the routes module.
pub use crate::sse::sse_handler as sse_events;
