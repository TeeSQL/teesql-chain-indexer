//! `/v1/:chain/factories/:addr/clusters` and `.../contains` —
//! factory-side reads.
//!
//! `clusters` returns every diamond minted by the factory; `contains`
//! is the gas-webhook hot path (sub-millisecond Postgres lookup,
//! one signed bool back).

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
use crate::routes::common::{build_signed, parse_address};
use crate::state::MultiChainState;

#[derive(Deserialize)]
pub struct FactoryPath {
    pub chain: String,
    pub addr: String,
}

#[derive(Deserialize)]
pub struct ContainsQuery {
    #[serde(flatten)]
    pub common: RawQuery,
    pub address: String,
}

pub async fn list_factory_clusters(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<FactoryPath>,
    Query(raw): Query<RawQuery>,
) -> Result<Json<Value>, ApiError> {
    let factory = parse_address(&p.addr)?;
    let common = raw.parse()?;
    let env = build_signed(
        &state,
        &p.chain,
        common,
        None,
        move |app, _as_of, _common| async move {
            let chain_id = app.store.chain_id();
            let rows = sqlx::query(
                "SELECT address FROM watched_contracts
             WHERE chain_id = $1 AND parent = $2 AND kind = 'cluster_diamond'
             ORDER BY from_block",
            )
            .bind(chain_id)
            .bind(&factory[..])
            .fetch_all(app.store.pool())
            .await
            .map_err(ApiError::from)?;
            let mut addrs: Vec<String> = Vec::with_capacity(rows.len());
            for row in rows {
                let addr: Vec<u8> = row.try_get("address").map_err(ApiError::from)?;
                addrs.push(format!("0x{}", hex::encode(addr)));
            }
            Ok(json!({
                "factory": format!("0x{}", hex::encode(factory)),
                "clusters": addrs,
            }))
        },
    )
    .await?;
    Ok(Json(env))
}

pub async fn factory_contains(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<FactoryPath>,
    Query(q): Query<ContainsQuery>,
) -> Result<Json<Value>, ApiError> {
    let factory = parse_address(&p.addr)?;
    let target = parse_address(&q.address)?;
    let common = q.common.parse()?;
    let env = build_signed(
        &state,
        &p.chain,
        common,
        None,
        move |app, _as_of, _common| async move {
            let chain_id = app.store.chain_id();
            let row = sqlx::query(
                "SELECT 1 AS x FROM watched_contracts
             WHERE chain_id = $1 AND parent = $2 AND address = $3 AND kind = 'cluster_diamond'
             LIMIT 1",
            )
            .bind(chain_id)
            .bind(&factory[..])
            .bind(&target[..])
            .fetch_optional(app.store.pool())
            .await
            .map_err(ApiError::from)?;
            Ok(json!({
                "factory": format!("0x{}", hex::encode(factory)),
                "address": format!("0x{}", hex::encode(target)),
                "contains": row.is_some(),
            }))
        },
    )
    .await?;
    Ok(Json(env))
}
