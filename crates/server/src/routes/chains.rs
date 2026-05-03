//! `/v1/chains` and `/v1/:chain/chain` — chain-state metadata.
//!
//! `/v1/chains` is unsigned (it's a process-level inventory, not an
//! on-chain answer). `/v1/:chain/chain` returns this chain's head,
//! finalized cursor, and `last_event_id` wrapped in the §7.1 signed
//! envelope so consumers can pin the indexer's reported chain head
//! against an out-of-band check.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::error::ApiError;
use crate::query::RawQuery;
use crate::routes::common::build_signed;
use crate::state::{AppState, MultiChainState};

#[derive(Serialize)]
pub struct ChainSummary {
    pub shortname: String,
    pub chain_id: i32,
    pub head_block: u64,
    pub finalized_block: u64,
    pub last_event_id: i64,
}

#[derive(Serialize)]
pub struct ChainsResponse {
    pub chains: Vec<ChainSummary>,
}

pub async fn list_chains(
    State(state): State<Arc<MultiChainState>>,
) -> Result<Json<ChainsResponse>, ApiError> {
    let mut chains = Vec::with_capacity(state.by_shortname.len());
    let mut sorted: Vec<(&String, &AppState)> = state.by_shortname.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (shortname, app) in sorted {
        let summary = read_chain_summary(shortname.clone(), app).await?;
        chains.push(summary);
    }
    Ok(Json(ChainsResponse { chains }))
}

pub async fn get_chain(
    State(state): State<Arc<MultiChainState>>,
    Path(chain): Path<String>,
    Query(raw): Query<RawQuery>,
) -> Result<Json<Value>, ApiError> {
    let common = raw.parse()?;
    let chain_for_payload = chain.clone();
    let env = build_signed(
        &state,
        &chain,
        common,
        None,
        move |app, _as_of, _common| async move {
            let summary = read_chain_summary(chain_for_payload, &app).await?;
            Ok(json!({
                "shortname": summary.shortname,
                "chain_id": summary.chain_id,
                "head_block": summary.head_block,
                "finalized_block": summary.finalized_block,
                "last_event_id": summary.last_event_id,
            }))
        },
    )
    .await?;
    Ok(Json(env))
}

async fn read_chain_summary(shortname: String, app: &AppState) -> Result<ChainSummary, ApiError> {
    let chain_id = app.store.chain_id();
    let row = sqlx::query(
        "SELECT
            COALESCE((SELECT v FROM chain_state WHERE chain_id = $1 AND k = 'head_block'), '0') AS head,
            COALESCE((SELECT v FROM chain_state WHERE chain_id = $1 AND k = 'finalized_block'), '0') AS finalized,
            COALESCE((SELECT MAX(id) FROM events WHERE chain_id = $1), 0)::text AS last_event_id",
    )
    .bind(chain_id)
    .fetch_one(app.store.pool())
    .await
    .map_err(ApiError::from)?;
    let head: String = row.try_get("head").map_err(ApiError::from)?;
    let finalized: String = row.try_get("finalized").map_err(ApiError::from)?;
    let last_event_id: String = row.try_get("last_event_id").map_err(ApiError::from)?;
    Ok(ChainSummary {
        shortname,
        chain_id,
        head_block: head.parse().unwrap_or(0),
        finalized_block: finalized.parse().unwrap_or(0),
        last_event_id: last_event_id.parse().unwrap_or(0),
    })
}
