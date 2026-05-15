//! `/v1/:chain/clusters/:addr/...` cluster-state reads.
//!
//! Each handler dispatches into a [`teesql_chain_indexer_core::views::View`] whose
//! `replay(...)` reconstructs the materialized payload for the
//! requested block. For the live (head) path the view's stored
//! materialized table is the cheap source; for `?as_of_block` it
//! replays through `events`. The route layer does not own the SQL —
//! it threads the resolved AppState + AsOf into the View trait.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::ApiError;
use crate::query::RawQuery;
use crate::routes::common::{build_signed, parse_address, CacheKey};
use crate::state::{AppState, MultiChainState};

#[derive(Deserialize)]
pub struct ClusterPath {
    pub chain: String,
    pub addr: String,
}

#[derive(Deserialize)]
pub struct MemberPath {
    pub chain: String,
    pub addr: String,
    pub member_id: String,
}

#[derive(Deserialize)]
pub struct MembersQuery {
    #[serde(flatten)]
    pub common: RawQuery,
    /// Default false — matches the REST API contract in the spec
    /// table.
    #[serde(default)]
    pub include_retired: bool,
}

/// Endpoint-name strings used as the `historical_query_cache.endpoint`
/// key and as the `View::name()` lookup. Kept in one place so the
/// REST and gRPC layers don't drift.
pub mod endpoint {
    pub const LEADER: &str = "leader";
    pub const MEMBERS: &str = "members";
    pub const LIFECYCLE: &str = "lifecycle";
    /// Materialized MRTD allowlist driven by
    /// `ComposeHashAllowed` / `ComposeHashRemoved`
    /// (unified-network-design §4.2).
    pub const COMPOSE_HASHES: &str = "compose_hashes";
}

pub async fn cluster_overview(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<ClusterPath>,
    Query(raw): Query<RawQuery>,
) -> Result<Json<Value>, ApiError> {
    let cluster = parse_address(&p.addr)?;
    let common = raw.parse()?;
    let env = build_signed(
        &state,
        &p.chain,
        common,
        None,
        move |app, as_of, _common| async move {
            let leader = run_view(&app, endpoint::LEADER, cluster, as_of.block_number).await?;
            let members = run_view(&app, endpoint::MEMBERS, cluster, as_of.block_number).await?;
            let lifecycle =
                run_view(&app, endpoint::LIFECYCLE, cluster, as_of.block_number).await?;
            let member_count = members
                .as_array()
                .or_else(|| members.get("members").and_then(|v| v.as_array()))
                .map(|a| a.len())
                .unwrap_or(0);
            Ok(json!({
                "address": format!("0x{}", hex::encode(cluster)),
                "leader": leader,
                "members_count": member_count,
                "lifecycle": lifecycle,
            }))
        },
    )
    .await?;
    Ok(Json(env))
}

pub async fn cluster_leader(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<ClusterPath>,
    Query(raw): Query<RawQuery>,
) -> Result<Json<Value>, ApiError> {
    let cluster = parse_address(&p.addr)?;
    let common = raw.parse()?;
    let cache = CacheKey {
        cluster,
        endpoint: endpoint::LEADER,
    };
    let env = build_signed(
        &state,
        &p.chain,
        common,
        Some(cache),
        move |app, as_of, _common| async move {
            run_view(&app, endpoint::LEADER, cluster, as_of.block_number).await
        },
    )
    .await?;
    Ok(Json(env))
}

pub async fn cluster_members(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<ClusterPath>,
    Query(q): Query<MembersQuery>,
) -> Result<Json<Value>, ApiError> {
    let cluster = parse_address(&p.addr)?;
    let common = q.common.parse()?;
    let cache = CacheKey {
        cluster,
        endpoint: endpoint::MEMBERS,
    };
    let include_retired = q.include_retired;
    let env = build_signed(
        &state,
        &p.chain,
        common,
        Some(cache),
        move |app, as_of, _common| async move {
            let mut payload =
                run_view(&app, endpoint::MEMBERS, cluster, as_of.block_number).await?;
            if !include_retired {
                filter_retired_in_place(&mut payload);
            }
            Ok(payload)
        },
    )
    .await?;
    Ok(Json(env))
}

pub async fn cluster_member(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<MemberPath>,
    Query(raw): Query<RawQuery>,
) -> Result<Json<Value>, ApiError> {
    let cluster = parse_address(&p.addr)?;
    let member_id = parse_member_id(&p.member_id)?;
    let common = raw.parse()?;
    let env = build_signed(
        &state,
        &p.chain,
        common,
        None,
        move |app, as_of, _common| async move {
            let payload = run_view(&app, endpoint::MEMBERS, cluster, as_of.block_number).await?;
            let member = pluck_member(&payload, &member_id).ok_or_else(|| {
                ApiError::not_found(format!(
                    "member 0x{} not found in cluster 0x{}",
                    hex::encode(member_id),
                    hex::encode(cluster)
                ))
            })?;
            Ok(member)
        },
    )
    .await?;
    Ok(Json(env))
}

pub async fn cluster_lifecycle(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<ClusterPath>,
    Query(raw): Query<RawQuery>,
) -> Result<Json<Value>, ApiError> {
    let cluster = parse_address(&p.addr)?;
    let common = raw.parse()?;
    let cache = CacheKey {
        cluster,
        endpoint: endpoint::LIFECYCLE,
    };
    let env = build_signed(
        &state,
        &p.chain,
        common,
        Some(cache),
        move |app, as_of, _common| async move {
            run_view(&app, endpoint::LIFECYCLE, cluster, as_of.block_number).await
        },
    )
    .await?;
    Ok(Json(env))
}

/// Per unified-network-design §4.2: surfaces the MRTD allowlist as
/// reconstructed from `ComposeHashAllowed` / `ComposeHashRemoved`.
/// Fabric's audit path (§8) reads this view alongside direct-RPC
/// state to detect indexer suppression of allowlist mutations.
pub async fn cluster_compose_hashes(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<ClusterPath>,
    Query(raw): Query<RawQuery>,
) -> Result<Json<Value>, ApiError> {
    let cluster = parse_address(&p.addr)?;
    let common = raw.parse()?;
    let cache = CacheKey {
        cluster,
        endpoint: endpoint::COMPOSE_HASHES,
    };
    let env = build_signed(
        &state,
        &p.chain,
        common,
        Some(cache),
        move |app, as_of, _common| async move {
            run_view(&app, endpoint::COMPOSE_HASHES, cluster, as_of.block_number).await
        },
    )
    .await?;
    Ok(Json(env))
}

pub(crate) async fn run_view(
    app: &AppState,
    endpoint: &str,
    cluster: [u8; 20],
    as_of_block: u64,
) -> Result<Value, ApiError> {
    let view = app.views.get(endpoint).cloned().ok_or_else(|| {
        ApiError::internal(format!("no view registered for endpoint '{endpoint}'"))
    })?;
    view.replay(&app.store, app.store.chain_id(), cluster, as_of_block)
        .await
        .map_err(ApiError::from)
}

fn parse_member_id(s: &str) -> Result<[u8; 32], ApiError> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(raw)
        .map_err(|e| ApiError::bad_request(format!("invalid member_id hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request(format!(
            "member_id must be 32 bytes; got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn pluck_member(payload: &Value, member_id: &[u8; 32]) -> Option<Value> {
    let target = format!("0x{}", hex::encode(member_id));
    let arr = payload
        .as_array()
        .or_else(|| payload.get("members").and_then(|v| v.as_array()))?;
    arr.iter()
        .find(|m| {
            m.get("member_id")
                .and_then(|v| v.as_str())
                .map(|s| s.eq_ignore_ascii_case(&target))
                .unwrap_or(false)
        })
        .cloned()
}

fn filter_retired_in_place(payload: &mut Value) {
    let arr_mut = if payload.is_array() {
        payload.as_array_mut()
    } else {
        payload.get_mut("members").and_then(|v| v.as_array_mut())
    };
    let Some(arr) = arr_mut else {
        return;
    };
    arr.retain(|m| m.get("retired_at").map(|v| v.is_null()).unwrap_or(true));
}
