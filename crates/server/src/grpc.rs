// Tonic's `Status` is intentionally large (176 bytes) because it
// carries a metadata map. Every method here is a transport adapter
// that returns `Result<_, Status>`; boxing every Err would buy us
// nothing and obscure the trait signature tonic dictates.
#![allow(clippy::result_large_err)]

//! gRPC mirror under `teesql.chain_indexer.v1`. Every method
//! delegates into the exact same handler pipeline REST uses
//! ([`crate::routes::common::build_signed`] + the per-endpoint
//! payload closure) so the two transports cannot drift.
//!
//! Conversion strategy:
//!   * REST + gRPC both compute the envelope as a single
//!     `serde_json::Value`.
//!   * REST returns it via `axum::Json`.
//!   * gRPC splits the JSON envelope into the proto's typed
//!     `SignedResponse { data, as_of, attestation, quote_b64? }`.
//!     `data` and `as_of` round-trip through `prost_types::Struct`
//!     so the proto schema stays free-form (mirrors what we'd do
//!     in a NATS or message-bus transport).
//!
//! Streaming is the only method that can't reuse the REST pipeline:
//! REST's SSE handler emits `axum::response::sse::Event`, gRPC needs
//! `EventEnvelope` proto messages. The streaming worker reads the
//! same backlog + broadcast bus combination [`crate::sse`] uses,
//! signs each event independently, and pushes the proto envelope
//! down the stream.

use std::pin::Pin;
use std::sync::Arc;

use futures::stream::Stream;
use futures::StreamExt;
use serde_json::{json, Value};
use sqlx::Row;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};

use crate::as_of;
use crate::envelope;
use crate::error::ApiError;
use crate::query::CommonRead;
use crate::routes::clusters::{endpoint, run_view};
use crate::routes::common::{build_signed, parse_address, resolve_chain, CacheKey};
use crate::routes::events::{fetch_event_by_id, parse_kinds};
use crate::sse::RecentIds;
use crate::state::MultiChainState;
use teesql_chain_indexer_core::ingest::NotifyEvent;

pub mod proto {
    //! Generated tonic types for `teesql.chain_indexer.v1`. Re-
    //! exported behind an explicit module so the rest of the crate
    //! can refer to them as `crate::grpc::proto::*` rather than
    //! polluting the top level.
    tonic::include_proto!("teesql.chain_indexer.v1");
}

use proto::chain_indexer_server::ChainIndexer;
use proto::{
    AttestationResponse as ProtoAttestationResponse, ChainSummary, ChainsResponse, ClusterRequest,
    EventEnvelope, FactoryContainsRequest, FactoryRequest, FreshQuote, GetChainRequest,
    GetEventByIdRequest, HealthResponse, ListEventsRequest, MemberRequest, MembersRequest,
    Safety as ProtoSafety, SignedResponse, StreamEventsRequest,
};

/// gRPC service backed by the shared multi-chain state.
pub struct ChainIndexerService {
    pub state: Arc<MultiChainState>,
}

impl ChainIndexerService {
    pub fn new(state: Arc<MultiChainState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl ChainIndexer for ChainIndexerService {
    async fn get_health(&self, _request: Request<()>) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "ok".to_string(),
            uptime_seconds: self.state.started_at.elapsed().as_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }

    async fn get_attestation(
        &self,
        _request: Request<()>,
    ) -> Result<Response<ProtoAttestationResponse>, Status> {
        Ok(Response::new(ProtoAttestationResponse {
            signer_address: format!("0x{}", hex::encode(self.state.signer.signer_address())),
            quote_b64: self.state.signer.boot_quote_b64().to_string(),
        }))
    }

    async fn list_chains(&self, _request: Request<()>) -> Result<Response<ChainsResponse>, Status> {
        let mut chains = Vec::with_capacity(self.state.by_shortname.len());
        let mut sorted: Vec<(&String, _)> = self.state.by_shortname.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (shortname, app) in sorted {
            let row = sqlx::query(
                "SELECT
                    COALESCE((SELECT v FROM chain_state WHERE chain_id = $1 AND k = 'head_block'), '0') AS head,
                    COALESCE((SELECT v FROM chain_state WHERE chain_id = $1 AND k = 'finalized_block'), '0') AS finalized,
                    COALESCE((SELECT MAX(id) FROM events WHERE chain_id = $1), 0)::text AS last_event_id",
            )
            .bind(app.store.chain_id())
            .fetch_one(app.store.pool())
            .await
            .map_err(|e| Status::internal(format!("chain_state read: {e}")))?;
            let head: String = row
                .try_get("head")
                .map_err(|e| Status::internal(e.to_string()))?;
            let finalized: String = row
                .try_get("finalized")
                .map_err(|e| Status::internal(e.to_string()))?;
            let last_event_id: String = row
                .try_get("last_event_id")
                .map_err(|e| Status::internal(e.to_string()))?;
            chains.push(ChainSummary {
                shortname: shortname.clone(),
                chain_id: app.store.chain_id() as u32,
                head_block: head.parse().unwrap_or(0),
                finalized_block: finalized.parse().unwrap_or(0),
                last_event_id: last_event_id.parse().unwrap_or(0),
            });
        }
        Ok(Response::new(ChainsResponse { chains }))
    }

    async fn get_chain(
        &self,
        request: Request<GetChainRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        let req = request.into_inner();
        let common = common_from_proto(req.safety, req.as_of_block, req.fresh_quote.as_ref())?;
        let chain = req.chain.clone();
        let chain_for_payload = chain.clone();
        let env = build_signed(
            &self.state,
            &chain,
            common,
            None,
            move |app, as_of, _common| async move {
                let chain_id = app.store.chain_id();
                Ok(json!({
                    "shortname": chain_for_payload,
                    "chain_id": chain_id,
                    "head_block": as_of.finalized_block,
                    "finalized_block": as_of.finalized_block,
                }))
            },
        )
        .await
        .map_err(Status::from)?;
        Ok(Response::new(value_to_signed_response(env)?))
    }

    async fn list_factory_clusters(
        &self,
        request: Request<FactoryRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        let req = request.into_inner();
        let common = common_from_proto(req.safety, req.as_of_block, req.fresh_quote.as_ref())?;
        let factory = parse_address(&req.factory_address).map_err(Status::from)?;
        let chain = req.chain;
        let env = build_signed(
            &self.state,
            &chain,
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
                let mut addrs = Vec::with_capacity(rows.len());
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
        .await
        .map_err(Status::from)?;
        Ok(Response::new(value_to_signed_response(env)?))
    }

    async fn factory_contains(
        &self,
        request: Request<FactoryContainsRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        let req = request.into_inner();
        let common = common_from_proto(req.safety, req.as_of_block, req.fresh_quote.as_ref())?;
        let factory = parse_address(&req.factory_address).map_err(Status::from)?;
        let target = parse_address(&req.address).map_err(Status::from)?;
        let chain = req.chain;
        let env = build_signed(
            &self.state,
            &chain,
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
        .await
        .map_err(Status::from)?;
        Ok(Response::new(value_to_signed_response(env)?))
    }

    async fn get_cluster(
        &self,
        request: Request<ClusterRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        let req = request.into_inner();
        let common = common_from_proto(req.safety, req.as_of_block, req.fresh_quote.as_ref())?;
        let cluster = parse_address(&req.cluster_address).map_err(Status::from)?;
        let chain = req.chain;
        let env = build_signed(
            &self.state,
            &chain,
            common,
            None,
            move |app, as_of, _common| async move {
                let leader = run_view(&app, endpoint::LEADER, cluster, as_of.block_number).await?;
                let members =
                    run_view(&app, endpoint::MEMBERS, cluster, as_of.block_number).await?;
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
        .await
        .map_err(Status::from)?;
        Ok(Response::new(value_to_signed_response(env)?))
    }

    async fn get_cluster_leader(
        &self,
        request: Request<ClusterRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        let req = request.into_inner();
        let common = common_from_proto(req.safety, req.as_of_block, req.fresh_quote.as_ref())?;
        let cluster = parse_address(&req.cluster_address).map_err(Status::from)?;
        let chain = req.chain;
        let cache = CacheKey {
            cluster,
            endpoint: endpoint::LEADER,
        };
        let env = build_signed(
            &self.state,
            &chain,
            common,
            Some(cache),
            move |app, as_of, _common| async move {
                run_view(&app, endpoint::LEADER, cluster, as_of.block_number).await
            },
        )
        .await
        .map_err(Status::from)?;
        Ok(Response::new(value_to_signed_response(env)?))
    }

    async fn get_cluster_leader_proof(
        &self,
        request: Request<ClusterRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        proof_method(self, request, endpoint::LEADER).await
    }

    async fn get_cluster_members(
        &self,
        request: Request<MembersRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        let req = request.into_inner();
        let common = common_from_proto(req.safety, req.as_of_block, req.fresh_quote.as_ref())?;
        let cluster = parse_address(&req.cluster_address).map_err(Status::from)?;
        let chain = req.chain;
        let include_retired = req.include_retired;
        let cache = CacheKey {
            cluster,
            endpoint: endpoint::MEMBERS,
        };
        let env = build_signed(
            &self.state,
            &chain,
            common,
            Some(cache),
            move |app, as_of, _common| async move {
                let mut payload =
                    run_view(&app, endpoint::MEMBERS, cluster, as_of.block_number).await?;
                if !include_retired {
                    let arr_opt = if payload.is_array() {
                        payload.as_array_mut()
                    } else {
                        payload.get_mut("members").and_then(|v| v.as_array_mut())
                    };
                    if let Some(arr) = arr_opt {
                        arr.retain(|m| m.get("retired_at").map(|v| v.is_null()).unwrap_or(true));
                    }
                }
                Ok(payload)
            },
        )
        .await
        .map_err(Status::from)?;
        Ok(Response::new(value_to_signed_response(env)?))
    }

    async fn get_cluster_members_proof(
        &self,
        request: Request<ClusterRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        proof_method(self, request, endpoint::MEMBERS).await
    }

    async fn get_cluster_member(
        &self,
        request: Request<MemberRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        let req = request.into_inner();
        let common = common_from_proto(req.safety, req.as_of_block, req.fresh_quote.as_ref())?;
        let cluster = parse_address(&req.cluster_address).map_err(Status::from)?;
        let raw = req.member_id.strip_prefix("0x").unwrap_or(&req.member_id);
        let bytes = hex::decode(raw)
            .map_err(|e| Status::invalid_argument(format!("member_id hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(Status::invalid_argument("member_id must be 32 bytes"));
        }
        let mut member_id = [0u8; 32];
        member_id.copy_from_slice(&bytes);
        let chain = req.chain;
        let env = build_signed(
            &self.state,
            &chain,
            common,
            None,
            move |app, as_of, _common| async move {
                let payload =
                    run_view(&app, endpoint::MEMBERS, cluster, as_of.block_number).await?;
                let target = format!("0x{}", hex::encode(member_id));
                let arr = payload
                    .as_array()
                    .or_else(|| payload.get("members").and_then(|v| v.as_array()));
                let member = arr
                    .and_then(|a| {
                        a.iter()
                            .find(|m| {
                                m.get("member_id")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.eq_ignore_ascii_case(&target))
                                    .unwrap_or(false)
                            })
                            .cloned()
                    })
                    .ok_or_else(|| {
                        ApiError::not_found(format!(
                            "member {target} not found in cluster 0x{}",
                            hex::encode(cluster)
                        ))
                    })?;
                Ok(member)
            },
        )
        .await
        .map_err(Status::from)?;
        Ok(Response::new(value_to_signed_response(env)?))
    }

    async fn get_cluster_lifecycle(
        &self,
        request: Request<ClusterRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        let req = request.into_inner();
        let common = common_from_proto(req.safety, req.as_of_block, req.fresh_quote.as_ref())?;
        let cluster = parse_address(&req.cluster_address).map_err(Status::from)?;
        let chain = req.chain;
        let cache = CacheKey {
            cluster,
            endpoint: endpoint::LIFECYCLE,
        };
        let env = build_signed(
            &self.state,
            &chain,
            common,
            Some(cache),
            move |app, as_of, _common| async move {
                run_view(&app, endpoint::LIFECYCLE, cluster, as_of.block_number).await
            },
        )
        .await
        .map_err(Status::from)?;
        Ok(Response::new(value_to_signed_response(env)?))
    }

    async fn get_cluster_lifecycle_proof(
        &self,
        request: Request<ClusterRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        proof_method(self, request, endpoint::LIFECYCLE).await
    }

    async fn list_cluster_events(
        &self,
        request: Request<ListEventsRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        let req = request.into_inner();
        let common = common_from_proto(req.safety, req.as_of_block, req.fresh_quote.as_ref())?;
        let cluster = parse_address(&req.cluster_address).map_err(Status::from)?;
        let chain = req.chain;
        let limit = req.limit.unwrap_or(100).clamp(1, 1000);
        let kinds: Vec<String> = req.kind;
        let since = req.since.map(|n| n as i64);
        let env = build_signed(
            &self.state,
            &chain,
            common,
            None,
            move |app, as_of, _common| async move {
                let chain_id = app.store.chain_id();
                let kinds_arg: Vec<String> = kinds.clone();
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
                .bind(since.unwrap_or(0))
                .bind(as_of.block_number as i64)
                .bind(&kinds_arg)
                .bind(limit as i64)
                .fetch_all(app.store.pool())
                .await
                .map_err(ApiError::from)?;
                let mut events = Vec::with_capacity(rows.len());
                for row in rows {
                    let id: i64 = row.try_get("id").map_err(ApiError::from)?;
                    let block_number: i64 = row.try_get("block_number").map_err(ApiError::from)?;
                    let log_index: i32 = row.try_get("log_index").map_err(ApiError::from)?;
                    let tx_hash: Vec<u8> = row.try_get("tx_hash").map_err(ApiError::from)?;
                    let decoded_kind: Option<String> =
                        row.try_get("decoded_kind").map_err(ApiError::from)?;
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
                let next_since = events.last().and_then(|e| e.get("id")).cloned();
                Ok(json!({
                    "cluster": format!("0x{}", hex::encode(cluster)),
                    "events": events,
                    "limit": limit,
                    "next_since": next_since,
                }))
            },
        )
        .await
        .map_err(Status::from)?;
        Ok(Response::new(value_to_signed_response(env)?))
    }

    async fn get_event_by_id(
        &self,
        request: Request<GetEventByIdRequest>,
    ) -> Result<Response<SignedResponse>, Status> {
        let req = request.into_inner();
        let common = common_from_proto(req.safety, req.as_of_block, req.fresh_quote.as_ref())?;
        let chain = req.chain;
        let id = req.id;
        let env = build_signed(
            &self.state,
            &chain,
            common,
            None,
            move |app, _as_of, _common| async move { fetch_event_by_id(&app, id).await },
        )
        .await
        .map_err(Status::from)?;
        Ok(Response::new(value_to_signed_response(env)?))
    }

    type StreamClusterEventsStream =
        Pin<Box<dyn Stream<Item = Result<EventEnvelope, Status>> + Send + 'static>>;

    async fn stream_cluster_events(
        &self,
        request: Request<StreamEventsRequest>,
    ) -> Result<Response<Self::StreamClusterEventsStream>, Status> {
        let req = request.into_inner();
        let app = resolve_chain(&self.state, &req.chain)
            .map_err(Status::from)?
            .clone();
        let cluster = parse_address(&req.cluster_address).map_err(Status::from)?;
        let kinds: Vec<String> = req.kind;
        let kinds_arc = Arc::new(kinds);
        let since = req.since.map(|n| n as i64).unwrap_or(0);
        let pool = app.store.pool().clone();
        let chain_id = app.store.chain_id();
        let signer = app.signer.clone();
        let live_rx = app.sse_tx.subscribe();

        let stream = async_stream::stream! {
            let mut last_id = since;
            // Same per-connection dedup as the SSE handler: when the
            // shared broadcast bus fans the same id through both the
            // in-proc Ingestor channel and the Postgres LISTEN path,
            // emit exactly one envelope per id. See `crate::sse` for
            // the design + sizing rationale.
            let mut recent = RecentIds::new();

            // ---- Replay ----
            loop {
                match read_backlog_for_grpc(&pool, chain_id, &cluster, &kinds_arc, last_id, 500).await {
                    Ok(rows) if rows.is_empty() => break,
                    Ok(rows) => {
                        for row in rows {
                            if !recent.observe(row.id) {
                                continue;
                            }
                            last_id = row.id;
                            match build_event_envelope(&row, signer.as_ref()) {
                                Ok(env) => yield Ok(env),
                                Err(e) => {
                                    yield Err(Status::internal(format!("event-envelope build: {e}")));
                                    return;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        yield Err(Status::internal(format!("backlog read: {e}")));
                        return;
                    }
                }
            }

            // ---- Live tail ----
            let mut live = BroadcastStream::new(live_rx);
            while let Some(item) = live.next().await {
                match item {
                    Ok(ev) => {
                        if ev.cluster != cluster {
                            continue;
                        }
                        if !kinds_arc.is_empty() && !kinds_arc.iter().any(|k| k == &ev.kind) {
                            continue;
                        }
                        // Cheap pre-fetch dedup: skip the row read +
                        // signature when this id already went out.
                        if !recent.observe(ev.event_id) {
                            continue;
                        }
                        match read_row_for_grpc(&pool, chain_id, &cluster, ev.event_id).await {
                            Ok(Some(row)) => {
                                last_id = row.id;
                                match build_event_envelope(&row, signer.as_ref()) {
                                    Ok(env) => yield Ok(env),
                                    Err(e) => {
                                        yield Err(Status::internal(format!("event-envelope build: {e}")));
                                        return;
                                    }
                                }
                            }
                            Ok(None) => continue,
                            Err(e) => {
                                yield Err(Status::internal(format!("live-row read: {e}")));
                                return;
                            }
                        }
                    }
                    Err(_lagged) => {
                        // Catch up from `last_id` and resume.
                        match read_backlog_for_grpc(
                            &pool, chain_id, &cluster, &kinds_arc, last_id, 500,
                        )
                        .await
                        {
                            Ok(rows) => {
                                for row in rows {
                                    if !recent.observe(row.id) {
                                        continue;
                                    }
                                    last_id = row.id;
                                    if let Ok(env) = build_event_envelope(&row, signer.as_ref()) {
                                        yield Ok(env);
                                    }
                                }
                            }
                            Err(e) => {
                                yield Err(Status::internal(format!("post-lag backlog read: {e}")));
                                return;
                            }
                        }
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}

async fn proof_method(
    svc: &ChainIndexerService,
    request: Request<ClusterRequest>,
    endpoint_name: &'static str,
) -> Result<Response<SignedResponse>, Status> {
    let req = request.into_inner();
    let common = common_from_proto(req.safety, req.as_of_block, req.fresh_quote.as_ref())?;
    let cluster = parse_address(&req.cluster_address).map_err(Status::from)?;
    let chain = req.chain;
    let env = build_signed(
        &svc.state,
        &chain,
        common,
        None,
        move |app, as_of, _common| async move {
            let kinds = match endpoint_name {
                endpoint::LEADER => vec!["LeaderClaimed", "LeaderRevoked"],
                endpoint::MEMBERS => vec![
                    "MemberRegistered",
                    "MemberRetired",
                    "InstanceIdUpdated",
                    "PublicEndpointUpdated",
                ],
                endpoint::LIFECYCLE => vec!["ClusterDestroyed"],
                _ => vec![],
            };
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
            .bind(app.store.chain_id())
            .bind(&cluster[..])
            .bind(as_of.block_number as i64)
            .bind(&kinds_owned)
            .fetch_all(app.store.pool())
            .await
            .map_err(ApiError::from)?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let block_number: i64 = row.try_get("block_number").map_err(ApiError::from)?;
                let log_index: i32 = row.try_get("log_index").map_err(ApiError::from)?;
                let tx_hash: Vec<u8> = row.try_get("tx_hash").map_err(ApiError::from)?;
                let topic0: Vec<u8> = row.try_get("topic0").map_err(ApiError::from)?;
                let topics_rest: Vec<u8> = row.try_get("topics_rest").map_err(ApiError::from)?;
                let data: Vec<u8> = row.try_get("data").map_err(ApiError::from)?;
                let decoded_kind: Option<String> =
                    row.try_get("decoded_kind").map_err(ApiError::from)?;
                let decoded: Option<Value> = row.try_get("decoded").map_err(ApiError::from)?;
                out.push(json!({
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
            Ok(json!({
                "endpoint": endpoint_name,
                "cluster": format!("0x{}", hex::encode(cluster)),
                "events": out,
            }))
        },
    )
    .await
    .map_err(Status::from)?;
    Ok(Response::new(value_to_signed_response(env)?))
}

// ---- common-read decoder ----

fn common_from_proto(
    safety: i32,
    as_of_block: Option<u64>,
    fresh_quote: Option<&FreshQuote>,
) -> Result<CommonRead, Status> {
    let safety = match ProtoSafety::try_from(safety).unwrap_or_default() {
        ProtoSafety::Head => crate::as_of::Safety::Head,
        ProtoSafety::Finalized => crate::as_of::Safety::Finalized,
    };
    if as_of_block.is_some() && safety == crate::as_of::Safety::Finalized {
        return Err(Status::invalid_argument(
            "safety and as_of_block are mutually exclusive",
        ));
    }
    let fresh_quote_nonce = match fresh_quote {
        Some(fq) => Some(parse_nonce_proto(&fq.nonce)?),
        None => None,
    };
    Ok(CommonRead {
        safety,
        as_of_block,
        fresh_quote_nonce,
    })
}

fn parse_nonce_proto(s: &str) -> Result<[u8; 32], Status> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes =
        hex::decode(raw).map_err(|e| Status::invalid_argument(format!("nonce hex decode: {e}")))?;
    if bytes.len() != 32 {
        return Err(Status::invalid_argument("nonce must be 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ---- envelope value → proto ----

fn value_to_signed_response(env: Value) -> Result<SignedResponse, Status> {
    let obj = env
        .as_object()
        .ok_or_else(|| Status::internal("envelope is not a JSON object"))?;
    let data = obj
        .get("data")
        .cloned()
        .ok_or_else(|| Status::internal("envelope missing 'data'"))?;
    let as_of_v = obj
        .get("as_of")
        .cloned()
        .ok_or_else(|| Status::internal("envelope missing 'as_of'"))?;
    let attestation_v = obj
        .get("attestation")
        .cloned()
        .ok_or_else(|| Status::internal("envelope missing 'attestation'"))?;
    let quote_b64 = obj
        .get("quote_b64")
        .and_then(|v| v.as_str().map(str::to_string));
    let attestation =
        serde_json::from_value::<teesql_chain_indexer_attest::Attestation>(attestation_v)
            .map_err(|e| Status::internal(format!("attestation decode: {e}")))?;
    Ok(SignedResponse {
        data: Some(value_to_struct(data).map_err(|e| Status::internal(e.to_string()))?),
        as_of: Some(value_to_struct(as_of_v).map_err(|e| Status::internal(e.to_string()))?),
        attestation: Some(proto::Attestation {
            signer_address: attestation.signer_address,
            signature: attestation.signature,
            payload_hash: attestation.payload_hash,
            signed_at: attestation.signed_at,
            expires_at: attestation.expires_at,
        }),
        quote_b64,
    })
}

fn value_to_struct(value: Value) -> anyhow::Result<prost_types::Struct> {
    use prost_types::value::Kind;
    use prost_types::{ListValue, NullValue, Struct, Value as PValue};
    fn convert(v: Value) -> anyhow::Result<PValue> {
        let kind = match v {
            Value::Null => Kind::NullValue(NullValue::NullValue as i32),
            Value::Bool(b) => Kind::BoolValue(b),
            Value::Number(n) => {
                let f = n
                    .as_f64()
                    .ok_or_else(|| anyhow::anyhow!("number {} not f64", n))?;
                if !f.is_finite() {
                    anyhow::bail!("non-finite number");
                }
                Kind::NumberValue(f)
            }
            Value::String(s) => Kind::StringValue(s),
            Value::Array(arr) => {
                let mut values = Vec::with_capacity(arr.len());
                for x in arr {
                    values.push(convert(x)?);
                }
                Kind::ListValue(ListValue { values })
            }
            Value::Object(obj) => {
                let mut fields: std::collections::BTreeMap<String, PValue> =
                    std::collections::BTreeMap::new();
                for (k, v) in obj {
                    fields.insert(k, convert(v)?);
                }
                Kind::StructValue(Struct {
                    fields: fields.into_iter().collect(),
                })
            }
        };
        Ok(PValue { kind: Some(kind) })
    }
    let v = convert(value)?;
    match v.kind {
        Some(Kind::StructValue(s)) => Ok(s),
        _ => anyhow::bail!("value is not an object"),
    }
}

// ---- streaming-side helpers (use the same SQL shapes as REST) ----

#[derive(Debug)]
struct GrpcEventRow {
    id: i64,
    block_number: i64,
    log_index: i32,
    tx_hash: Vec<u8>,
    decoded_kind: Option<String>,
    decoded: Option<Value>,
}

async fn read_backlog_for_grpc(
    pool: &sqlx::PgPool,
    chain_id: i32,
    cluster: &[u8; 20],
    kinds: &Arc<Vec<String>>,
    after_id: i64,
    limit: i64,
) -> Result<Vec<GrpcEventRow>, sqlx::Error> {
    let kinds_arg: Vec<String> = kinds.as_ref().clone();
    let rows = sqlx::query(
        "SELECT id, block_number, log_index, tx_hash, decoded_kind, decoded
         FROM events
         WHERE chain_id = $1
           AND contract = $2
           AND removed = false
           AND id > $3
           AND ($4::text[] = '{}' OR decoded_kind = ANY($4))
         ORDER BY id
         LIMIT $5",
    )
    .bind(chain_id)
    .bind(&cluster[..])
    .bind(after_id)
    .bind(&kinds_arg)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(GrpcEventRow {
            id: row.try_get("id")?,
            block_number: row.try_get("block_number")?,
            log_index: row.try_get("log_index")?,
            tx_hash: row.try_get("tx_hash")?,
            decoded_kind: row.try_get("decoded_kind")?,
            decoded: row.try_get("decoded")?,
        });
    }
    Ok(out)
}

async fn read_row_for_grpc(
    pool: &sqlx::PgPool,
    chain_id: i32,
    cluster: &[u8; 20],
    id: i64,
) -> Result<Option<GrpcEventRow>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, block_number, log_index, tx_hash, decoded_kind, decoded
         FROM events
         WHERE chain_id = $1 AND id = $2 AND contract = $3 AND removed = false",
    )
    .bind(chain_id)
    .bind(id)
    .bind(&cluster[..])
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(GrpcEventRow {
        id: row.try_get("id")?,
        block_number: row.try_get("block_number")?,
        log_index: row.try_get("log_index")?,
        tx_hash: row.try_get("tx_hash")?,
        decoded_kind: row.try_get("decoded_kind")?,
        decoded: row.try_get("decoded")?,
    }))
}

fn build_event_envelope(
    row: &GrpcEventRow,
    signer: &teesql_chain_indexer_attest::Signer,
) -> anyhow::Result<EventEnvelope> {
    let event = json!({
        "id": row.id,
        "block_number": row.block_number,
        "log_index": row.log_index,
        "tx_hash": format!("0x{}", hex::encode(&row.tx_hash)),
        "kind": row.decoded_kind,
        "decoded": row.decoded,
    });
    // Streaming frames embed `block_number` as the as_of block — the
    // client only sees the block this event landed in, not whatever
    // head was when the frame was emitted.
    let as_of = json!({
        "block_number": row.block_number,
        "block_hash": Value::Null,
        "block_timestamp": Value::Null,
        "finalized_block": Value::Null,
        "safety": "head",
    });
    let attestation = signer.sign(&event, &as_of);
    Ok(EventEnvelope {
        event: Some(value_to_struct(event)?),
        as_of: Some(value_to_struct(as_of)?),
        attestation: Some(proto::Attestation {
            signer_address: attestation.signer_address,
            signature: attestation.signature,
            payload_hash: attestation.payload_hash,
            signed_at: attestation.signed_at,
            expires_at: attestation.expires_at,
        }),
    })
}

// Suppress unused-import warnings from helpers consumed only by
// tests + the stream method (which doesn't use as_of/envelope/parse_kinds
// directly).
#[allow(dead_code)]
fn _link_unused() {
    let _ = parse_kinds;
    let _ = NotifyEvent {
        cluster: [0; 20],
        kind: String::new(),
        event_id: 0,
        block_number: 0,
        log_index: 0,
    };
    let _ = as_of::Safety::Head;
    let _ = envelope::build;
}
