//! Ingest pipeline. Spec §6.
//!
//! The [`Ingestor`] owns the runtime: cold-start backfill via
//! `eth_getLogs` chunked at 2,000 blocks (§6.1), then a steady-state
//! WS subscription (§6.2) with reorg-aware insertion (§6.3) and
//! `pg_notify` fan-out.
//!
//! ## Tasks
//!
//! `run()` executes serially in the spawning task — all work happens
//! on a single tokio task by default. The structure mirrors the spec's
//! ws_listener / ingest_worker split conceptually (the WS stream is
//! the listener; the per-event handler is the worker), but elides the
//! separating mpsc channel because Postgres write latency, not Rust,
//! is the throughput ceiling per §6.2 — and a single channel pop
//! before every insert just adds context-switch noise without buying
//! parallelism.
//!
//! Callers that want explicit out-of-band fan-out (e.g. Agent 6's SSE
//! handler running in the same process) can supply a
//! `notify_channel(tx)` to the builder; the ingestor sends a
//! [`NotifyEvent`] on every successful event apply, alongside the
//! standard `pg_notify` so cross-process consumers still see it.
//!
//! ## Reconnect model
//!
//! `steady_state_loop` runs forever. On a WS error or unexpected
//! stream end, it backs off (1s → 30s, capped, exponential) and falls
//! back to a chunked `eth_getLogs` catchup before re-subscribing —
//! same code path as cold-start, so a fresh process and a recovered
//! one converge to the same state.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use alloy::consensus::{BlockHeader, Transaction};
use alloy::network::primitives::HeaderResponse;
use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, Log};
use alloy::transports::ws::WsConnect;
use futures::StreamExt;
use tokio::sync::mpsc;

use crate::decode::{DecodedEvent, Decoder};
use crate::reorg::{ReorgError, ReorgHandler};
use crate::store::{EventStore, WatchedContract};
use crate::views::View;

/// Maximum block range per `eth_getLogs` call — spec §6.1.5. Anything
/// larger trips Alchemy's response-size guard.
const BACKFILL_CHUNK: u64 = 2_000;

/// Backoff bounds for WS reconnect loops — spec §10 ("WS disconnect"
/// row).
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Postgres `chain_state` key for the highest block we've subscribed
/// past. Drives the reconnect catchup: on resume we eth_getLogs from
/// `last_subscription_seq + 1`. Spec §10.
const STATE_LAST_SUBSCRIPTION_SEQ: &str = "last_subscription_seq";

/// Periodicity at which the steady-state loop polls for new
/// watched contracts (e.g. a `ClusterDeployed` View just registered
/// a fresh diamond). Faster than this and we'd be hammering Postgres
/// for trivial reads; slower and a freshly-registered diamond's
/// events would lag noticeably. 5s is well inside the per-cluster
/// "first-event after deploy" SLA the gas-webhook needs.
const WATCHED_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Notification fan-out payload. Sent on the in-process mpsc when the
/// builder was given one, AND serialised + handed to `pg_notify`.
///
/// `cluster` ships on the wire as a 0x-prefixed 20-byte hex string
/// rather than the default serde `[u8; 20]` (which would emit a JSON
/// array of u8s). The string shape is what every cross-process
/// consumer expects: `pg_notify` payloads, REST/SSE clients, and the
/// `LISTEN chain_indexer_events` worker that re-hydrates back into
/// `NotifyEvent`. The byte-array default would break round-trip
/// deserialization on the LISTEN path (`invalid type: sequence,
/// expected a string`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NotifyEvent {
    /// Address that emitted the event. `[u8; 20]` rather than `Address`
    /// so consumers don't need alloy on the receive side.
    #[serde(
        serialize_with = "serialize_cluster_hex",
        deserialize_with = "deserialize_cluster_hex"
    )]
    pub cluster: [u8; 20],
    /// Decoded `Decoder.kind()` value. `unknown` when no decoder
    /// matched — kept as a non-empty string so JSON consumers can
    /// always project it.
    pub kind: String,
    /// `events.id` assigned by Postgres. Consumers paginate from this.
    pub event_id: i64,
    pub block_number: u64,
    pub log_index: i32,
}

fn serialize_cluster_hex<S: serde::Serializer>(addr: &[u8; 20], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("0x{}", hex::encode(addr)))
}

fn deserialize_cluster_hex<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 20], D::Error> {
    use serde::de::Error;
    let s: String = serde::Deserialize::deserialize(d)?;
    let raw = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(raw).map_err(D::Error::custom)?;
    if bytes.len() != 20 {
        return Err(D::Error::custom(format!(
            "cluster address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Wire shape for the `chain_indexer_control` LISTEN channel — Track
/// A4. Mirrors `NotifyEvent`'s string-encoded `cluster` discipline so
/// the consumer-side LISTEN worker (Track D3 SSE handler) can
/// deserialize directly without an intermediate shape that drifts.
///
/// `kind` is one of `"ControlInstructionBroadcast"` | `"ControlAck"`.
/// `row_id` is the bigserial PK assigned to either the
/// `control_instructions` or `control_acks` row — the consumer uses
/// it for ordered backlog reads exactly like `event_id` does on the
/// generic events bus. `event_id` rides alongside as the
/// generic-table row id so the consumer can correlate to the raw
/// `events` row when needed (e.g. for tx-hash provenance assertions
/// during reorg replay verification).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ControlNotifyEvent {
    #[serde(
        serialize_with = "serialize_cluster_hex",
        deserialize_with = "deserialize_cluster_hex"
    )]
    pub cluster: [u8; 20],
    pub kind: String,
    pub row_id: i64,
    pub event_id: i64,
    pub block_number: u64,
    pub log_index: i32,
}

/// Long-running ingest engine. One per chain.
///
/// Construct via [`Ingestor::builder`] — direct construction would
/// have to expose every internal field, and the builder is also
/// where dependency injection (decoders, views, optional notify
/// channel) happens.
///
/// `Debug` is intentionally hand-written so trait objects (decoders /
/// views) don't have to implement it; the printed form names the
/// chain and counts of plugged-in components, which is what surfaces
/// in `tracing` spans and test failures.
pub struct Ingestor {
    chain_id: i32,
    rpc_http_url: String,
    rpc_ws_url: String,
    store: EventStore,
    decoders: Arc<HashMap<[u8; 32], Box<dyn Decoder>>>,
    views: Arc<Vec<Box<dyn View>>>,
    finality_depth: u64,
    notify_tx: Option<mpsc::Sender<NotifyEvent>>,
    /// Optional R2 mirror for `MemberWgPubkeySetV2` quote bytes
    /// (unified-network-design §9.2). Fire-and-forget: a failed upload
    /// never fails the DB write. Defaults to `None` (mirror disabled).
    quote_r2_mirror: Option<Arc<dyn crate::r2_mirror::R2QuoteMirror>>,
}

impl std::fmt::Debug for Ingestor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ingestor")
            .field("chain_id", &self.chain_id)
            .field("decoders", &self.decoders.len())
            .field("views", &self.views.len())
            .field("finality_depth", &self.finality_depth)
            .finish()
    }
}

impl Ingestor {
    pub fn builder() -> IngestorBuilder {
        IngestorBuilder::default()
    }

    /// Run forever. Cold-start backfill, then the steady-state WS
    /// loop with reconnect/backoff. Returns only on a fatal error
    /// (catastrophic reorg, missing required dependency, etc.) — the
    /// spec §10 expectation is that the supervisor restarts on `Err`,
    /// and a clean exit is impossible by design.
    pub async fn run(self) -> anyhow::Result<()> {
        tracing::info!(
            chain_id = self.chain_id,
            finality_depth = self.finality_depth,
            "ingestor starting cold-start backfill"
        );

        // Replay historical ClusterDeployed events into
        // `watched_contracts`. Older indexer revisions decoded the
        // event but never auto-registered the diamond, leaving
        // already-indexed clusters invisible to the per-diamond
        // ingest loop. This pass is idempotent (`add_watched_contract`
        // does ON CONFLICT DO NOTHING) so it's safe to run on every
        // boot — its job is to backfill old gaps without disturbing
        // anything else.
        self.rehydrate_watched_diamonds().await?;

        // Persist a snapshot of the chain head so the cold-start loop
        // has a stable target. New blocks arriving during backfill
        // are caught by the reconnect/catchup path the steady-state
        // loop runs on first entry.
        let head = self.fetch_head().await?;
        self.store
            .set_state("head_block", &head.to_string())
            .await?;

        self.cold_start_backfill(head).await?;

        tracing::info!(
            chain_id = self.chain_id,
            head,
            "cold-start backfill complete; entering steady state"
        );

        self.steady_state_loop().await
    }

    /// Walk the `events` table for every prior ClusterDeployed and
    /// register the diamond into `watched_contracts`. Closes the gap
    /// where an older indexer revision recorded the factory event
    /// without bootstrapping the per-diamond watcher — without this
    /// pass, a v0.1.3-era cursor that's already past the diamond's
    /// deploy block would never re-decode the event and the cluster
    /// would stay invisible to read endpoints + downstream consumers.
    async fn rehydrate_watched_diamonds(&self) -> anyhow::Result<()> {
        let rows = sqlx::query(
            "SELECT contract, block_number, decoded \
             FROM events \
             WHERE chain_id = $1 AND decoded_kind = 'ClusterDeployed' AND removed = false \
             ORDER BY block_number, log_index",
        )
        .bind(self.chain_id)
        .fetch_all(self.store.pool())
        .await?;

        if rows.is_empty() {
            return Ok(());
        }

        let mut added = 0usize;
        for row in rows {
            use sqlx::Row as _;
            let factory_bytes: Vec<u8> = row.try_get("contract")?;
            let block_number_i64: i64 = row.try_get("block_number")?;
            let decoded: Option<serde_json::Value> = row.try_get("decoded")?;
            let Some(payload) = decoded else { continue };
            let Some(diamond_str) = payload.get("diamond").and_then(|v| v.as_str()) else {
                tracing::warn!(
                    block = block_number_i64,
                    "rehydrate: ClusterDeployed payload missing `diamond` field"
                );
                continue;
            };
            let raw = diamond_str.strip_prefix("0x").unwrap_or(diamond_str);
            let bytes = match hex::decode(raw) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        block = block_number_i64,
                        diamond = diamond_str,
                        error = %e,
                        "rehydrate: ClusterDeployed.diamond not hex"
                    );
                    continue;
                }
            };
            let diamond: [u8; 20] = match bytes.as_slice().try_into() {
                Ok(b) => b,
                Err(_) => {
                    tracing::warn!(
                        block = block_number_i64,
                        diamond = diamond_str,
                        len = bytes.len(),
                        "rehydrate: ClusterDeployed.diamond expected 20 bytes"
                    );
                    continue;
                }
            };
            let factory: [u8; 20] = factory_bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("ClusterDeployed event row has malformed contract column")
            })?;
            let from_block = u64::try_from(block_number_i64).map_err(|_| {
                anyhow::anyhow!("rehydrate: block_number {block_number_i64} negative")
            })?;
            self.store
                .add_watched_contract(diamond, "cluster_diamond", Some(factory), from_block)
                .await?;
            added += 1;
        }

        tracing::info!(
            chain_id = self.chain_id,
            count = added,
            "rehydrate: replayed ClusterDeployed events into watched_contracts"
        );
        Ok(())
    }

    /// Resolve the current chain head over HTTPS. Used as the
    /// snapshot block for cold-start backfill and as the resume
    /// point for catchup after a WS disconnect.
    async fn fetch_head(&self) -> anyhow::Result<u64> {
        let provider = ProviderBuilder::new().connect_http(self.rpc_http_url.parse()?);
        let head = provider.get_block_number().await?;
        Ok(head)
    }

    /// Iterate the watched-contract registry and bring every cursor
    /// up to `target_head`. Re-iterates after each pass so newly-
    /// registered diamonds (added by `View.apply` during the pass)
    /// are picked up in the same loop — spec §6.1 step 6.
    async fn cold_start_backfill(&self, target_head: u64) -> anyhow::Result<()> {
        let topic0_set = self.topic0_set();
        loop {
            let mut watched = self.store.list_watched_contracts().await?;
            watched.sort_by_key(|w| w.from_block); // earliest first → ClusterDeployed before child events
            let mut work_remaining = false;

            for w in watched.iter() {
                let cursor = self.store.cursor(w.address).await?;
                let from = cursor.max(w.from_block);
                if from > target_head {
                    continue;
                }
                work_remaining = true;
                tracing::info!(
                    chain_id = self.chain_id,
                    address = %hex::encode(w.address),
                    kind = %w.kind,
                    from,
                    to = target_head,
                    "backfilling contract"
                );
                self.backfill_contract(w, &topic0_set, from, target_head)
                    .await?;
            }

            // No contract had work this pass AND the watched set
            // didn't grow during the pass: cold-start is done.
            if !work_remaining {
                let after_count = self.store.list_watched_contracts().await?.len();
                if after_count == watched.len() {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Backfill one watched contract from `from` to `to` inclusive,
    /// chunked at `BACKFILL_CHUNK`. Decode → block-upsert → event-
    /// insert → views → notify per chunk; advance the cursor only
    /// after a chunk fully commits so a partial-chunk crash retries
    /// the same chunk on restart (idempotent via the dedup index).
    async fn backfill_contract(
        &self,
        watched: &WatchedContract,
        topic0_set: &[B256],
        from: u64,
        to: u64,
    ) -> anyhow::Result<()> {
        let provider = ProviderBuilder::new().connect_http(self.rpc_http_url.parse()?);
        let address = Address::from_slice(&watched.address);

        let mut start = from;
        while start <= to {
            let end = (start + BACKFILL_CHUNK - 1).min(to);
            let filter = Filter::new()
                .address(address)
                .event_signature(topic0_set.to_vec())
                .from_block(start)
                .to_block(end);
            let logs = provider.get_logs(&filter).await?;
            tracing::debug!(
                address = %hex::encode(watched.address),
                from = start,
                to = end,
                count = logs.len(),
                "backfill chunk"
            );

            for log in logs {
                self.process_log(&provider, log).await?;
            }

            // Cursor stores "next block to scan" → end + 1.
            self.store
                .advance_cursor(watched.address, end.saturating_add(1))
                .await?;
            start = end.saturating_add(1);
        }
        Ok(())
    }

    /// Steady-state WS loop. Subscribes to `logs` (filtered by every
    /// watched address + every known topic0) and `newHeads` (for
    /// reorg detection). On any error, backs off and reruns the
    /// catchup-via-eth_getLogs path before re-subscribing.
    async fn steady_state_loop(self) -> anyhow::Result<()> {
        let mut backoff = RECONNECT_BACKOFF_MIN;
        loop {
            match self.steady_state_once().await {
                Ok(()) => {
                    // Restart triggered by the inner loop (e.g.
                    // watched-set grew). Reset backoff.
                    backoff = RECONNECT_BACKOFF_MIN;
                }
                Err(IngestError::Fatal(e)) => return Err(e),
                Err(IngestError::Transient(e)) => {
                    tracing::warn!(
                        chain_id = self.chain_id,
                        backoff_ms = backoff.as_millis(),
                        error = %e,
                        "steady-state loop error; backing off"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
                    // HTTPS catchup before re-subscribing — picks up
                    // anything we missed during the disconnect window.
                    if let Err(e) = self.catchup_after_disconnect().await {
                        tracing::warn!(error = %e, "catchup failed; continuing to resubscribe anyway");
                    }
                }
            }
        }
    }

    /// HTTPS catchup from `last_subscription_seq` to the current
    /// head. Identical semantics to cold-start backfill but scoped
    /// to whatever watched contracts existed at disconnect time.
    async fn catchup_after_disconnect(&self) -> anyhow::Result<()> {
        let head = self.fetch_head().await?;
        let resume_block = self
            .store
            .get_state(STATE_LAST_SUBSCRIPTION_SEQ)
            .await?
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        if resume_block >= head {
            return Ok(());
        }
        // cold_start_backfill is idempotent and uses the per-contract
        // cursor; calling it here re-walks everything past the
        // cursor up to `head`, which is exactly the catchup we want.
        self.cold_start_backfill(head).await
    }

    /// One steady-state subscription cycle. Returns:
    /// - `Ok(())` when an inner condition (watched-set grew) triggered
    ///   a planned re-subscribe.
    /// - `Err(Transient)` on WS / RPC errors → caller backs off and
    ///   reconnects.
    /// - `Err(Fatal)` on catastrophic reorg → caller propagates and
    ///   the supervisor restarts the process.
    async fn steady_state_once(&self) -> Result<(), IngestError> {
        let watched_initial = self
            .store
            .list_watched_contracts()
            .await
            .map_err(IngestError::Transient)?;
        let watched_addrs: Vec<Address> = watched_initial
            .iter()
            .map(|w| Address::from_slice(&w.address))
            .collect();
        let watched_set: HashSet<[u8; 20]> = watched_initial.iter().map(|w| w.address).collect();
        let initial_set_size = watched_set.len();

        if watched_addrs.is_empty() {
            // No contracts to subscribe to yet — sleep + retry. This
            // happens on a fresh deploy before the first factory has
            // been registered.
            tokio::time::sleep(WATCHED_REFRESH_INTERVAL).await;
            return Ok(());
        }

        let topic0_set = self.topic0_set();

        let ws_provider = ProviderBuilder::new()
            .connect_ws(WsConnect::new(self.rpc_ws_url.clone()))
            .await
            .map_err(|e| IngestError::Transient(anyhow::anyhow!("WS connect: {e}")))?;
        let http_provider = ProviderBuilder::new().connect_http(
            self.rpc_http_url
                .parse()
                .map_err(|e| IngestError::Transient(anyhow::anyhow!("rpc_http_url: {e}")))?,
        );

        let log_filter = Filter::new()
            .address(watched_addrs.clone())
            .event_signature(topic0_set);
        let log_sub = ws_provider
            .subscribe_logs(&log_filter)
            .await
            .map_err(|e| IngestError::Transient(anyhow::anyhow!("subscribe_logs: {e}")))?;
        let mut log_stream = log_sub.into_stream();

        let head_sub = ws_provider
            .subscribe_blocks()
            .await
            .map_err(|e| IngestError::Transient(anyhow::anyhow!("subscribe_blocks: {e}")))?;
        let mut head_stream = head_sub.into_stream();

        let mut refresh_tick = tokio::time::interval(WATCHED_REFRESH_INTERVAL);
        // First tick fires immediately by default; skip it so we don't
        // spin a re-subscribe before the first real event.
        refresh_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        refresh_tick.tick().await;

        loop {
            tokio::select! {
                biased;

                // Reorg detection takes priority over event ingestion.
                // A new head with a mismatching parent_hash means the
                // logs we're about to insert are on the wrong chain.
                maybe_head = head_stream.next() => {
                    match maybe_head {
                        Some(header) => self.handle_new_head(&http_provider, header).await?,
                        None => return Err(IngestError::Transient(anyhow::anyhow!(
                            "newHeads stream ended"
                        ))),
                    }
                }

                maybe_log = log_stream.next() => {
                    match maybe_log {
                        Some(log) => {
                            // Defensive client-side address check —
                            // the WS server applies the filter, but
                            // a stray log arriving via reconnect or
                            // subscription overlap should still be
                            // dropped silently here.
                            let addr_bytes: [u8; 20] = log.address().0.0;
                            if !watched_set.contains(&addr_bytes) {
                                continue;
                            }
                            // Per-event reorg gate (spec §6.2 step 1):
                            // if the log's block_hash differs from
                            // what we stored at the same height, the
                            // chain has reorged underneath us. Run
                            // the rollback BEFORE processing the new
                            // log so we don't stack canonical events
                            // on top of stale ones.
                            if let (Some(bn), Some(bh)) = (log.block_number, log.block_hash) {
                                if let Some(prior) = self
                                    .store
                                    .block_hash_at(bn)
                                    .await
                                    .map_err(IngestError::Transient)?
                                {
                                    if prior != bh.0 {
                                        self.handle_reorg(&http_provider, bn).await?;
                                    }
                                }
                            }
                            self.process_log(&http_provider, log).await
                                .map_err(IngestError::Transient)?;
                        }
                        None => return Err(IngestError::Transient(anyhow::anyhow!(
                            "logs stream ended"
                        ))),
                    }
                }

                _ = refresh_tick.tick() => {
                    let now = self.store.list_watched_contracts().await
                        .map_err(IngestError::Transient)?;
                    if now.len() != initial_set_size {
                        tracing::info!(
                            chain_id = self.chain_id,
                            old = initial_set_size,
                            new = now.len(),
                            "watched-contract set changed; re-subscribing"
                        );
                        // Bring the new contract(s) up to head before
                        // re-subscribing so we don't miss events
                        // emitted between deploy and our resub.
                        let head = self.fetch_head().await
                            .map_err(IngestError::Transient)?;
                        self.cold_start_backfill(head).await
                            .map_err(IngestError::Transient)?;
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Handle a newHeads frame: persist the block, run reorg detection
    /// against `parent_hash`, and on rollback advance materialised
    /// views forward from the common ancestor.
    async fn handle_new_head<P>(
        &self,
        provider: &P,
        header: <alloy::network::Ethereum as alloy::network::Network>::HeaderResponse,
    ) -> Result<(), IngestError>
    where
        P: Provider,
    {
        let number = header.number();
        let hash: [u8; 32] = header.hash().0;
        let parent_hash: [u8; 32] = header.parent_hash().0;
        let block_ts: i64 = header.timestamp() as i64;

        // Compare parent_hash to what we stored for number-1. A mismatch
        // means we ingested a stale chain; walk back and replay.
        let mut reorg_needed = false;
        if number > 0 {
            if let Some(prev_stored) = self
                .store
                .block_hash_at(number - 1)
                .await
                .map_err(IngestError::Transient)?
            {
                if prev_stored != parent_hash {
                    reorg_needed = true;
                }
            }
        }

        // Persist the block. If the row existed with a different hash
        // the upsert returns the prior hash — also a reorg signal.
        let prior = self
            .store
            .upsert_block(number, hash, parent_hash, block_ts)
            .await
            .map_err(IngestError::Transient)?;
        if prior.is_some() {
            reorg_needed = true;
        }

        if reorg_needed {
            tracing::warn!(
                chain_id = self.chain_id,
                number,
                "reorg detected on newHeads; running ancestor walk"
            );
            self.handle_reorg(provider, number).await?;
        }

        self.store
            .set_state(STATE_LAST_SUBSCRIPTION_SEQ, &number.to_string())
            .await
            .map_err(IngestError::Transient)?;
        self.store
            .set_state("head_block", &number.to_string())
            .await
            .map_err(IngestError::Transient)?;
        if number >= self.finality_depth {
            self.store
                .set_state(
                    "finalized_block",
                    &(number - self.finality_depth).to_string(),
                )
                .await
                .map_err(IngestError::Transient)?;
        }

        Ok(())
    }

    /// Reorg orchestration: find the common ancestor, mark events
    /// past it as removed, then replay surviving events through
    /// every view.
    async fn handle_reorg<P>(&self, provider: &P, head: u64) -> Result<(), IngestError>
    where
        P: Provider,
    {
        let handler = ReorgHandler::new(self.finality_depth);
        let common = match handler
            .find_common_ancestor(&self.store, provider, head)
            .await
        {
            Ok(b) => b,
            Err(ReorgError::DeeperThanFinality { .. }) => {
                return Err(IngestError::Fatal(anyhow::anyhow!(
                    "reorg deeper than finality_depth ({} blocks); supervisor restart required",
                    self.finality_depth
                )));
            }
            Err(e) => return Err(IngestError::Transient(anyhow::Error::from(e))),
        };

        let removed = self
            .store
            .mark_removed_after(common)
            .await
            .map_err(IngestError::Transient)?;
        // Track A4: control-plane rows live in dedicated tables and
        // are not covered by `mark_removed_after` (which only flips
        // `events`). Roll them back alongside the generic events so
        // the per-cluster ControlOrderer (Track D1) doesn't see
        // dispatched-then-orphaned instructions/acks past the
        // common ancestor.
        let removed_control = self
            .store
            .mark_control_removed_after(common)
            .await
            .map_err(IngestError::Transient)?;
        // GAP-W1-003: `cluster_member_quotes` is another dedicated
        // table (raw TDX quote bytes recovered from
        // `setMemberWgPubkeyAttested` tx calldata, keyed by
        // `(chain, cluster, member, quote_hash)`). Roll back the rows
        // whose source `MemberWgPubkeySetV2` event landed past the
        // common ancestor so the REST surface stops serving
        // forked-out quote bytes between rollback and replay. The
        // replay-side `upsert_member_quote` revives the row when the
        // event re-emits on the new canonical chain.
        let removed_quotes = self
            .store
            .mark_member_quotes_removed_after(common)
            .await
            .map_err(IngestError::Transient)?;
        tracing::warn!(
            chain_id = self.chain_id,
            common_ancestor = common,
            head,
            removed_events = removed,
            removed_control = removed_control,
            removed_quotes = removed_quotes,
            "reorg rollback applied; replaying views forward"
        );

        // Replay views forward from common+1 to head. The simplest
        // correct path: re-process every watched contract's events
        // from common+1 via the cold_start_backfill path (idempotent;
        // reuses the same View.apply() logic).
        self.cold_start_backfill(head)
            .await
            .map_err(IngestError::Transient)?;
        Ok(())
    }

    /// Common per-event handler for both backfill and steady-state.
    ///
    /// Reorg detection is the caller's responsibility (steady-state
    /// runs the `block_hash_at` probe inline; backfill trusts the
    /// chain because we just fetched the canonical logs ourselves).
    /// Keeping the reorg branch out of here breaks the
    /// `process_log → handle_reorg → cold_start_backfill →
    /// process_log` recursion the compiler refuses to size.
    async fn process_log<P>(&self, provider: &P, log: Log) -> anyhow::Result<()>
    where
        P: Provider,
    {
        let block_number = log
            .block_number
            .ok_or_else(|| anyhow::anyhow!("log missing block_number"))?;
        let block_hash: [u8; 32] = log
            .block_hash
            .ok_or_else(|| anyhow::anyhow!("log missing block_hash"))?
            .0;

        // Persist the block row alongside the event for completeness;
        // header timestamp is unknown from the log alone, so stamp 0.
        // (newHeads handler will overwrite with the real timestamp.)
        self.store
            .upsert_block(block_number, block_hash, [0u8; 32], 0)
            .await?;

        let event = DecodedEvent::from_log(self.chain_id, &log, &self.decoders)?;
        let inserted_id = self.store.insert_event(&event).await?;
        let event_id = match inserted_id {
            Some(id) => id,
            None => {
                // Already ingested; idempotent path — still re-apply
                // views in case the prior apply crashed mid-flight.
                tracing::trace!(
                    block_number,
                    log_index = event.log_index,
                    "event already in store; re-applying views"
                );
                // Fetch the existing row's id so notify carries a
                // meaningful event_id.
                self.fetch_event_id(&event).await?
            }
        };

        for view in self.views.iter() {
            view.apply(&self.store, &event).await?;
        }

        // Auto-register child diamonds emitted by a watched factory.
        // Spec §6.1 step 6 — every `ClusterDeployed` from a factory
        // becomes a new `cluster_diamond` watched_contract entry,
        // anchored to the deploy block so backfill picks up the
        // diamond's own event surface from the moment it was minted.
        // The cold-start refresh tick + steady-state watched-set
        // monitor in `steady_state_once` notice the new row and
        // re-subscribe.
        if event.kind.as_deref() == Some("ClusterDeployed") {
            if let Err(e) = self.register_deployed_diamond(&event).await {
                // Don't fail the whole event apply on a registry write
                // hiccup — the next ClusterDeployed re-application
                // (WS replay, restart, or operator-driven backfill) is
                // idempotent and will retry. Log loudly so the gap is
                // visible.
                tracing::warn!(
                    chain_id = self.chain_id,
                    block = event.block_number,
                    log_index = event.log_index,
                    error = %e,
                    "auto-register ClusterDeployed diamond failed; retry on next replay"
                );
            }
        }

        // Track A4: control-plane events go to dedicated tables in
        // addition to the generic `events` row, and fan out on the
        // separate `chain_indexer_control` channel. The per-cluster
        // ControlOrderer (Track D1) consumes that channel; keeping
        // control traffic off the generic events bus avoids forcing
        // every existing SSE subscriber to filter the new high-rate
        // (per-instruction × per-member) ack volume out of their feed.
        //
        // Failures here log and move on by design — the row is
        // already in `events` so a future replay (WS reconnect,
        // operator-driven `eth_getLogs` re-pull) re-runs this branch
        // idempotently against the unique
        // `(cluster, nonce|job_id, seq) WHERE removed=false` indexes.
        match event.kind.as_deref() {
            Some("ControlInstructionBroadcast") => {
                if let Err(e) = self
                    .insert_control_instruction_from_event(&event, event_id)
                    .await
                {
                    tracing::warn!(
                        chain_id = self.chain_id,
                        block = event.block_number,
                        log_index = event.log_index,
                        error = %e,
                        "ControlInstructionBroadcast insert/notify failed; retry on next replay"
                    );
                }
            }
            Some("ControlAck") => {
                if let Err(e) = self.insert_control_ack_from_event(&event, event_id).await {
                    tracing::warn!(
                        chain_id = self.chain_id,
                        block = event.block_number,
                        log_index = event.log_index,
                        error = %e,
                        "ControlAck insert/notify failed; retry on next replay"
                    );
                }
            }
            // V2 admission event: the on-chain payload is just the
            // `(memberId, wgPubkey, quoteHash)` triple; the indexer
            // recovers the ~4.5 KB TDX quote bytes from the originating
            // tx's calldata and persists them in `cluster_member_quotes`
            // so the REST quote surface (§9.2) can serve them by hash.
            //
            // Failures log and move on for the same reason as the
            // control-plane branches above: the generic `events` row is
            // already in place, so a future replay re-runs this branch
            // idempotently against the unique
            // `(chain_id, cluster_address, member_id, quote_hash)`
            // primary key on `cluster_member_quotes`.
            Some("MemberWgPubkeySetV2") => {
                if let Err(e) = self
                    .recover_attested_quote_from_event(provider, &event)
                    .await
                {
                    tracing::warn!(
                        chain_id = self.chain_id,
                        block = event.block_number,
                        log_index = event.log_index,
                        tx_hash = %hex::encode(event.tx_hash),
                        error = %e,
                        "MemberWgPubkeySetV2 quote-byte recovery failed; retry on next replay"
                    );
                }
            }
            _ => {}
        }

        let kind = event.kind.clone().unwrap_or_else(|| "unknown".to_string());
        let payload = NotifyEvent {
            cluster: event.contract,
            kind: kind.clone(),
            event_id,
            block_number: event.block_number,
            log_index: event.log_index,
        };
        let payload_json = serde_json::to_value(&payload)?;
        self.store.notify(&payload_json).await?;

        if let Some(tx) = &self.notify_tx {
            // Try-send: a slow consumer must not back-pressure the
            // ingest loop, so we drop on full and rely on pg_notify
            // as the durable fan-out.
            if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                tx.try_send(payload.clone())
            {
                tracing::warn!("notify_tx full; dropping NotifyEvent (pg_notify still sent)");
            }
        }

        Ok(())
    }

    /// Insert a `ControlInstructionBroadcast` row into the dedicated
    /// `control_instructions` table and fire the
    /// `chain_indexer_control` notification. Decodes the typed fields
    /// out of the generic `event.decoded` JSON the
    /// [`crate::decode::Decoder`] produced — the JSON shape is set in
    /// `teesql-abi::cluster_diamond::ControlInstructionBroadcastDecoder`
    /// (Track A4). Idempotent: the unique
    /// `(cluster, nonce) WHERE removed=false` index swallows replays.
    /// Spec docs/specs/control-plane-redesign.md §5.3.
    async fn insert_control_instruction_from_event(
        &self,
        event: &DecodedEvent,
        event_id: i64,
    ) -> anyhow::Result<()> {
        let payload = event.decoded.as_ref().ok_or_else(|| {
            anyhow::anyhow!("ControlInstructionBroadcast event has no decoded payload")
        })?;

        let instruction_id = parse_bytes32_field(payload, "instructionId")?;
        // clusterId on the event is the bytes32 cluster discriminator
        // pinned by the EIP-712 envelope; we store the emitter address
        // (event.contract) as the row's `cluster` column so consumers
        // join against `watched_contracts.address` without indirection.
        // The on-chain `clusterId` lives in the raw events row's
        // decoded JSON for callers who need both.
        let nonce = parse_uint64_string_field(payload, "nonce")?;
        let target_members = parse_bytes32_array_field(payload, "targetMembers")?;
        let expiry = parse_uint64_string_field(payload, "expiry")?;
        let salt = parse_bytes32_field(payload, "salt")?;
        let ciphertext = parse_bytes_field(payload, "ciphertext")?;
        let ciphertext_hash = parse_bytes32_field(payload, "ciphertextHash")?;

        let inserted = self
            .store
            .insert_control_instruction(
                event.contract,
                instruction_id,
                nonce,
                &target_members,
                expiry,
                salt,
                &ciphertext,
                ciphertext_hash,
                event.block_number,
                event.log_index,
                event.tx_hash,
            )
            .await?;

        let row_id = match inserted {
            Some(id) => id,
            None => {
                // Idempotent re-apply (WS replay, cold-start overlap).
                // The on-conflict clause skipped the insert; we still
                // want a notification fired so a downstream consumer
                // that crashed mid-fetch the first time around picks
                // up the row on its next reconnect. Look up the
                // existing row's id so the LISTEN payload carries a
                // stable cursor.
                lookup_control_instruction_id(self.store.pool(), event.contract, nonce).await?
            }
        };

        let payload = ControlNotifyEvent {
            cluster: event.contract,
            kind: "ControlInstructionBroadcast".to_string(),
            row_id,
            event_id,
            block_number: event.block_number,
            log_index: event.log_index,
        };
        let payload_json = serde_json::to_value(&payload)?;
        self.store.notify_control(&payload_json).await?;
        Ok(())
    }

    /// Insert a `ControlAck` row into the dedicated `control_acks`
    /// table and fire the `chain_indexer_control` notification.
    /// Mirrors `insert_control_instruction_from_event`. Spec §5.3 +
    /// §8.1. Idempotent under replay via the unique
    /// `(cluster, job_id, seq) WHERE removed=false` index.
    async fn insert_control_ack_from_event(
        &self,
        event: &DecodedEvent,
        event_id: i64,
    ) -> anyhow::Result<()> {
        let payload = event
            .decoded
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ControlAck event has no decoded payload"))?;

        let instruction_id = parse_bytes32_field(payload, "instructionId")?;
        let job_id = parse_bytes32_field(payload, "jobId")?;
        let member_id = parse_bytes32_field(payload, "memberId")?;
        let status = parse_uint8_field(payload, "status")?;
        let seq = parse_uint64_string_field(payload, "seq")?;
        // logPointer is bytes32 zero on intermediate ACCEPTED acks
        // (spec §8.1 — terminal acks carry the sha256). Treat the
        // all-zero value as "not set" so a downstream NULL check
        // doesn't have to special-case it.
        let log_pointer_raw = parse_bytes32_field(payload, "logPointer")?;
        let log_pointer = if log_pointer_raw == [0u8; 32] {
            None
        } else {
            Some(log_pointer_raw)
        };
        let summary = parse_bytes_field(payload, "summary")?;
        let summary_opt: Option<&[u8]> = if summary.is_empty() {
            None
        } else {
            Some(summary.as_slice())
        };

        let inserted = self
            .store
            .insert_control_ack(
                event.contract,
                instruction_id,
                job_id,
                member_id,
                status,
                seq,
                log_pointer,
                summary_opt,
                event.block_number,
                event.log_index,
                event.tx_hash,
            )
            .await?;

        let row_id = match inserted {
            Some(id) => id,
            None => lookup_control_ack_id(self.store.pool(), event.contract, job_id, seq).await?,
        };

        let payload = ControlNotifyEvent {
            cluster: event.contract,
            kind: "ControlAck".to_string(),
            row_id,
            event_id,
            block_number: event.block_number,
            log_index: event.log_index,
        };
        let payload_json = serde_json::to_value(&payload)?;
        self.store.notify_control(&payload_json).await?;
        Ok(())
    }

    /// Decode a `ClusterDeployed` event and add the freshly-minted
    /// diamond to `watched_contracts`. The factory event was already
    /// recorded (its `event.contract` is the factory itself); this
    /// extra step bootstraps the per-diamond watcher without waiting
    /// for an operator to add the address by hand or for the
    /// `listClusters()` cold-start path to re-discover it on restart.
    async fn register_deployed_diamond(&self, event: &DecodedEvent) -> anyhow::Result<()> {
        let diamond = parse_cluster_deployed_diamond(event.decoded.as_ref())?;
        // `add_watched_contract` is idempotent (`ON CONFLICT DO
        // NOTHING`) so re-application via WS replay / cold-start is
        // safe. Anchor `from_block` to the deploy block so backfill
        // doesn't waste scans on pre-deploy ranges.
        self.store
            .add_watched_contract(
                diamond,
                "cluster_diamond",
                Some(event.contract),
                event.block_number,
            )
            .await?;
        tracing::info!(
            chain_id = self.chain_id,
            factory = %hex::encode(event.contract),
            diamond = %hex::encode(diamond),
            from_block = event.block_number,
            "auto-registered ClusterDeployed diamond"
        );
        Ok(())
    }

    /// Recover and persist the raw TDX quote bytes referenced by a
    /// `MemberWgPubkeySetV2` event. Fetches the originating tx via
    /// `eth_getTransactionByHash`, scans the input for the
    /// `setMemberWgPubkeyAttested` selector, ABI-decodes the call, and
    /// upserts a `cluster_member_quotes` row.
    ///
    /// Returns early with `Ok(())` when:
    ///   - a row already exists for the `(member_id, quote_hash)`
    ///     content-address (re-observation under WS replay), or
    ///   - the cluster recovers the bytes but `keccak256(bytes) !=
    ///     quoteHash` (logs at error, no row written).
    ///
    /// The on-chain V2 surface already enforces the hash commitment, so
    /// a mismatch here would indicate either a buggy tx-search match or
    /// an out-of-sync provider response. Either way, refusing to write
    /// the row preserves the table's invariant that
    /// `keccak256(quote_bytes) == quote_hash` for every persisted row.
    async fn recover_attested_quote_from_event<P>(
        &self,
        provider: &P,
        event: &DecodedEvent,
    ) -> anyhow::Result<()>
    where
        P: Provider,
    {
        let payload = event
            .decoded
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MemberWgPubkeySetV2 event has no decoded payload"))?;

        let member_id = parse_bytes32_field(payload, "memberId")?;
        let wg_pubkey = parse_bytes32_field(payload, "wgPubkey")?;
        let quote_hash = parse_bytes32_field(payload, "quoteHash")?;

        // Idempotent short-circuit: if the content-addressed row already
        // exists we don't need to refetch the tx. `eth_getTransactionByHash`
        // is the expensive step in this branch (RPC round-trip, full tx
        // body fetch), so the pre-check pays for itself on every replay
        // or backfill overlap.
        if self
            .store
            .member_quote_by_hash(event.contract, member_id, quote_hash)
            .await?
            .is_some()
        {
            tracing::trace!(
                chain_id = self.chain_id,
                cluster = %hex::encode(event.contract),
                member = %hex::encode(member_id),
                quote_hash = %hex::encode(quote_hash),
                "MemberWgPubkeySetV2 quote already persisted; skipping recovery"
            );
            return Ok(());
        }

        let tx_hash_b256 = B256::from(event.tx_hash);
        let tx = provider
            .get_transaction_by_hash(tx_hash_b256)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "eth_getTransactionByHash returned None for {}",
                    hex::encode(event.tx_hash)
                )
            })?;
        let tx_input = tx.input();

        let quote_bytes =
            crate::quote_recovery::extract_attested_quote_bytes(tx_input, &member_id, &quote_hash)?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "setMemberWgPubkeyAttested selector not found in tx {} calldata \
                 (or all decode candidates mismatched the event bindings)",
                        hex::encode(event.tx_hash)
                    )
                })?;

        // Defense in depth — the contract already enforces this, but a
        // buggy scan-and-decode that picked up the wrong slice would
        // otherwise pollute the table with bytes that disagree with the
        // on-chain commitment.
        if let Err(actual) =
            crate::quote_recovery::verify_quote_hash_commitment(&quote_bytes, &quote_hash)
        {
            anyhow::bail!(
                "recovered quote bytes disagree with on-chain quoteHash for member {}: \
                 expected {} got {}",
                hex::encode(member_id),
                hex::encode(quote_hash),
                hex::encode(actual)
            );
        }

        let inserted = self
            .store
            .upsert_member_quote(
                event.contract,
                member_id,
                quote_hash,
                wg_pubkey,
                &quote_bytes,
                event.block_number,
                event.block_hash,
                event.log_index,
                event.tx_hash,
            )
            .await?;

        if inserted {
            tracing::info!(
                chain_id = self.chain_id,
                cluster = %hex::encode(event.contract),
                member = %hex::encode(member_id),
                quote_hash = %hex::encode(quote_hash),
                quote_len = quote_bytes.len(),
                block = event.block_number,
                "persisted MemberWgPubkeySetV2 quote bytes"
            );
        }

        // R2 mirror is write-on-write — fire-and-forget after the
        // authoritative Postgres row is in place. A failed upload is
        // logged at `warn` but doesn't abort the ingest path: R2 is
        // availability-only (design §9.2), the row stays correct,
        // and a future backfill sweep can re-run the upload. Even
        // when the DB upsert returned `inserted=false` (we're
        // re-observing a known quote), we still call `put_quote` —
        // the mirror's idempotence means a re-PUT to the same
        // content-addressed key is a no-op, and a previous run that
        // wrote the DB row but crashed before the upload eventually
        // converges this way.
        if let Some(mirror) = &self.quote_r2_mirror {
            match mirror
                .put_quote(event.contract, member_id, quote_hash, &quote_bytes)
                .await
            {
                Ok(Some(uri)) => {
                    if let Err(e) = self
                        .store
                        .set_member_quote_r2_uri(event.contract, member_id, quote_hash, &uri)
                        .await
                    {
                        tracing::warn!(
                            chain_id = self.chain_id,
                            cluster = %hex::encode(event.contract),
                            member = %hex::encode(member_id),
                            quote_hash = %hex::encode(quote_hash),
                            error = %e,
                            "R2 upload succeeded but persisting r2_uri failed; backfill on next sweep"
                        );
                    } else {
                        tracing::debug!(
                            chain_id = self.chain_id,
                            cluster = %hex::encode(event.contract),
                            member = %hex::encode(member_id),
                            quote_hash = %hex::encode(quote_hash),
                            r2_uri = %uri,
                            "R2 mirror upload complete"
                        );
                    }
                }
                Ok(None) => {
                    // Mirror declined to upload (disabled or skipped);
                    // nothing to record.
                }
                Err(e) => {
                    tracing::warn!(
                        chain_id = self.chain_id,
                        cluster = %hex::encode(event.contract),
                        member = %hex::encode(member_id),
                        quote_hash = %hex::encode(quote_hash),
                        error = %e,
                        "R2 mirror upload failed; backfill on next sweep"
                    );
                }
            }
        }
        Ok(())
    }

    /// Look up the existing `events.id` for an event we tried to
    /// insert but hit the dedup index. Same composite key as the
    /// unique index → single B-tree probe.
    async fn fetch_event_id(&self, ev: &DecodedEvent) -> anyhow::Result<i64> {
        let block_number_i64 = i64::try_from(ev.block_number)
            .map_err(|_| anyhow::anyhow!("block number {} overflows i64", ev.block_number))?;
        let id: i64 = sqlx::query_scalar(
            "SELECT id FROM events \
             WHERE chain_id = $1 AND contract = $2 \
               AND block_hash = $3 AND log_index = $4",
        )
        .bind(ev.chain_id)
        .bind(&ev.contract[..])
        .bind(&ev.block_hash[..])
        .bind(ev.log_index)
        .bind(block_number_i64) // unused but keeps query parameter shape stable for future reuse
        .fetch_one(self.store.pool())
        .await
        .map_err(|e| anyhow::anyhow!("re-fetch event id: {e}"))?;
        Ok(id)
    }

    /// Snapshot of every decoder's topic0 — used as the WS log filter
    /// and the chunked-backfill filter.
    fn topic0_set(&self) -> Vec<B256> {
        self.decoders.keys().map(|k| B256::from(*k)).collect()
    }
}

/// Internal error split: transient errors trigger reconnect+backoff;
/// fatal errors bubble out of `run()` so the supervisor restarts the
/// process (cold-start from scratch).
#[derive(Debug)]
enum IngestError {
    Transient(anyhow::Error),
    Fatal(anyhow::Error),
}

impl From<anyhow::Error> for IngestError {
    fn from(e: anyhow::Error) -> Self {
        Self::Transient(e)
    }
}

/// Builder for [`Ingestor`]. Required fields: `chain_id`,
/// `rpc_http_url`, `rpc_ws_url`, `store`, `finality_depth`. Decoders
/// and views default to empty (an empty pipeline still drains the
/// chain into the raw `events` table — useful as a smoke test).
#[derive(Default)]
pub struct IngestorBuilder {
    chain_id: Option<i32>,
    rpc_http_url: Option<String>,
    rpc_ws_url: Option<String>,
    store: Option<EventStore>,
    decoders: HashMap<[u8; 32], Box<dyn Decoder>>,
    views: Vec<Box<dyn View>>,
    finality_depth: Option<u64>,
    notify_tx: Option<mpsc::Sender<NotifyEvent>>,
    quote_r2_mirror: Option<Arc<dyn crate::r2_mirror::R2QuoteMirror>>,
}

impl IngestorBuilder {
    pub fn chain_id(mut self, chain_id: i32) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    pub fn rpc_http_url(mut self, url: impl Into<String>) -> Self {
        self.rpc_http_url = Some(url.into());
        self
    }

    pub fn rpc_ws_url(mut self, url: impl Into<String>) -> Self {
        self.rpc_ws_url = Some(url.into());
        self
    }

    pub fn store(mut self, store: EventStore) -> Self {
        self.store = Some(store);
        self
    }

    /// Add a decoder. Re-adding the same `topic0` overwrites the
    /// previous entry — last-write-wins, useful for tests but the
    /// production wiring in the bin crate registers each decoder
    /// exactly once.
    pub fn decoder(mut self, decoder: Box<dyn Decoder>) -> Self {
        self.decoders.insert(decoder.topic0(), decoder);
        self
    }

    pub fn view(mut self, view: Box<dyn View>) -> Self {
        self.views.push(view);
        self
    }

    pub fn finality_depth(mut self, depth: u64) -> Self {
        self.finality_depth = Some(depth);
        self
    }

    /// Optional in-process notification channel — Agent 6's SSE
    /// handler subscribes here to skip the `pg_notify` round-trip.
    pub fn notify_channel(mut self, tx: mpsc::Sender<NotifyEvent>) -> Self {
        self.notify_tx = Some(tx);
        self
    }

    /// Plug in an R2 mirror for `MemberWgPubkeySetV2` quote bytes
    /// (unified-network-design §9.2). The ingestor calls
    /// [`crate::r2_mirror::R2QuoteMirror::put_quote`] after every
    /// successful Postgres upsert. A failed upload is logged at
    /// `warn` and does not fail the DB write — R2 is availability-
    /// only, not authoritative, so the row stays correct and the
    /// periodic backfill (see `cluster_member_quotes_pending_r2_idx`)
    /// retries on the next sweep.
    pub fn quote_r2_mirror(mut self, mirror: Arc<dyn crate::r2_mirror::R2QuoteMirror>) -> Self {
        self.quote_r2_mirror = Some(mirror);
        self
    }

    pub fn build(self) -> anyhow::Result<Ingestor> {
        let chain_id = self
            .chain_id
            .ok_or_else(|| anyhow::anyhow!("IngestorBuilder: chain_id required"))?;
        let rpc_http_url = self
            .rpc_http_url
            .ok_or_else(|| anyhow::anyhow!("IngestorBuilder: rpc_http_url required"))?;
        let rpc_ws_url = self
            .rpc_ws_url
            .ok_or_else(|| anyhow::anyhow!("IngestorBuilder: rpc_ws_url required"))?;
        let store = self
            .store
            .ok_or_else(|| anyhow::anyhow!("IngestorBuilder: store required"))?;
        let finality_depth = self
            .finality_depth
            .ok_or_else(|| anyhow::anyhow!("IngestorBuilder: finality_depth required"))?;

        if store.chain_id() != chain_id {
            anyhow::bail!(
                "store.chain_id() == {} but builder configured chain_id == {}",
                store.chain_id(),
                chain_id
            );
        }

        Ok(Ingestor {
            chain_id,
            rpc_http_url,
            rpc_ws_url,
            store,
            decoders: Arc::new(self.decoders),
            views: Arc::new(self.views),
            finality_depth,
            notify_tx: self.notify_tx,
            quote_r2_mirror: self.quote_r2_mirror,
        })
    }
}

/// Pure parser for the `diamond` field on a decoded ClusterDeployed
/// event. Split out so the v0.1.4 fix (auto-register diamond from the
/// factory event) can be unit-tested without spinning up an EventStore
/// or a real Postgres pool — the actual `add_watched_contract` call is
/// just an idempotent `ON CONFLICT DO NOTHING` insert downstream.
pub fn parse_cluster_deployed_diamond(
    decoded: Option<&serde_json::Value>,
) -> anyhow::Result<[u8; 20]> {
    let payload =
        decoded.ok_or_else(|| anyhow::anyhow!("ClusterDeployed has no decoded payload"))?;
    let diamond_str = payload
        .get("diamond")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("ClusterDeployed payload missing `diamond` field"))?;
    let raw = diamond_str.strip_prefix("0x").unwrap_or(diamond_str);
    let bytes =
        hex::decode(raw).map_err(|e| anyhow::anyhow!("ClusterDeployed.diamond not hex: {e}"))?;
    bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "ClusterDeployed.diamond expected 20 bytes, got {}",
            bytes.len()
        )
    })
}

// ---------------------------------------------------------------------------
// Field parsers for control-plane events. The decoded JSON shape is
// produced by `teesql-abi::cluster_diamond` (Track A4 decoders); the
// parsers below are kept pure (operate on `&serde_json::Value`) so
// unit tests can exercise every error branch without a Postgres
// pool. The corresponding insert paths in `Ingestor` are thin shims
// that route the parsed values to `EventStore::insert_control_*`.
// ---------------------------------------------------------------------------

/// `0x`-prefixed 64-hex-char string → `[u8; 32]`. Used for
/// `instructionId`, `clusterId`, `salt`, `ciphertextHash`, `jobId`,
/// `memberId`, `logPointer` — every bytes32 field on the control
/// events. Accepts mixed-case + missing-prefix shapes for parity
/// with `parse_cluster_deployed_diamond`'s flexibility.
pub fn parse_bytes32_field(payload: &serde_json::Value, field: &str) -> anyhow::Result<[u8; 32]> {
    let s = payload
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("payload missing `{field}` (expected hex string)"))?;
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(raw).map_err(|e| anyhow::anyhow!("`{field}` not hex: {e}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("`{field}` expected 32 bytes, got {}", bytes.len()))
}

/// Variable-length `bytes` field (`ciphertext`, `summary`) → owned
/// `Vec<u8>`. Empty `"0x"` returns an empty vec rather than failing;
/// the spec allows `summary` to be empty on intermediate acks.
pub fn parse_bytes_field(payload: &serde_json::Value, field: &str) -> anyhow::Result<Vec<u8>> {
    let s = payload
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("payload missing `{field}` (expected hex string)"))?;
    let raw = s.strip_prefix("0x").unwrap_or(s);
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(raw).map_err(|e| anyhow::anyhow!("`{field}` not hex: {e}"))
}

/// `uint64`-as-decimal-string → `u64`. Mirrors the
/// `uint64_to_json` encoder convention (decimal string for parity
/// with `uint256`). Rejects negative or non-decimal shapes loudly
/// so a future encoder drift surfaces here rather than silently
/// truncating in `i64::try_from`.
pub fn parse_uint64_string_field(payload: &serde_json::Value, field: &str) -> anyhow::Result<u64> {
    let s = payload
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("payload missing `{field}` (expected decimal string)"))?;
    s.parse::<u64>()
        .map_err(|e| anyhow::anyhow!("`{field}` not a u64 decimal: {e}"))
}

/// `uint8` → `u8`. Status enums fit in JSON Number land (max 255 is
/// well inside f64), but we still bound-check defensively because
/// a non-control payload reaching this parser would be a regression
/// in the dispatch above.
pub fn parse_uint8_field(payload: &serde_json::Value, field: &str) -> anyhow::Result<u8> {
    let v = payload
        .get(field)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("payload missing `{field}` (expected JSON number)"))?;
    u8::try_from(v).map_err(|_| anyhow::anyhow!("`{field}` value {v} out of u8 range"))
}

/// `bytes32[]` → owned `Vec<[u8; 32]>`. Used for
/// `ControlInstructionBroadcast.targetMembers`. Empty array =
/// "broadcast to all" per spec §5.6; an empty input still returns
/// `Ok(vec![])` so the caller doesn't have to special-case the wire
/// shape at the boundary.
pub fn parse_bytes32_array_field(
    payload: &serde_json::Value,
    field: &str,
) -> anyhow::Result<Vec<[u8; 32]>> {
    let arr = payload
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("payload missing `{field}` (expected JSON array)"))?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let s = item
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("`{field}[{i}]` expected hex string, got {item:?}"))?;
        let raw = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(raw).map_err(|e| anyhow::anyhow!("`{field}[{i}]` not hex: {e}"))?;
        let arr32: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("`{field}[{i}]` expected 32 bytes, got {}", bytes.len())
        })?;
        out.push(arr32);
    }
    Ok(out)
}

/// Look up an existing `control_instructions.id` for an event we
/// tried to insert but hit the dedup index (idempotent replay path).
/// Filters on `removed=false` to match the partial unique index, so
/// a reorg-rolled-back row never re-surfaces as a "live" id.
async fn lookup_control_instruction_id(
    pool: &sqlx::PgPool,
    cluster: [u8; 20],
    nonce: u64,
) -> anyhow::Result<i64> {
    let nonce_i64 = i64::try_from(nonce)
        .map_err(|_| anyhow::anyhow!("nonce {nonce} overflows i64 in lookup"))?;
    let id: i64 = sqlx::query_scalar(
        "SELECT id FROM control_instructions \
         WHERE cluster = $1 AND nonce = $2 AND removed = false",
    )
    .bind(&cluster[..])
    .bind(nonce_i64)
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow::anyhow!("lookup_control_instruction_id: {e}"))?;
    Ok(id)
}

/// Look up an existing `control_acks.id` for an idempotent replay.
async fn lookup_control_ack_id(
    pool: &sqlx::PgPool,
    cluster: [u8; 20],
    job_id: [u8; 32],
    seq: u64,
) -> anyhow::Result<i64> {
    let seq_i64 =
        i64::try_from(seq).map_err(|_| anyhow::anyhow!("seq {seq} overflows i64 in lookup"))?;
    let id: i64 = sqlx::query_scalar(
        "SELECT id FROM control_acks \
         WHERE cluster = $1 AND job_id = $2 AND seq = $3 AND removed = false",
    )
    .bind(&cluster[..])
    .bind(&job_id[..])
    .bind(seq_i64)
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow::anyhow!("lookup_control_ack_id: {e}"))?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_missing_required_fields() {
        let err = Ingestor::builder().build().unwrap_err();
        assert!(err.to_string().contains("chain_id required"));
    }

    #[test]
    fn notify_event_serializes_round_trip() {
        let n = NotifyEvent {
            cluster: [0xab; 20],
            kind: "MemberRegistered".into(),
            event_id: 42,
            block_number: 1234,
            log_index: 7,
        };
        let s = serde_json::to_string(&n).unwrap();
        let back: NotifyEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.cluster, n.cluster);
        assert_eq!(back.kind, n.kind);
        assert_eq!(back.event_id, n.event_id);
        assert_eq!(back.block_number, n.block_number);
        assert_eq!(back.log_index, n.log_index);
    }

    /// `cluster` MUST land on the wire as a 0x-prefixed hex string,
    /// not a JSON byte array. The LISTEN consumer (`server::sse`'s
    /// listen_loop) expects this shape; the byte-array default would
    /// break re-hydration with `invalid type: sequence, expected a
    /// string`. Pin both directions in this test so any future
    /// regression to the default shape fails here.
    #[test]
    fn notify_event_cluster_serializes_as_hex_string() {
        let n = NotifyEvent {
            cluster: [0xab; 20],
            kind: "MemberRegistered".into(),
            event_id: 42,
            block_number: 1234,
            log_index: 7,
        };
        let v = serde_json::to_value(&n).unwrap();
        let cluster = v
            .get("cluster")
            .expect("cluster field present")
            .as_str()
            .expect("cluster serialized as string");
        assert_eq!(cluster, "0xabababababababababababababababababababab");

        // Round-trip from a JSON object literal (the shape pg_notify
        // payload consumers see) succeeds.
        let raw = r#"{"cluster":"0xabababababababababababababababababababab","kind":"MemberRegistered","event_id":42,"block_number":1234,"log_index":7}"#;
        let back: NotifyEvent = serde_json::from_str(raw).unwrap();
        assert_eq!(back.cluster, [0xab; 20]);
    }

    // ── B6: register_deployed_diamond extraction (v0.1.4 fix) ───────
    //
    // The full register_deployed_diamond fn writes to watched_contracts
    // (Postgres) — testing that arm requires a real DB. The decoded-
    // payload extraction is the load-bearing v0.1.4 fix though: before
    // it landed, ClusterDeployed events came in with the diamond
    // address but auto-registration didn't fire because the parser
    // wasn't there. These tests pin the extraction surface so a future
    // refactor of the event decoder's JSON shape trips the test instead
    // of silently breaking auto-registration.
    //
    // Per memory `project_chain_indexer_live_20260503.md`, this code
    // path drove the chain-indexer's storage backend cutover from
    // platform `fbdacec943` to platform-3 `653cccb310` on 2026-05-04.

    #[test]
    fn parse_cluster_deployed_diamond_extracts_lowercase_hex() {
        // Canonical happy path: ClusterDeployed event's `decoded`
        // payload carries `diamond` as a 0x-prefixed lowercase hex
        // address. Parser must recover the 20-byte address.
        let decoded = serde_json::json!({
            "diamond": "0xe2a0233b75beb63f9c377de4ed4ac5965b2eacb9",
            "deployer": "0x60b174704adaf2b0bf87b426b364d6ebd81818e1"
        });
        let addr = parse_cluster_deployed_diamond(Some(&decoded)).unwrap();
        assert_eq!(
            hex::encode(addr),
            "e2a0233b75beb63f9c377de4ed4ac5965b2eacb9"
        );
    }

    #[test]
    fn parse_cluster_deployed_diamond_accepts_uppercase_hex() {
        // Some encoders mixed-case the address. Pin the parser's
        // case-insensitivity so a future ABI/decoder bump that flips
        // case doesn't surface as "addr not 20 bytes".
        let decoded = serde_json::json!({
            "diamond": "0xE2A0233B75BEB63F9C377DE4ED4AC5965B2EACB9"
        });
        let addr = parse_cluster_deployed_diamond(Some(&decoded)).unwrap();
        assert_eq!(
            hex::encode(addr),
            "e2a0233b75beb63f9c377de4ed4ac5965b2eacb9"
        );
    }

    #[test]
    fn parse_cluster_deployed_diamond_accepts_address_without_0x_prefix() {
        let decoded = serde_json::json!({
            "diamond": "e2a0233b75beb63f9c377de4ed4ac5965b2eacb9"
        });
        let addr = parse_cluster_deployed_diamond(Some(&decoded)).unwrap();
        assert_eq!(addr.len(), 20);
        assert_eq!(addr[0], 0xe2);
    }

    #[test]
    fn parse_cluster_deployed_diamond_rejects_missing_payload() {
        let err = parse_cluster_deployed_diamond(None).unwrap_err();
        assert!(err.to_string().contains("no decoded payload"), "msg: {err}");
    }

    #[test]
    fn parse_cluster_deployed_diamond_rejects_missing_diamond_field() {
        // The decoder ran but the contract emitted no diamond — would
        // be a contract bug (or a wrong topic0 collision). Surface it
        // loudly so the operator can investigate rather than swallowing
        // and silently skipping registration.
        let decoded = serde_json::json!({
            "deployer": "0xdeadbeef",
        });
        let err = parse_cluster_deployed_diamond(Some(&decoded)).unwrap_err();
        assert!(err.to_string().contains("missing `diamond`"), "msg: {err}");
    }

    #[test]
    fn parse_cluster_deployed_diamond_rejects_non_string_diamond_field() {
        let decoded = serde_json::json!({
            "diamond": 12345
        });
        let err = parse_cluster_deployed_diamond(Some(&decoded)).unwrap_err();
        assert!(err.to_string().contains("missing `diamond`"), "msg: {err}");
    }

    #[test]
    fn parse_cluster_deployed_diamond_rejects_non_hex_diamond() {
        let decoded = serde_json::json!({
            "diamond": "0xnot-actually-hex-at-all"
        });
        let err = parse_cluster_deployed_diamond(Some(&decoded)).unwrap_err();
        assert!(err.to_string().contains("not hex"), "msg: {err}");
    }

    #[test]
    fn parse_cluster_deployed_diamond_rejects_short_address() {
        // 19 bytes (38 hex) — close but not an Ethereum address.
        let decoded = serde_json::json!({
            "diamond": "0xe2a0233b75beb63f9c377de4ed4ac5965b2eac"
        });
        let err = parse_cluster_deployed_diamond(Some(&decoded)).unwrap_err();
        assert!(err.to_string().contains("expected 20 bytes"), "msg: {err}");
    }

    #[test]
    fn parse_cluster_deployed_diamond_rejects_long_address() {
        // 21 bytes (42 hex) — too many.
        let decoded = serde_json::json!({
            "diamond": "0xe2a0233b75beb63f9c377de4ed4ac5965b2eacb9aa"
        });
        let err = parse_cluster_deployed_diamond(Some(&decoded)).unwrap_err();
        assert!(err.to_string().contains("expected 20 bytes"), "msg: {err}");
    }

    #[test]
    fn parse_cluster_deployed_diamond_rejects_zero_address_payload() {
        // Zero address is parseable but a real ClusterDeployed event
        // would never emit it — this is just a coverage assertion that
        // the parser doesn't pre-filter on content. (Caller decides
        // whether to register a zero-address watcher; keeping that
        // policy out of the parser is the v0.1.4 design.)
        let decoded = serde_json::json!({
            "diamond": "0x0000000000000000000000000000000000000000"
        });
        let addr = parse_cluster_deployed_diamond(Some(&decoded)).unwrap();
        assert_eq!(addr, [0u8; 20]);
    }

    // ── Track A4: control-plane payload parsers ───────────────────────
    //
    // These pin the wire shape produced by `teesql-abi`'s
    // ControlInstructionBroadcastDecoder + ControlAckDecoder so any
    // future encoder drift trips here rather than silently leaving
    // the dedicated control_instructions / control_acks tables empty.

    fn full_broadcast_payload() -> serde_json::Value {
        // Mirrors the JSON that
        // `teesql-abi::cluster_diamond::ControlInstructionBroadcastDecoder`
        // emits — uint64 fields land as decimal strings, bytes32
        // arrays as 0x-hex strings inside an array.
        serde_json::json!({
            "instructionId":  "0x1111111111111111111111111111111111111111111111111111111111111111",
            "clusterId":      "0x2222222222222222222222222222222222222222222222222222222222222222",
            "nonce":          "5",
            "targetMembers":  [
                "0x3333333333333333333333333333333333333333333333333333333333333333",
                "0x4444444444444444444444444444444444444444444444444444444444444444",
            ],
            "expiry":         "1717592400",
            "salt":           "0x5555555555555555555555555555555555555555555555555555555555555555",
            "ciphertextHash": "0x6666666666666666666666666666666666666666666666666666666666666666",
            "ciphertext":     "0xdeadbeef",
        })
    }

    fn full_ack_payload() -> serde_json::Value {
        serde_json::json!({
            "instructionId": "0x7777777777777777777777777777777777777777777777777777777777777777",
            "jobId":         "0x8888888888888888888888888888888888888888888888888888888888888888",
            "memberId":      "0x9999999999999999999999999999999999999999999999999999999999999999",
            "status":        3,
            "seq":           "42",
            "logPointer":    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "summary":       "0xcafe",
        })
    }

    #[test]
    fn parse_bytes32_field_round_trips_lowercase() {
        let p = full_broadcast_payload();
        let id = parse_bytes32_field(&p, "instructionId").unwrap();
        assert_eq!(id, [0x11; 32]);
    }

    #[test]
    fn parse_bytes32_field_accepts_uppercase_and_no_prefix() {
        let p = serde_json::json!({"x": "AABBCCDDEEFF112233445566778899AABBCCDDEEFF112233445566778899AABB"});
        // 64 hex chars = 32 bytes; case-insensitive + missing prefix.
        let v = parse_bytes32_field(&p, "x").unwrap();
        assert_eq!(v[0], 0xAA);
        assert_eq!(v[31], 0xBB);
    }

    #[test]
    fn parse_bytes32_field_rejects_missing() {
        let p = serde_json::json!({"y": "0x"});
        let err = parse_bytes32_field(&p, "x").unwrap_err();
        assert!(err.to_string().contains("missing `x`"));
    }

    #[test]
    fn parse_bytes32_field_rejects_wrong_length() {
        let p = serde_json::json!({"x": "0x1122"});
        let err = parse_bytes32_field(&p, "x").unwrap_err();
        assert!(err.to_string().contains("expected 32 bytes"));
    }

    #[test]
    fn parse_uint64_string_field_happy_path() {
        let p = full_broadcast_payload();
        assert_eq!(parse_uint64_string_field(&p, "nonce").unwrap(), 5);
        assert_eq!(
            parse_uint64_string_field(&p, "expiry").unwrap(),
            1_717_592_400
        );
    }

    #[test]
    fn parse_uint64_string_field_max_value() {
        // u64::MAX serialised as decimal string round-trips. Catches a
        // future regression where someone "optimised" the encoder to
        // emit a JSON number and silently round-tripped through f64.
        let p = serde_json::json!({"x": "18446744073709551615"});
        assert_eq!(parse_uint64_string_field(&p, "x").unwrap(), u64::MAX);
    }

    #[test]
    fn parse_uint64_string_field_rejects_non_decimal() {
        let p = serde_json::json!({"x": "0xdead"});
        let err = parse_uint64_string_field(&p, "x").unwrap_err();
        assert!(err.to_string().contains("not a u64 decimal"));
    }

    #[test]
    fn parse_uint8_field_in_range() {
        let p = full_ack_payload();
        assert_eq!(parse_uint8_field(&p, "status").unwrap(), 3);
    }

    #[test]
    fn parse_uint8_field_rejects_overflow() {
        let p = serde_json::json!({"status": 256});
        let err = parse_uint8_field(&p, "status").unwrap_err();
        assert!(err.to_string().contains("out of u8 range"));
    }

    #[test]
    fn parse_bytes_field_decodes_hex_payload() {
        let p = full_ack_payload();
        let summary = parse_bytes_field(&p, "summary").unwrap();
        assert_eq!(summary, vec![0xca, 0xfe]);
    }

    #[test]
    fn parse_bytes_field_empty_zero_x_returns_empty_vec() {
        // `summary` on intermediate ACCEPTED acks is "0x" — empty
        // bytes. The parser must NOT error; the caller maps an empty
        // vec to `NULL` so the column reflects "not set" cleanly.
        let p = serde_json::json!({"summary": "0x"});
        let summary = parse_bytes_field(&p, "summary").unwrap();
        assert!(summary.is_empty());
    }

    #[test]
    fn parse_bytes32_array_field_recovers_each_element() {
        let p = full_broadcast_payload();
        let v = parse_bytes32_array_field(&p, "targetMembers").unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], [0x33; 32]);
        assert_eq!(v[1], [0x44; 32]);
    }

    #[test]
    fn parse_bytes32_array_field_empty_array_is_broadcast_signal() {
        // Spec §5.6: `targetMembers = []` means "deliver to all
        // members." The parser must preserve emptiness rather than
        // collapsing it into an error.
        let p = serde_json::json!({"x": []});
        let v = parse_bytes32_array_field(&p, "x").unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn parse_bytes32_array_field_rejects_non_string_element() {
        let p = serde_json::json!({"x": [123]});
        let err = parse_bytes32_array_field(&p, "x").unwrap_err();
        assert!(err.to_string().contains("expected hex string"));
    }

    #[test]
    fn parse_bytes32_array_field_rejects_short_element() {
        let p = serde_json::json!({"x": ["0x11"]});
        let err = parse_bytes32_array_field(&p, "x").unwrap_err();
        assert!(err.to_string().contains("expected 32 bytes"));
    }

    /// `ControlNotifyEvent` MUST land on the wire with `cluster` as a
    /// 0x-prefixed hex string — the LISTEN consumer path (Track D3)
    /// will deserialize directly back into this shape, so the byte-
    /// array default would silently break round-trip just like it
    /// did for the generic `NotifyEvent`.
    #[test]
    fn control_notify_event_round_trips_cluster_hex() {
        let n = ControlNotifyEvent {
            cluster: [0xab; 20],
            kind: "ControlInstructionBroadcast".into(),
            row_id: 1,
            event_id: 99,
            block_number: 12345,
            log_index: 2,
        };
        let v = serde_json::to_value(&n).unwrap();
        assert_eq!(
            v.get("cluster").unwrap().as_str().unwrap(),
            "0xabababababababababababababababababababab"
        );
        let raw = r#"{"cluster":"0xabababababababababababababababababababab","kind":"ControlAck","row_id":7,"event_id":42,"block_number":1,"log_index":0}"#;
        let back: ControlNotifyEvent = serde_json::from_str(raw).unwrap();
        assert_eq!(back.cluster, [0xab; 20]);
        assert_eq!(back.kind, "ControlAck");
        assert_eq!(back.row_id, 7);
    }
}
