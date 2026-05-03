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

use alloy::consensus::BlockHeader;
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NotifyEvent {
    /// Address that emitted the event. `[u8; 20]` rather than `Address`
    /// so consumers don't need alloy on the receive side.
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
        tracing::warn!(
            chain_id = self.chain_id,
            common_ancestor = common,
            head,
            removed_events = removed,
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
    async fn process_log<P>(&self, _provider: &P, log: Log) -> anyhow::Result<()>
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
        })
    }
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
}
