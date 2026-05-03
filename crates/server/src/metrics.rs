//! Prometheus-text counters + gauges for `/v1/metrics`.
//!
//! Hand-rolled because we already have `tracing` for structured
//! logging and the surface is small enough that a full
//! `prometheus` / `metrics-exporter-prometheus` dep is overkill.
//! Every counter is a `u64` behind a single `AtomicU64`, hot-path
//! mutation is one `fetch_add`. The render path serializes the
//! snapshot into the Prometheus text format the dashboard scraper
//! expects.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
pub struct Metrics {
    // ---- counters ----
    pub events_ingested: AtomicU64,
    pub events_deduped: AtomicU64,
    pub sse_connections_opened: AtomicU64,
    pub sse_connections_closed: AtomicU64,
    pub http_requests: AtomicU64,
    pub signer_sign_calls: AtomicU64,
    pub fresh_quote_calls: AtomicU64,
    pub rpc_reorgs: AtomicU64,

    // ---- gauges ----
    pub head_block: AtomicU64,
    pub finalized_block: AtomicU64,
    /// Wall-clock seconds since the most recent event was ingested.
    /// Bumped to 0 by the ingest worker on every insert; the
    /// `/metrics` render side reads "now" against the saved
    /// epoch-seconds (kept negative-able for "no events yet" case).
    pub last_event_ts: AtomicI64,
    pub sse_connections_active: AtomicI64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn inc_events_ingested(&self) {
        self.events_ingested.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_events_deduped(&self) {
        self.events_deduped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_http_requests(&self) {
        self.http_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_signer_sign_calls(&self) {
        self.signer_sign_calls.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fresh_quote_calls(&self) {
        self.fresh_quote_calls.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rpc_reorgs(&self) {
        self.rpc_reorgs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_connection_opened(&self) {
        self.sse_connections_opened.fetch_add(1, Ordering::Relaxed);
        self.sse_connections_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sse_connection_closed(&self) {
        self.sse_connections_closed.fetch_add(1, Ordering::Relaxed);
        self.sse_connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn set_head_block(&self, block: u64) {
        self.head_block.store(block, Ordering::Relaxed);
    }

    pub fn set_finalized_block(&self, block: u64) {
        self.finalized_block.store(block, Ordering::Relaxed);
    }

    pub fn touch_last_event(&self) {
        let now = unix_now() as i64;
        self.last_event_ts.store(now, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let now = unix_now() as i64;
        let last_event_ts = self.last_event_ts.load(Ordering::Relaxed);
        let lag_seconds = if last_event_ts == 0 {
            -1
        } else {
            now - last_event_ts
        };
        let mut out = String::new();
        out.push_str(
            "# HELP chain_indexer_events_ingested_total Events written to the events table.\n",
        );
        out.push_str("# TYPE chain_indexer_events_ingested_total counter\n");
        out.push_str(&format!(
            "chain_indexer_events_ingested_total {}\n",
            self.events_ingested.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP chain_indexer_events_deduped_total Events skipped via the dedup unique index.\n");
        out.push_str("# TYPE chain_indexer_events_deduped_total counter\n");
        out.push_str(&format!(
            "chain_indexer_events_deduped_total {}\n",
            self.events_deduped.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP chain_indexer_sse_connections_opened_total Cumulative SSE connections accepted.\n",
        );
        out.push_str("# TYPE chain_indexer_sse_connections_opened_total counter\n");
        out.push_str(&format!(
            "chain_indexer_sse_connections_opened_total {}\n",
            self.sse_connections_opened.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP chain_indexer_sse_connections_closed_total Cumulative SSE connections terminated.\n",
        );
        out.push_str("# TYPE chain_indexer_sse_connections_closed_total counter\n");
        out.push_str(&format!(
            "chain_indexer_sse_connections_closed_total {}\n",
            self.sse_connections_closed.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP chain_indexer_http_requests_total HTTP requests served.\n");
        out.push_str("# TYPE chain_indexer_http_requests_total counter\n");
        out.push_str(&format!(
            "chain_indexer_http_requests_total {}\n",
            self.http_requests.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP chain_indexer_signer_sign_calls_total Number of envelope signs performed.\n",
        );
        out.push_str("# TYPE chain_indexer_signer_sign_calls_total counter\n");
        out.push_str(&format!(
            "chain_indexer_signer_sign_calls_total {}\n",
            self.signer_sign_calls.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP chain_indexer_fresh_quote_calls_total ?attest=full quote generations.\n",
        );
        out.push_str("# TYPE chain_indexer_fresh_quote_calls_total counter\n");
        out.push_str(&format!(
            "chain_indexer_fresh_quote_calls_total {}\n",
            self.fresh_quote_calls.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP chain_indexer_rpc_reorgs_total Reorg rollbacks performed.\n");
        out.push_str("# TYPE chain_indexer_rpc_reorgs_total counter\n");
        out.push_str(&format!(
            "chain_indexer_rpc_reorgs_total {}\n",
            self.rpc_reorgs.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP chain_indexer_head_block Latest block ingested.\n");
        out.push_str("# TYPE chain_indexer_head_block gauge\n");
        out.push_str(&format!(
            "chain_indexer_head_block {}\n",
            self.head_block.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP chain_indexer_finalized_block Latest finalized block.\n");
        out.push_str("# TYPE chain_indexer_finalized_block gauge\n");
        out.push_str(&format!(
            "chain_indexer_finalized_block {}\n",
            self.finalized_block.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP chain_indexer_lag_seconds Wall-clock seconds since the most recent ingest. -1 = no events yet.\n",
        );
        out.push_str("# TYPE chain_indexer_lag_seconds gauge\n");
        out.push_str(&format!("chain_indexer_lag_seconds {lag_seconds}\n"));
        out.push_str("# HELP chain_indexer_sse_connections_active Open SSE connections.\n");
        out.push_str("# TYPE chain_indexer_sse_connections_active gauge\n");
        out.push_str(&format!(
            "chain_indexer_sse_connections_active {}\n",
            self.sse_connections_active.load(Ordering::Relaxed)
        ));

        out
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
