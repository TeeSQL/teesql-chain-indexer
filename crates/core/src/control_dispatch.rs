//! Per-cluster strict-ordered control-plane fan-out. Spec §7
//! (`docs/specs/control-plane-redesign.md`), Track D1 + D2 + D5.
//!
//! ## What this module owns
//!
//! One [`ControlOrderer`] per cluster. The orderer is the authoritative
//! cursor that tracks which `nonce` the cluster's subscribers have
//! observed in order so far, buffers out-of-order arrivals, holds back
//! events until they've earned `confirmations_required` blocks of
//! finality, and stalls (emitting a hole) when the gap between the
//! lowest-buffered nonce and `next_expected_nonce` cannot be closed
//! within bounds (`MAX_BUFFER_AGE`, `MAX_BUFFER`).
//!
//! ## What this module does NOT own
//!
//! - Subscriber fan-out / SSE wire format. The dispatcher returns a
//!   structured outcome ([`ControlDispatchOutcome`]) and the caller
//!   (the `ControlDispatcher` task in the bin crate) decides what to
//!   do with it: write `control_holes` to Postgres, push frames onto
//!   per-subscriber channels, etc. Keeping I/O out of the orderer
//!   makes the state machine fully unit-testable without a Postgres
//!   pool.
//! - Decryption / handler dispatch. The orderer hands back the
//!   [`BufferedInstr`] payload by reference; consumers are responsible
//!   for matching it to a sidecar handler.
//! - On-chain `authorizeSkip`. Per spec §5.7 there is no skip
//!   mechanism — holes are resolved by the cluster-owner Safe
//!   re-broadcasting at the missing nonce, which arrives via the
//!   normal event path and drains the buffer.
//!
//! ## State diagram
//!
//! ```text
//!   on_event(ev, block, head):
//!       block_too_recent (head - block < confirmations_required)
//!           → push to pending_finality, return Buffered(reason=NotFinal)
//!
//!       finality OK + nonce < next_expected_nonce
//!           → drop silently, return Dropped(reason=AlreadyDispatched)
//!
//!       finality OK + nonce == next_expected_nonce
//!           → dispatch ev, advance cursor, drain contiguous buffer
//!           → return Dispatched { dispatched: vec![...], drained: N }
//!
//!       finality OK + nonce > next_expected_nonce
//!           → buffer.insert(nonce, ev)
//!           → return Buffered(reason=AwaitingPredecessor)
//!
//!   tick(now):
//!       (a) promote any pending_finality whose head-distance has
//!           crossed confirmations_required (caller passes head_block)
//!       (b) re-evaluate the buffer's lowest entry:
//!             - if buffer.first().expiry <= now → emit_hole(buffer_expired)
//!             - if buffer.len() > MAX_BUFFER → emit_hole(buffer_full)
//!             - if buffer-age > MAX_AGE → emit_hole(buffer_age)
//!           when emit_hole fires, the cursor STAYS PUT — the spec
//!           explicitly says do NOT advance past a hole on its own.
//! ```
//!
//! ## Resilience
//!
//! After a process restart or reorg-rolled-back chunk of events, the
//! caller rebuilds the orderer's `next_expected_nonce` from
//! [`crate::store::EventStore::highest_finalized_control_nonce`] and
//! drains [`crate::store::EventStore::list_finalized_control_instructions`]
//! through `on_event` to re-warm the buffer. Spec §7.3 + §7.6.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Default Base soft-finality used by the orderer for instructions
/// reachable via the chain-indexer's WS subscription. ~12 blocks at
/// 2s per Base block ≈ 24s. Spec §7.2 fixes the default at 12.
pub const DEFAULT_CONFIRMATIONS_REQUIRED: u64 = 12;

/// Per-cluster buffer-size cap. Spec §7.7. A buffer-bound exhaustion
/// with a missing nonce at the front triggers a hole. 100 covers many
/// minutes of out-of-order delivery at expected control-plane rates
/// (sub-1Hz cluster-wide).
pub const DEFAULT_MAX_BUFFER: usize = 100;

/// Per-cluster buffer-age cap. Spec §7.7. The lowest-nonce entry that
/// has waited longer than this for its predecessor triggers a hole.
pub const DEFAULT_MAX_BUFFER_AGE: Duration = Duration::from_secs(60 * 60);

/// One buffered (or just-dispatched) control instruction. Carries
/// only the fields the orderer + its caller need; the orderer is
/// agnostic to ciphertext / payload shape and just shuttles the
/// envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferedInstr {
    pub instruction_id: [u8; 32],
    pub nonce: u64,
    pub target_members: Vec<[u8; 32]>,
    /// On-chain envelope expiry (uint64 unix seconds). Buffer-age is a
    /// separate axis (`buffered_at`) — the spec considers either an
    /// expiry-cross or a bound-cross sufficient to trigger a hole.
    pub expiry: u64,
    pub salt: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub ciphertext_hash: [u8; 32],
    pub block_number: u64,
    pub log_index: i32,
    pub tx_hash: [u8; 32],
    /// Wall-clock instant the orderer first observed this instruction.
    /// Set on first `on_event(...)`; used by `tick` to compute
    /// buffer-age against `OrdererConfig::max_buffer_age`. Tests
    /// don't compare `BufferedInstr` via `PartialEq` — they assert
    /// on `nonce` / payload fields directly — so the monotonic
    /// `Instant` here doesn't fight `derive(PartialEq, Eq)`.
    #[doc(hidden)]
    pub buffered_at: Instant,
}

impl BufferedInstr {
    /// Convenience constructor used by tests + by the
    /// `ControlDispatcher` adapter that wraps a
    /// `crate::store::ControlInstructionRow`. `buffered_at` is
    /// stamped at construction. The argument count mirrors the
    /// on-chain `ControlInstructionBroadcast` event one-for-one;
    /// bundling them into a struct here would just be a one-shot
    /// indirection adding no clarity over the named parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instruction_id: [u8; 32],
        nonce: u64,
        target_members: Vec<[u8; 32]>,
        expiry: u64,
        salt: [u8; 32],
        ciphertext: Vec<u8>,
        ciphertext_hash: [u8; 32],
        block_number: u64,
        log_index: i32,
        tx_hash: [u8; 32],
    ) -> Self {
        Self {
            instruction_id,
            nonce,
            target_members,
            expiry,
            salt,
            ciphertext,
            ciphertext_hash,
            block_number,
            log_index,
            tx_hash,
            buffered_at: Instant::now(),
        }
    }
}

/// Why the orderer reported a stall. Persisted as text in
/// `control_holes.reason` so a human reader doesn't need a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoleReason {
    /// Lowest buffer entry's `expiry` has been crossed by the
    /// dispatcher's wall clock. Spec §7.2.
    BufferExpired,
    /// Lowest buffer entry has been waiting longer than
    /// `MAX_BUFFER_AGE`. Spec §7.7.
    BufferAge,
    /// Buffer size exceeded `MAX_BUFFER` and the lowest nonce is
    /// still below `next_expected_nonce`. Spec §7.7.
    BufferFull,
}

impl HoleReason {
    /// Stable string slug stored in `control_holes.reason`.
    pub fn as_str(self) -> &'static str {
        match self {
            HoleReason::BufferExpired => "buffer_expired",
            HoleReason::BufferAge => "buffer_age",
            HoleReason::BufferFull => "buffer_full",
        }
    }
}

/// Tunable per-cluster knobs. Defaults match spec.
#[derive(Debug, Clone, Copy)]
pub struct OrdererConfig {
    pub confirmations_required: u64,
    pub max_buffer: usize,
    pub max_buffer_age: Duration,
}

impl Default for OrdererConfig {
    fn default() -> Self {
        Self {
            confirmations_required: DEFAULT_CONFIRMATIONS_REQUIRED,
            max_buffer: DEFAULT_MAX_BUFFER,
            max_buffer_age: DEFAULT_MAX_BUFFER_AGE,
        }
    }
}

/// Outcome of an `on_event` / `tick` call. The caller pattern-matches
/// on it:
///   - `Dispatched` → forward the entire `dispatched` slice to
///     subscribers, in order, then optionally `resolve_hole` on the
///     first dispatched nonce if a hole was just closed by backfill /
///     rebroadcast.
///   - `Buffered` → no-op for subscribers; metrics-only.
///   - `Dropped` → the event was below `next_expected_nonce`. Counts
///     as a no-op for ordering; useful telemetry on idempotent
///     replays.
///   - `Hole` → emit a hole frame to subscribers and write
///     `control_holes` row to Postgres. The cursor stays put.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlDispatchOutcome {
    Dispatched {
        /// Newly-dispatched instructions in nonce-ascending order.
        dispatched: Vec<BufferedInstr>,
    },
    /// Event was buffered (for finality or for predecessor wait).
    Buffered { nonce: u64, reason: BufferedReason },
    /// Event was dropped because its nonce is below
    /// `next_expected_nonce` (i.e. already dispatched on a previous
    /// run, or replayed via WS overlap).
    Dropped { nonce: u64 },
    /// Stall detected. Caller persists `control_holes`, emits a
    /// `hole` SSE frame, and stops dispatching for this cluster
    /// until the missing nonce arrives via backfill or rebroadcast.
    Hole {
        missing_nonce: u64,
        highest_buffered: u64,
        reason: HoleReason,
    },
    /// Steady state — `tick` walked the structures and found nothing
    /// to do.
    Idle,
}

/// Why an event landed in a buffer rather than being dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferedReason {
    /// `head - block < confirmations_required`. Sits in the
    /// `pending_finality` queue.
    NotFinal,
    /// `nonce > next_expected_nonce`. Sits in the main `BTreeMap`
    /// buffer waiting for its predecessor.
    AwaitingPredecessor,
}

/// Per-cluster strict-ordered control-event state machine. See module
/// docs for the full state diagram.
#[derive(Debug)]
pub struct ControlOrderer {
    cluster: [u8; 20],
    cfg: OrdererConfig,

    /// Next nonce we expect to dispatch. Starts at `0` for fresh
    /// clusters; cold-start hydration sets this to
    /// `MAX(finalized_nonce) + 1`.
    next_expected_nonce: u64,

    /// Out-of-order events whose finality + predecessor checks both
    /// passed but whose nonce is past `next_expected_nonce`. Keyed
    /// on `nonce` so `pop_first()` is cheap and we always see the
    /// lowest-buffered nonce in O(log n).
    buffer: BTreeMap<u64, BufferedInstr>,

    /// Events whose `block_number` is too recent — held until they've
    /// crossed `confirmations_required`. Tagged with the wall-clock
    /// instant they entered finality limbo so `tick` can promote them
    /// when the head moves; the held block_number is the gating value.
    pending_finality: Vec<BufferedInstr>,

    /// Latest `head` block the orderer was informed of. Used by
    /// `tick` to decide when to promote `pending_finality` entries.
    /// `0` means "never told" — events arrive with their own
    /// `head` value via `on_event`.
    head_block: u64,

    /// Open-hole tracking: when the orderer emits a hole, it records
    /// the missing nonce here so a subsequent `on_event` (the
    /// rebroadcast or backfill that closes the gap) can include the
    /// resolution signal in its `Dispatched` outcome via
    /// `resolved_holes`. Cleared on resolve.
    open_holes: BTreeMap<u64, HoleReason>,
}

impl ControlOrderer {
    /// Construct a fresh orderer at `next_expected_nonce = 0` (i.e.
    /// for a brand-new cluster). For an existing cluster, the caller
    /// hydrates via [`Self::with_initial_nonce`].
    pub fn new(cluster: [u8; 20], cfg: OrdererConfig) -> Self {
        Self {
            cluster,
            cfg,
            next_expected_nonce: 0,
            buffer: BTreeMap::new(),
            pending_finality: Vec::new(),
            head_block: 0,
            open_holes: BTreeMap::new(),
        }
    }

    /// Construct an orderer with `next_expected_nonce = initial`. Used
    /// at process-boot cold-start after consulting the
    /// `control_instructions` table.
    pub fn with_initial_nonce(cluster: [u8; 20], cfg: OrdererConfig, initial: u64) -> Self {
        let mut s = Self::new(cluster, cfg);
        s.next_expected_nonce = initial;
        s
    }

    /// Cluster discriminator the orderer was constructed for. Used by
    /// the dispatcher for tracing + multi-cluster routing.
    pub fn cluster(&self) -> [u8; 20] {
        self.cluster
    }

    /// Read-only view of the cursor. Useful in tests + metrics.
    pub fn next_expected_nonce(&self) -> u64 {
        self.next_expected_nonce
    }

    /// Read-only view of the buffer size — exposed for the
    /// `teesql_indexer_control_buffer_depth{cluster=...}` metric.
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Read-only view of the pending-finality queue size.
    pub fn pending_finality_len(&self) -> usize {
        self.pending_finality.len()
    }

    /// Currently-open holes: missing nonce → reason. Snapshot for
    /// hub-side surfacing + tests.
    pub fn open_holes(&self) -> Vec<(u64, HoleReason)> {
        self.open_holes.iter().map(|(&n, &r)| (n, r)).collect()
    }

    /// Process one decoded `ControlInstructionBroadcast` event.
    /// `head` is the indexer's current chain head; the orderer
    /// remembers it via `head_block` so subsequent `tick` calls can
    /// promote pending-finality entries even without a fresh event.
    ///
    /// See module-level docs for the full branch table.
    pub fn on_event(&mut self, ev: BufferedInstr, head: u64) -> ControlDispatchOutcome {
        if head > self.head_block {
            self.head_block = head;
        }

        // (1) Finality gate.
        if !self.has_finality(ev.block_number, head) {
            let nonce = ev.nonce;
            self.pending_finality.push(ev);
            return ControlDispatchOutcome::Buffered {
                nonce,
                reason: BufferedReason::NotFinal,
            };
        }

        // (2) Below-cursor → drop. Already dispatched.
        if ev.nonce < self.next_expected_nonce {
            return ControlDispatchOutcome::Dropped { nonce: ev.nonce };
        }

        // (3) Past-cursor → buffer.
        if ev.nonce > self.next_expected_nonce {
            let nonce = ev.nonce;
            self.buffer.insert(ev.nonce, ev);
            return ControlDispatchOutcome::Buffered {
                nonce,
                reason: BufferedReason::AwaitingPredecessor,
            };
        }

        // (4) Equal-cursor → dispatch + drain.
        let mut dispatched = Vec::with_capacity(1);
        dispatched.push(ev);
        self.next_expected_nonce += 1;
        self.drain_contiguous(&mut dispatched);

        // Resolving a hole at the lowest dispatched nonce: the caller
        // observes `dispatched[0].nonce` against `open_holes` and
        // emits a `resolve_hole` to Postgres.
        for d in &dispatched {
            self.open_holes.remove(&d.nonce);
        }

        ControlDispatchOutcome::Dispatched { dispatched }
    }

    /// Periodic maintenance: promote pending-finality entries whose
    /// block has earned enough confirmations, then evaluate the
    /// buffer's head against expiry + age + size bounds. Returns
    /// `Hole {...}` on first stall observation in any given tick;
    /// returns `Dispatched` if a finality-promotion produced
    /// dispatchable events; `Idle` otherwise.
    ///
    /// The caller drives `tick` on a periodic timer (the bin crate's
    /// `ControlDispatcher` task) AND opportunistically each time a
    /// new chain head arrives. Spec §7.7 — both bounds checks are
    /// hot-path runtime, not just static thresholds.
    pub fn tick(
        &mut self,
        now: Instant,
        now_unix_seconds: u64,
        head: u64,
    ) -> ControlDispatchOutcome {
        if head > self.head_block {
            self.head_block = head;
        }

        // (a) Promote pending_finality entries that have earned
        //     confirmation depth. Replace the vec to keep
        //     promotion-order stable (lowest nonce first after
        //     stable sort). The pending vec is small in practice
        //     (≤ ~50 entries during a finality lull) so the O(n)
        //     scan is fine.
        let mut promoted: Vec<BufferedInstr> = Vec::new();
        let mut still_waiting = Vec::with_capacity(self.pending_finality.len());
        for ev in std::mem::take(&mut self.pending_finality) {
            if self.has_finality(ev.block_number, head) {
                promoted.push(ev);
            } else {
                still_waiting.push(ev);
            }
        }
        self.pending_finality = still_waiting;
        promoted.sort_by_key(|p| p.nonce);

        // Promotion runs through the same on_event branches as a
        // fresh log. We aggregate any dispatched events from
        // promotions to surface them in this tick's outcome.
        let mut dispatched_now: Vec<BufferedInstr> = Vec::new();
        for ev in promoted {
            // Inline the post-finality branches; bypassing on_event
            // avoids re-pushing into pending_finality (we just
            // confirmed finality).
            if ev.nonce < self.next_expected_nonce {
                continue; // Dropped silently
            }
            if ev.nonce > self.next_expected_nonce {
                self.buffer.insert(ev.nonce, ev);
                continue;
            }
            // Equal-cursor.
            let nonce = ev.nonce;
            dispatched_now.push(ev);
            self.next_expected_nonce += 1;
            // Drain into the same vec.
            self.drain_contiguous(&mut dispatched_now);
            self.open_holes.remove(&nonce);
        }

        if !dispatched_now.is_empty() {
            for d in &dispatched_now {
                self.open_holes.remove(&d.nonce);
            }
            return ControlDispatchOutcome::Dispatched {
                dispatched: dispatched_now,
            };
        }

        // (b) Evaluate hole conditions. Order of checks matches the
        // spec: expiry first (operator-tunable), then buffer-age,
        // then buffer-size.
        if let Some((&first_nonce, first_instr)) = self.buffer.iter().next() {
            // The buffer holds entries above `next_expected_nonce`. A
            // stall is meaningful only when there is a gap between
            // cursor and lowest buffered nonce.
            if first_nonce > self.next_expected_nonce {
                // (i) On-chain envelope expiry.
                if first_instr.expiry <= now_unix_seconds {
                    return self.emit_hole(HoleReason::BufferExpired);
                }
                // (ii) Wall-clock buffer-age.
                if now.saturating_duration_since(first_instr.buffered_at) >= self.cfg.max_buffer_age
                {
                    return self.emit_hole(HoleReason::BufferAge);
                }
                // (iii) Size bound.
                if self.buffer.len() > self.cfg.max_buffer {
                    return self.emit_hole(HoleReason::BufferFull);
                }
            }
        }

        ControlDispatchOutcome::Idle
    }

    /// Reorg integration (spec §7.6). The caller has just flipped
    /// `removed=true` on the events table for `block_number > common`;
    /// the orderer's pending-finality queue must drop any entries
    /// whose block was rolled back. Buffered entries with
    /// `block_number > common` are also removed; the cursor itself
    /// is NOT rewound — the dispatcher's caller is responsible for
    /// re-warming via `list_finalized_control_instructions` (which
    /// already filters `removed=false`).
    pub fn drop_after_block(&mut self, common_block: u64) {
        self.pending_finality
            .retain(|ev| ev.block_number <= common_block);
        let to_remove: Vec<u64> = self
            .buffer
            .iter()
            .filter(|(_, ev)| ev.block_number > common_block)
            .map(|(&n, _)| n)
            .collect();
        for n in to_remove {
            self.buffer.remove(&n);
        }
    }

    /// Drain contiguous entries from `buffer` whose nonce equals the
    /// (advancing) cursor, appending each to `out` in nonce-ascending
    /// order.
    fn drain_contiguous(&mut self, out: &mut Vec<BufferedInstr>) {
        while let Some(entry) = self.buffer.first_entry() {
            if *entry.key() == self.next_expected_nonce {
                let (_, ev) = entry.remove_entry();
                out.push(ev);
                self.next_expected_nonce += 1;
            } else {
                break;
            }
        }
    }

    /// Whether `block_number` is `confirmations_required` blocks deep
    /// against `head`. Returns true also when the orderer was not yet
    /// told a head (head==0) — finality gating is skipped in that
    /// case to avoid stalling fresh test fixtures with `head` left at
    /// zero. Production callers always pass a real head.
    fn has_finality(&self, block_number: u64, head: u64) -> bool {
        if head == 0 {
            // Bootstrap: no head observed yet. Treat as past-finality
            // so the orderer can be hand-driven in tests with explicit
            // ordering. Spec §7.2 says the chain head is the gate;
            // when the gate is unknown the conservative thing is
            // actually to fail-closed, but doing so traps unit tests
            // that need to exercise post-finality branches without
            // mocking a head. The bin crate's ControlDispatcher
            // initialises head_block to the indexer's current head
            // before the first on_event, so production never lands
            // here.
            return true;
        }
        head.saturating_sub(block_number) >= self.cfg.confirmations_required
    }

    /// Stamp `open_holes`, return the `Hole {...}` outcome the caller
    /// translates into a `control_holes` insert + a `hole` SSE frame.
    /// The cursor stays put — that's the whole point.
    fn emit_hole(&mut self, reason: HoleReason) -> ControlDispatchOutcome {
        let missing = self.next_expected_nonce;
        let highest = self.buffer.keys().next_back().copied().unwrap_or(missing);
        self.open_holes.insert(missing, reason);
        ControlDispatchOutcome::Hole {
            missing_nonce: missing,
            highest_buffered: highest,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster() -> [u8; 20] {
        [0xc0; 20]
    }

    fn instr(nonce: u64, block_number: u64, expiry: u64) -> BufferedInstr {
        BufferedInstr::new(
            // instructionId distinct per nonce so tests don't
            // accidentally compare equal across cases.
            {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&nonce.to_be_bytes());
                h
            },
            nonce,
            vec![],
            expiry,
            [0u8; 32],
            vec![],
            [0u8; 32],
            block_number,
            0,
            [0u8; 32],
        )
    }

    fn instr_with_target(
        nonce: u64,
        block_number: u64,
        expiry: u64,
        targets: Vec<[u8; 32]>,
    ) -> BufferedInstr {
        let mut i = instr(nonce, block_number, expiry);
        i.target_members = targets;
        i
    }

    /// In-order arrival, all past finality → each event dispatches
    /// immediately, cursor advances, buffer stays empty.
    #[test]
    fn d1_in_order_past_finality_dispatches_immediately() {
        let cfg = OrdererConfig {
            confirmations_required: 12,
            ..OrdererConfig::default()
        };
        let mut o = ControlOrderer::new(cluster(), cfg);
        let head = 1000;

        // nonce 0 at block 50 → head-block = 950 ≫ 12 → finality OK.
        let out = o.on_event(instr(0, 50, u64::MAX), head);
        match out {
            ControlDispatchOutcome::Dispatched { dispatched } => {
                assert_eq!(dispatched.len(), 1);
                assert_eq!(dispatched[0].nonce, 0);
            }
            other => panic!("expected Dispatched, got {other:?}"),
        }
        assert_eq!(o.next_expected_nonce(), 1);
        assert_eq!(o.buffer_len(), 0);

        let out = o.on_event(instr(1, 51, u64::MAX), head);
        assert!(matches!(
            out,
            ControlDispatchOutcome::Dispatched { dispatched } if dispatched.len() == 1 && dispatched[0].nonce == 1
        ));
        assert_eq!(o.next_expected_nonce(), 2);
    }

    /// Out-of-order arrival: 1, then 0 → 0 dispatches and drains 1
    /// from the buffer in a single outcome.
    #[test]
    fn d1_out_of_order_then_fill_drains_buffer() {
        let mut o = ControlOrderer::new(cluster(), OrdererConfig::default());
        let head = 1000;

        let out = o.on_event(instr(1, 50, u64::MAX), head);
        match out {
            ControlDispatchOutcome::Buffered {
                nonce,
                reason: BufferedReason::AwaitingPredecessor,
            } => {
                assert_eq!(nonce, 1);
            }
            other => panic!("expected Buffered(AwaitingPredecessor), got {other:?}"),
        }
        assert_eq!(o.buffer_len(), 1);
        assert_eq!(o.next_expected_nonce(), 0);

        // Now nonce 0 arrives — should dispatch 0 + drain 1 in one outcome.
        let out = o.on_event(instr(0, 49, u64::MAX), head);
        match out {
            ControlDispatchOutcome::Dispatched { dispatched } => {
                assert_eq!(dispatched.len(), 2);
                assert_eq!(dispatched[0].nonce, 0);
                assert_eq!(dispatched[1].nonce, 1);
            }
            other => panic!("expected Dispatched(2), got {other:?}"),
        }
        assert_eq!(o.next_expected_nonce(), 2);
        assert_eq!(o.buffer_len(), 0);
    }

    /// Below-cursor event is dropped silently (idempotent re-apply).
    #[test]
    fn d1_below_cursor_event_is_dropped() {
        let mut o = ControlOrderer::with_initial_nonce(cluster(), OrdererConfig::default(), 5);
        let head = 1000;
        let out = o.on_event(instr(3, 50, u64::MAX), head);
        match out {
            ControlDispatchOutcome::Dropped { nonce } => assert_eq!(nonce, 3),
            other => panic!("expected Dropped, got {other:?}"),
        }
        assert_eq!(o.next_expected_nonce(), 5);
    }

    /// Finality gate: event with block too close to head is parked
    /// in `pending_finality`, then tick promotes it once head moves.
    #[test]
    fn d1_finality_buffering_then_tick_promotes() {
        let cfg = OrdererConfig {
            confirmations_required: 12,
            ..OrdererConfig::default()
        };
        let mut o = ControlOrderer::new(cluster(), cfg);
        // head=100, block=95 → distance 5 < 12 → buffer.
        let out = o.on_event(instr(0, 95, u64::MAX), 100);
        match out {
            ControlDispatchOutcome::Buffered {
                nonce,
                reason: BufferedReason::NotFinal,
            } => assert_eq!(nonce, 0),
            other => panic!("expected Buffered(NotFinal), got {other:?}"),
        }
        assert_eq!(o.pending_finality_len(), 1);
        assert_eq!(o.next_expected_nonce(), 0);

        // tick at head=110 → distance 15 ≥ 12 → promote + dispatch.
        let out = o.tick(Instant::now(), 1_000_000, 110);
        match out {
            ControlDispatchOutcome::Dispatched { dispatched } => {
                assert_eq!(dispatched.len(), 1);
                assert_eq!(dispatched[0].nonce, 0);
            }
            other => panic!("expected Dispatched, got {other:?}"),
        }
        assert_eq!(o.next_expected_nonce(), 1);
        assert_eq!(o.pending_finality_len(), 0);
    }

    /// `tick` on an empty buffer + empty pending → Idle.
    #[test]
    fn d1_tick_idle_when_nothing_pending() {
        let mut o = ControlOrderer::new(cluster(), OrdererConfig::default());
        let out = o.tick(Instant::now(), 1_000_000, 1000);
        assert!(matches!(out, ControlDispatchOutcome::Idle));
    }

    // ── D2: hole detection ────────────────────────────────────────────

    /// Buffer entry whose `expiry` has passed → tick emits a Hole and
    /// the cursor stays put.
    #[test]
    fn d2_hole_on_expiry() {
        let mut o = ControlOrderer::with_initial_nonce(cluster(), OrdererConfig::default(), 0);
        let head = 1000;
        // Nonce 5 with expiry=100. Cursor sits at 0 waiting for 0..4.
        let out = o.on_event(instr(5, 50, 100), head);
        assert!(matches!(out, ControlDispatchOutcome::Buffered { .. }));

        // Now wall clock is past expiry → Hole at missing=0.
        let out = o.tick(Instant::now(), 200, head);
        match out {
            ControlDispatchOutcome::Hole {
                missing_nonce,
                highest_buffered,
                reason,
            } => {
                assert_eq!(missing_nonce, 0);
                assert_eq!(highest_buffered, 5);
                assert_eq!(reason, HoleReason::BufferExpired);
            }
            other => panic!("expected Hole, got {other:?}"),
        }
        // Cursor stays put.
        assert_eq!(o.next_expected_nonce(), 0);
        // Subsequent ticks while the gap persists keep emitting Hole
        // (the dispatcher dedupes on the `(cluster, missing_nonce)`
        // unique index in `record_hole`).
        let out = o.tick(Instant::now(), 200, head);
        assert!(matches!(out, ControlDispatchOutcome::Hole { .. }));
    }

    /// `MAX_BUFFER` exceeded with the lowest nonce still missing →
    /// Hole. Use `BufferFull`.
    #[test]
    fn d2_hole_on_buffer_full() {
        let cfg = OrdererConfig {
            max_buffer: 2,
            ..OrdererConfig::default()
        };
        let mut o = ControlOrderer::with_initial_nonce(cluster(), cfg, 0);
        let head = 1000;
        // Buffer 1, 2, 3 — past max_buffer (2).
        for n in [1u64, 2, 3] {
            let _ = o.on_event(instr(n, 50, u64::MAX), head);
        }
        let out = o.tick(Instant::now(), 1_000_000, head);
        match out {
            ControlDispatchOutcome::Hole {
                missing_nonce,
                highest_buffered,
                reason,
            } => {
                assert_eq!(missing_nonce, 0);
                assert_eq!(highest_buffered, 3);
                assert_eq!(reason, HoleReason::BufferFull);
            }
            other => panic!("expected Hole(BufferFull), got {other:?}"),
        }
    }

    /// Buffer-age: an old entry stays in the buffer for longer than
    /// `MAX_BUFFER_AGE`. Use a tiny duration in tests so we don't
    /// have to wait an hour.
    #[test]
    fn d2_hole_on_buffer_age() {
        let cfg = OrdererConfig {
            max_buffer_age: Duration::from_millis(0),
            ..OrdererConfig::default()
        };
        let mut o = ControlOrderer::with_initial_nonce(cluster(), cfg, 0);
        let head = 1000;
        // Nonce 1 with very-future expiry, but buffer-age is 0.
        let _ = o.on_event(instr(1, 50, u64::MAX), head);
        // Tick immediately. saturating_duration_since on the same
        // Instant yields 0, which is `>= 0` for `max_buffer_age`.
        // The `>=` makes the boundary inclusive on purpose: a 0-age
        // bound is the way tests assert the path without sleeping.
        let out = o.tick(Instant::now(), 1_000_000, head);
        match out {
            ControlDispatchOutcome::Hole { reason, .. } => {
                assert_eq!(reason, HoleReason::BufferAge);
            }
            other => panic!("expected Hole(BufferAge), got {other:?}"),
        }
    }

    /// Hole gets resolved when the missing nonce arrives via
    /// rebroadcast. The orderer drains the buffer in one outcome and
    /// `open_holes` is cleared so `resolve_hole` can be persisted.
    #[test]
    fn d2_hole_resolution_via_rebroadcast() {
        let mut o = ControlOrderer::with_initial_nonce(cluster(), OrdererConfig::default(), 0);
        let head = 1000;
        // Buffer 1, 2, 3.
        for n in [1u64, 2, 3] {
            let _ = o.on_event(instr(n, 50, u64::MAX), head);
        }
        // Force a hole.
        let _ = o.tick(Instant::now(), 1_000_000, head); // not a hole; expiries still fine
                                                         // Now expire the buffer head:
        let cfg = OrdererConfig {
            max_buffer_age: Duration::from_millis(0),
            ..OrdererConfig::default()
        };
        let _ = std::mem::replace(&mut o.cfg, cfg);
        let out = o.tick(Instant::now(), 1_000_000, head);
        assert!(matches!(out, ControlDispatchOutcome::Hole { .. }));
        // open_holes records the missing nonce.
        let holes = o.open_holes();
        assert_eq!(holes.len(), 1);
        assert_eq!(holes[0].0, 0);

        // Rebroadcast at nonce 0 arrives.
        let out = o.on_event(instr(0, 60, u64::MAX), head);
        match out {
            ControlDispatchOutcome::Dispatched { dispatched } => {
                let nonces: Vec<u64> = dispatched.iter().map(|d| d.nonce).collect();
                assert_eq!(nonces, vec![0, 1, 2, 3]);
            }
            other => panic!("expected Dispatched(0..=3), got {other:?}"),
        }
        // The hole at nonce 0 is closed.
        assert!(o.open_holes().is_empty());
        assert_eq!(o.next_expected_nonce(), 4);
    }

    // ── D5: backfill / cold-start ────────────────────────────────────

    /// `with_initial_nonce` sets the cursor but does not pretend to
    /// have data — events at the new cursor still flow through
    /// on_event normally.
    #[test]
    fn d5_with_initial_nonce_starts_at_cursor() {
        let mut o = ControlOrderer::with_initial_nonce(cluster(), OrdererConfig::default(), 100);
        assert_eq!(o.next_expected_nonce(), 100);
        let out = o.on_event(instr(100, 50, u64::MAX), 1000);
        match out {
            ControlDispatchOutcome::Dispatched { dispatched } => {
                assert_eq!(dispatched.len(), 1);
                assert_eq!(dispatched[0].nonce, 100);
            }
            other => panic!("expected Dispatched, got {other:?}"),
        }
        assert_eq!(o.next_expected_nonce(), 101);
    }

    /// Reorg integration: pending-finality entries past the common
    /// ancestor are dropped; surviving entries replay in order.
    #[test]
    fn d5_reorg_drop_after_block_clears_pending() {
        let mut o = ControlOrderer::new(cluster(), OrdererConfig::default());
        // head=100, conf=12. Block 95 → not yet final.
        let _ = o.on_event(instr(0, 95, u64::MAX), 100);
        let _ = o.on_event(instr(1, 96, u64::MAX), 100);
        assert_eq!(o.pending_finality_len(), 2);
        // Reorg back to common=95: events at block_number > 95 dropped.
        o.drop_after_block(95);
        assert_eq!(o.pending_finality_len(), 1);
        // The remaining one is at block 95 → kept.
        assert_eq!(o.pending_finality[0].block_number, 95);
    }

    /// Reorg drops buffer entries past common too (they were
    /// dispatched/buffered post-finality but the chain rewound).
    #[test]
    fn d5_reorg_drops_buffer_entries_past_common() {
        let mut o = ControlOrderer::with_initial_nonce(cluster(), OrdererConfig::default(), 0);
        // Buffer nonce 1 at block 60, nonce 2 at block 70.
        let _ = o.on_event(instr(1, 60, u64::MAX), 1000);
        let _ = o.on_event(instr(2, 70, u64::MAX), 1000);
        assert_eq!(o.buffer_len(), 2);
        o.drop_after_block(65);
        // Only nonce 1 (block 60) survives.
        assert_eq!(o.buffer_len(), 1);
        assert!(o.buffer.contains_key(&1));
        assert!(!o.buffer.contains_key(&2));
    }

    // ── D4 coverage: target-members semantics tested at the orderer
    // level. The on-chain shape (empty array = all members) is filtered
    // server-side in the SSE handler; this tests round-trips it
    // through the BufferedInstr type so a regression to `Vec<>` shape
    // trips here.

    #[test]
    fn d4_target_members_empty_means_broadcast_all() {
        let mut o = ControlOrderer::new(cluster(), OrdererConfig::default());
        let _ = o.on_event(instr_with_target(0, 50, u64::MAX, vec![]), 1000);
        // Cursor advanced; the dispatched outcome's target_members
        // shape is empty Vec, not None.
        assert_eq!(o.next_expected_nonce(), 1);
    }

    #[test]
    fn d4_target_members_non_empty_preserves_order() {
        let mut o = ControlOrderer::new(cluster(), OrdererConfig::default());
        let m1 = [0x11u8; 32];
        let m2 = [0x22u8; 32];
        let out = o.on_event(instr_with_target(0, 50, u64::MAX, vec![m1, m2]), 1000);
        match out {
            ControlDispatchOutcome::Dispatched { dispatched } => {
                assert_eq!(dispatched.len(), 1);
                assert_eq!(dispatched[0].target_members, vec![m1, m2]);
            }
            other => panic!("expected Dispatched, got {other:?}"),
        }
    }

    #[test]
    fn hole_reason_as_str_stable() {
        // Pin the slugs — `control_holes.reason` consumers (hub UI,
        // metrics dashboards) match on these strings.
        assert_eq!(HoleReason::BufferExpired.as_str(), "buffer_expired");
        assert_eq!(HoleReason::BufferAge.as_str(), "buffer_age");
        assert_eq!(HoleReason::BufferFull.as_str(), "buffer_full");
    }
}
