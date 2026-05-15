-- provision.sql (run once on the monitor cluster's primary, as the
-- postgres superuser via the local trust path — same execution shape as
-- deployments/monitoring-hub/provision.sql).
\set ON_ERROR_STOP on

-- Roles must exist BEFORE the database so the database can be owned by
-- chain_indexer_writer (an OWNER = postgres database forces every
-- subsequent CREATE TABLE to need explicit grants for the writer; we
-- want the writer to own the schema natively). LOGIN only — the
-- sidecar's wire-protocol auth substitution intercepts the password
-- using the cluster's KMS-derived secret, so no password is set here.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chain_indexer_writer') THEN
        CREATE ROLE chain_indexer_writer WITH LOGIN;
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chain_indexer_reader') THEN
        CREATE ROLE chain_indexer_reader WITH LOGIN;
    END IF;
END $$;

-- Idempotent database creation, OWNER set to the writer so the writer
-- naturally owns every table it creates. \gexec runs the SELECT only
-- when the WHERE clause matches.
SELECT 'CREATE DATABASE chain_indexer OWNER chain_indexer_writer'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'chain_indexer')\gexec

\c chain_indexer

GRANT ALL PRIVILEGES ON DATABASE chain_indexer TO chain_indexer_writer;
GRANT ALL ON SCHEMA public TO chain_indexer_writer;
ALTER DEFAULT PRIVILEGES FOR ROLE chain_indexer_writer IN SCHEMA public
    GRANT ALL ON TABLES TO chain_indexer_writer;
ALTER DEFAULT PRIVILEGES FOR ROLE chain_indexer_writer IN SCHEMA public
    GRANT ALL ON SEQUENCES TO chain_indexer_writer;

GRANT CONNECT ON DATABASE chain_indexer TO chain_indexer_reader;
GRANT USAGE ON SCHEMA public TO chain_indexer_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE chain_indexer_writer IN SCHEMA public
    GRANT SELECT ON TABLES TO chain_indexer_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE chain_indexer_writer IN SCHEMA public
    GRANT SELECT ON SEQUENCES TO chain_indexer_reader;

-- Tables follow. The migration runner inside the indexer applies them
-- on first connect; this provision script only sets up the database +
-- roles + grants. Schema below is reproduced for reference.

-- Every table carries a chain_id discriminator. One indexer process
-- writes per chain; multiple processes share the same database.

-- Block tracking — used for reorg detection.
CREATE TABLE blocks (
  chain_id     int NOT NULL,
  number       bigint NOT NULL,
  hash         bytea NOT NULL,
  parent_hash  bytea NOT NULL,
  block_ts     bigint NOT NULL,
  ingested_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, number)
);
CREATE INDEX blocks_hash_idx ON blocks (chain_id, hash);

-- Watched contract registry — populated from config + ClusterDeployed events.
CREATE TABLE watched_contracts (
  chain_id    int NOT NULL,
  address     bytea NOT NULL,
  kind        text NOT NULL CHECK (kind IN ('factory','cluster_diamond')),
  parent      bytea,                          -- factory address; NULL for factories themselves
  from_block  bigint NOT NULL,
  added_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, address)
);

-- Raw event log — append-only, source of truth.
--
-- Earlier revisions of this file declared `PARTITION BY RANGE
-- (block_number)`, but the unique dedup index `events_dedup_idx`
-- (`chain_id, contract, block_hash, log_index`) doesn't include
-- `block_number`, and Postgres rejects unique indexes on partitioned
-- tables that don't cover the partition key. Two ways out: (a) widen
-- the dedup index to include `block_number` AND change the
-- `ON CONFLICT` clause in `crates/core/src/store.rs::insert_event` to
-- match, or (b) drop partitioning until v0.1.x actually grows
-- partition-management code. We picked (b) — the code base has no
-- partition rollover / drop logic yet, the spec drift was producing a
-- table operators couldn't create from scratch, and a single TeeSQL-
-- internal cluster's event volume is well below partition-pressure
-- territory. Re-introduce in a future release alongside the
-- partition-management code.
CREATE TABLE events (
  id            bigserial NOT NULL,
  chain_id      int NOT NULL,
  contract      bytea NOT NULL,
  block_number  bigint NOT NULL,
  block_hash    bytea NOT NULL,
  log_index     int NOT NULL,
  tx_hash       bytea NOT NULL,
  topic0        bytea NOT NULL,
  topics_rest   bytea NOT NULL,                -- topics 1..3 concatenated
  data          bytea NOT NULL,
  decoded_kind  text,                          -- 'MemberRegistered' etc; NULL = no decoder matched
  decoded       jsonb,                         -- decoder output
  removed       boolean NOT NULL DEFAULT false,-- flipped true on reorg rollback
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, block_number, id)
);

CREATE UNIQUE INDEX events_dedup_idx ON events (chain_id, contract, block_hash, log_index);
CREATE INDEX events_contract_kind_idx ON events (chain_id, contract, decoded_kind, block_number);
CREATE INDEX events_decoded_gin ON events USING gin (decoded jsonb_path_ops);

-- Materialized views (just summary tables we keep current inline; not
-- Postgres MATERIALIZED VIEWs because we update them per-event, not
-- via REFRESH). Always derived from `events`; safe to truncate and
-- rebuild if they ever drift.

CREATE TABLE cluster_leader (
  chain_id         int NOT NULL,
  cluster_address  bytea NOT NULL,
  member_id        bytea NOT NULL,
  epoch            bigint NOT NULL,
  as_of_block      bigint NOT NULL,
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, cluster_address)
);

CREATE TABLE cluster_members (
  chain_id         int NOT NULL,
  cluster_address  bytea NOT NULL,
  member_id        bytea NOT NULL,
  instance_id      bytea,
  passthrough      bytea,
  dns_label        text,
  public_endpoint  text,
  -- Explicit `host:port` target the fabric uotcp dialer connects to
  -- when establishing this member's WireGuard tunnel. Derived from
  -- `public_endpoint` (Phala deployment metadata) at materialization
  -- time so fabric never has to parse the URL or guess the port —
  -- spec docs/designs/network-architecture-unified.md §3.3, §9.3.
  -- NULL until `PublicEndpointUpdated` lands a parseable URL.
  wg_endpoint      text,
  -- WireGuard pubkey hex (lowercase 64-char Curve25519, no 0x prefix).
  -- Populated by V1 `MemberWgPubkeySet` events emitted by WgMeshFacet
  -- (Phase 1 fabric cross-boundary). NULL until the member's first
  -- publish; fabric defers admission until non-NULL.
  wg_pubkey_hex    text,
  -- V2 admission columns per unified-network-design §4.1. Populated by
  -- `MemberWgPubkeySetV2` and tracked alongside (not in place of)
  -- `wg_pubkey_hex` so a cluster mid-cutover surfaces both — fabric
  -- prefers V2 when present, but pre-cutover clusters keep working
  -- through the V1 column. NULL until the member's first attested
  -- publish.
  wg_pubkey        bytea,                      -- 32-byte raw Curve25519
  quote_hash       bytea,                      -- keccak256(tdxQuote)
  -- Event coordinates of the most recent V2 publish applied to
  -- `wg_pubkey` / `quote_hash`. Compared as a tuple against incoming
  -- events so a stale `MemberWgPubkeySetV2` re-delivered after a
  -- rotation cannot revert the row to the older pubkey. NULL until
  -- the first V2 event is observed.
  wg_pubkey_v2_block      bigint,
  wg_pubkey_v2_log_index  int,
  -- Latest `TcbDegraded` alert per unified-network-design §6.3 / §7.
  -- `tcb_severity` is a uint8 enum (1 = warn, 2 = critical at design
  -- time; smallint leaves room for the contract surface to expand).
  -- The pair is "current alert snapshot, not audit trail"; the full
  -- history lives in the events log.
  tcb_severity     smallint,
  tcb_degraded_at  bigint,                     -- block timestamp of the latest event
  -- Event coordinates of the most recent `TcbDegraded` applied to
  -- `tcb_severity` / `tcb_degraded_at`. Same purpose as the V2 pair
  -- above: a stale duplicate cannot overwrite a newer severity.
  tcb_event_block      bigint,
  tcb_event_log_index  int,
  registered_at    bigint,                     -- block timestamp
  retired_at       bigint,                     -- NULL = active
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, cluster_address, member_id)
);

-- Idempotent backfill of `wg_pubkey_hex` on clusters provisioned
-- before Phase 1 fabric cross-boundary landed. `ADD COLUMN IF NOT
-- EXISTS` is a no-op on a fresh DB where the column above already
-- defines it; on an upgraded DB it bolts the column on without
-- losing the existing roster.
ALTER TABLE cluster_members ADD COLUMN IF NOT EXISTS wg_pubkey_hex text;
-- Idempotent backfill of the V2 admission columns + TCB alert pair
-- on clusters provisioned before the unified-network-design landed.
-- Same `ADD COLUMN IF NOT EXISTS` pattern as the wg_pubkey_hex
-- backfill above: no-op on a fresh DB; safe upgrade on an existing
-- one. Surfacing them as nullables preserves the pre-V2 roster
-- shape — fabric's V1 path keeps reading `wg_pubkey_hex` until the
-- contract cuts over.
ALTER TABLE cluster_members ADD COLUMN IF NOT EXISTS wg_pubkey bytea;
ALTER TABLE cluster_members ADD COLUMN IF NOT EXISTS quote_hash bytea;
ALTER TABLE cluster_members ADD COLUMN IF NOT EXISTS tcb_severity smallint;
ALTER TABLE cluster_members ADD COLUMN IF NOT EXISTS tcb_degraded_at bigint;
-- Backfill the per-event-source coordinate columns introduced by
-- W1-002 follow-up (stale-replay-cannot-revert). NULL on existing
-- rows is treated as "no prior event observed" by the materializer's
-- comparison logic, so the first post-upgrade event always wins.
ALTER TABLE cluster_members ADD COLUMN IF NOT EXISTS wg_pubkey_v2_block bigint;
ALTER TABLE cluster_members ADD COLUMN IF NOT EXISTS wg_pubkey_v2_log_index int;
ALTER TABLE cluster_members ADD COLUMN IF NOT EXISTS tcb_event_block bigint;
ALTER TABLE cluster_members ADD COLUMN IF NOT EXISTS tcb_event_log_index int;

-- ---------------------------------------------------------------------------
-- cluster_compose_hashes — MRTD allowlist materialization driven by
-- `ComposeHashAllowed` / `ComposeHashRemoved`
-- (unified-network-design §4.2).
--
-- One row per `(chain_id, cluster_address, compose_hash)`. `allowed_at`
-- and `removed_at` are block timestamps; the row's "live" state is
-- `allowed_at IS NOT NULL AND removed_at IS NULL`. A re-add after a
-- removal flips `removed_at` back to NULL — fabric reads the row as
-- a current-state snapshot, not a sticky history (the full audit
-- trail lives in the events log).
--
-- `allowed_at`/`removed_at` are nullable independently so an
-- out-of-order replay that delivers a removal before the matching
-- add still records the removal — the materializer fills the
-- missing half on subsequent ingest.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cluster_compose_hashes (
  chain_id         int NOT NULL,
  cluster_address  bytea NOT NULL,
  compose_hash     bytea NOT NULL,             -- 32-byte keccak256(compose YAML)
  allowed_at       bigint,                     -- block timestamp of the most recent allow
  removed_at       bigint,                     -- NULL = currently allowed
  -- Event coordinates of the most recent allow/remove applied to the
  -- row. Compared as a `(block_number, log_index)` tuple against
  -- incoming events so a stale duplicate `ComposeHashAllowed` (e.g.
  -- WS replay of an earlier allow that has since been superseded by
  -- `ComposeHashRemoved`) cannot clear `removed_at` and re-activate
  -- a revoked MRTD. NULL until the first event is observed.
  last_event_block      bigint,
  last_event_log_index  int,
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, cluster_address, compose_hash)
);

-- Backfill of the event-coordinate columns introduced by the W1-002
-- follow-up (stale-replay-cannot-reactivate). NULL on existing rows
-- is treated as "no prior event observed" by the materializer's
-- comparison logic, so the first post-upgrade event always wins.
ALTER TABLE cluster_compose_hashes
    ADD COLUMN IF NOT EXISTS last_event_block bigint;
ALTER TABLE cluster_compose_hashes
    ADD COLUMN IF NOT EXISTS last_event_log_index int;

-- Index optimised for fabric's "list currently-active hashes" probe.
-- Partial index excludes removed rows so the scan footprint stays
-- proportional to live allowlist size (single digits in practice).
CREATE INDEX IF NOT EXISTS cluster_compose_hashes_active_idx
    ON cluster_compose_hashes (chain_id, cluster_address)
    WHERE removed_at IS NULL;

-- ---------------------------------------------------------------------------
-- cluster_member_quotes — raw TDX quote bytes per
-- `MemberWgPubkeySetV2` admission (unified-network-design §4.1, §9.2).
--
-- The `MemberWgPubkeySetV2` event carries only `(memberId, wgPubkey,
-- quoteHash)`; the raw ~4.5 KB quote is too large for an event log
-- and is not persisted on chain. The indexer recovers the bytes from
-- the originating tx calldata (`setMemberWgPubkeyAttested`'s third
-- argument), verifies `keccak256(tdxQuote) == quoteHash`, and stores
-- the bytes here so fabric can fetch them through the REST surface
-- at `GET /v1/{chain}/clusters/{addr}/members/{id}/quote`.
--
-- Primary key includes `quote_hash` so a member's same-cluster
-- rotation (blue-green redeploy mints a new pubkey + quote per
-- design §6.3) keeps every historical quote retrievable. Fabric
-- always requests the latest by descending `observed_at`; the table
-- is content-addressed by `quote_hash` and immutable per row
-- (`quote_bytes` never changes for a given `quote_hash`).
--
-- `r2_uri` is the optional off-chain mirror location set after a
-- successful upload to the R2 availability mirror (design §9.2:
-- "R2 is availability-only; verify-by-hash means R2 trust is never
-- extended"). NULL when the indexer is configured without R2 or
-- when the upload has not completed yet.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS cluster_member_quotes (
  chain_id         int NOT NULL,
  cluster_address  bytea NOT NULL,                 -- 20-byte cluster diamond
  member_id        bytea NOT NULL,                 -- 32-byte member identity
  quote_hash       bytea NOT NULL,                 -- 32-byte keccak256(tdxQuote)
  wg_pubkey        bytea NOT NULL,                 -- 32-byte Curve25519 pubkey from the event
  quote_bytes      bytea NOT NULL,                 -- raw TDX quote (~4.5 KB)
  block_number     bigint NOT NULL,                -- emit block of MemberWgPubkeySetV2
  block_hash       bytea NOT NULL,
  log_index        int NOT NULL,
  tx_hash          bytea NOT NULL,                 -- setMemberWgPubkeyAttested tx
  r2_uri           text,                           -- NULL until R2 mirror upload succeeds
  observed_at      timestamptz NOT NULL DEFAULT now(),
  -- Reorg rollback flag — flipped to true when the row's source
  -- `MemberWgPubkeySetV2` event lands past the common ancestor of a
  -- reorg, then back to false by the cold-start replay that re-emits
  -- the event onto the new canonical chain. Mirrors the `removed`
  -- convention on `events`, `control_instructions`, `control_acks`.
  -- All read paths (latest_member_quote, member_quote_by_hash,
  -- REST handler) filter `removed = false` so a rolled-back row
  -- can't be served as the canonical answer between rollback and
  -- replay. Quote bytes themselves are content-addressed and never
  -- change for a given quote_hash, so the row survives the rollback
  -- as a soft-delete and is reanimated by the replay's upsert.
  removed          boolean NOT NULL DEFAULT false,
  PRIMARY KEY (chain_id, cluster_address, member_id, quote_hash)
);

-- Idempotent backfill of `removed` on clusters provisioned before
-- the reorg-cleanup follow-up landed. Default to false (matching
-- the column declaration above) so existing rows are visible to
-- the `removed = false` filter immediately.
ALTER TABLE cluster_member_quotes
    ADD COLUMN IF NOT EXISTS removed boolean NOT NULL DEFAULT false;

-- Latest-quote-per-member lookup. The REST handler answers
-- `GET .../members/{id}/quote` with the most recently observed row;
-- ordering by `block_number DESC, log_index DESC` matches canonical
-- chain order so a replayed older event cannot displace a newer one
-- by virtue of arriving later in wall-clock time. The query layer
-- adds `WHERE removed = false` to filter reorg-rolled-back rows; the
-- index is intentionally NOT partial so re-running this provision
-- script against an in-place upgrade doesn't try to drop+recreate
-- (CREATE INDEX IF NOT EXISTS is idempotent on name, not predicate).
CREATE INDEX IF NOT EXISTS cluster_member_quotes_latest_idx
    ON cluster_member_quotes
       (chain_id, cluster_address, member_id, block_number DESC, log_index DESC);

-- R2-mirror backfill index — finds rows that still need an upload.
-- Partial index keeps the scan tight when the indexer is configured
-- with the mirror enabled. The backfill sweep also filters `removed
-- = false` at query time so a reorg-rolled-back row isn't mirrored;
-- the predicate stays NULL-only here for the same shape-stability
-- reason as the latest index above.
CREATE INDEX IF NOT EXISTS cluster_member_quotes_pending_r2_idx
    ON cluster_member_quotes (chain_id, observed_at)
    WHERE r2_uri IS NULL;

-- Idempotent backfill of `wg_endpoint` on clusters provisioned before
-- GAP-W1-005 (the unified-architecture wg_endpoint surface). On an
-- upgraded DB the column is added empty; the next `PublicEndpointUpdated`
-- event back-populates it. Operators can also force a rebuild by
-- re-running the materializer's replay path for the cluster.
ALTER TABLE cluster_members ADD COLUMN IF NOT EXISTS wg_endpoint text;

CREATE TABLE cluster_lifecycle (
  chain_id         int NOT NULL,
  cluster_address  bytea NOT NULL,
  destroyed_at     bigint,                     -- block timestamp; NULL = active
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, cluster_address)
);

-- Per-watched-contract cursor: "we've processed up to and including
-- this block." Drives both cold-start backfill resume and WS-reconnect
-- catchup.
CREATE TABLE ingest_cursor (
  chain_id    int NOT NULL,
  contract    bytea NOT NULL,
  next_block  bigint NOT NULL,                 -- next block to scan
  PRIMARY KEY (chain_id, contract)
);

-- Misc chain state, per chain: head_block, finalized_block,
-- last_subscription_seq.
CREATE TABLE chain_state (
  chain_id int NOT NULL,
  k        text NOT NULL,
  v        text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, k)
);

-- Optional historical-query result cache. Hot queries (a consumer
-- repeatedly asking for the same as_of_block) hit this instead of
-- replaying events. Eviction is LRU+TTL; nothing here is authoritative.
CREATE TABLE historical_query_cache (
  chain_id        int NOT NULL,
  cluster_address bytea NOT NULL,
  endpoint        text NOT NULL,                -- e.g. 'leader' / 'members'
  as_of_block     bigint NOT NULL,
  payload         jsonb NOT NULL,
  attestation     jsonb NOT NULL,               -- pre-signed envelope; safe to serve as-is
  cached_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, cluster_address, endpoint, as_of_block)
);
CREATE INDEX historical_query_cache_lru ON historical_query_cache (cached_at);

-- ---------------------------------------------------------------------------
-- Control-plane tables (Track A4 — spec docs/specs/control-plane-redesign.md
-- §5.3, §7). Strongly-typed mirrors of the on-chain
-- ControlInstructionBroadcast + ControlAck events. Distinct from the generic
-- `events` row + `chain_indexer_events` channel because:
--
--   1. Downstream consumers (per-cluster ControlOrderer in Track D1, hub
--      audit log + log-fetch worker in Track F1/F2) want indexed columns
--      (cluster, nonce, jobId, seq) without fishing through a JSONB blob
--      on every probe.
--   2. The control-plane SSE stream subscribes to its own LISTEN channel
--      (`chain_indexer_control`) so consumers don't have to filter every
--      monitoring-hub heartbeat MemberRegistered event off the bus to
--      get to the per-cluster control traffic.
--
-- Both tables follow the same `removed BOOLEAN` reorg convention as
-- `events`: on reorg the ingestor flips `removed=true` for everything
-- past the common ancestor and re-applies surviving rows on replay.
-- ---------------------------------------------------------------------------

CREATE TABLE control_instructions (
  id              bigserial NOT NULL,
  cluster         bytea NOT NULL,                 -- 20-byte cluster diamond address (the emitter)
  instruction_id  bytea NOT NULL,                 -- bytes32 from the indexed topic
  nonce           bigint NOT NULL,                -- uint64 fits cleanly in bigint
  target_members  bytea[] NOT NULL,               -- bytes32[] non-indexed; empty = broadcast (spec §5.6)
  expiry          bigint NOT NULL,                -- uint64 unix seconds
  salt            bytea NOT NULL,                 -- bytes32
  ciphertext      bytea NOT NULL,                 -- raw bytes
  ciphertext_hash bytea NOT NULL,                 -- bytes32 = keccak256(ciphertext)
  block_number    bigint NOT NULL,
  log_index       int NOT NULL,
  tx_hash         bytea NOT NULL,
  observed_at     timestamptz NOT NULL DEFAULT now(),
  removed         boolean NOT NULL DEFAULT false,
  PRIMARY KEY (id)
);

-- (cluster, nonce) uniqueness — the on-chain bitmap-windowed nonce
-- check (spec §5.5 step 5) prevents true duplicates, but the indexer
-- can re-observe the same event on WS replay or a steady-state /
-- backfill overlap. The ingestor uses `ON CONFLICT (cluster, nonce)
-- WHERE removed = false DO NOTHING` to make the insert idempotent
-- without resurrecting reorg-marked rows.
CREATE UNIQUE INDEX control_instructions_cluster_nonce_idx
  ON control_instructions (cluster, nonce)
  WHERE removed = false;

CREATE INDEX control_instructions_block_idx
  ON control_instructions (cluster, block_number, log_index);

CREATE INDEX control_instructions_instruction_id_idx
  ON control_instructions (instruction_id);

CREATE TABLE control_acks (
  id              bigserial NOT NULL,
  cluster         bytea NOT NULL,
  instruction_id  bytea NOT NULL,
  job_id          bytea NOT NULL,
  member_id       bytea NOT NULL,
  status          smallint NOT NULL,              -- uint8 enum from spec §5.3 (1=ACCEPTED..6=EXPIRED)
  seq             bigint NOT NULL,                -- uint64 monotonic per (jobId, memberId)
  log_pointer     bytea,                          -- bytes32 sha256 of encrypted R2 log; NULL on intermediate ACCEPTED
  summary         bytea,                          -- variable bytes; NULL when not provided
  block_number    bigint NOT NULL,
  log_index       int NOT NULL,
  tx_hash         bytea NOT NULL,
  observed_at     timestamptz NOT NULL DEFAULT now(),
  removed         boolean NOT NULL DEFAULT false,
  PRIMARY KEY (id)
);

-- (cluster, job_id, seq) uniqueness — the spec mandates strict
-- monotonicity per (jobId, memberId), which the on-chain facet
-- enforces. Indexer-side dedup uses this index to swallow WS replays
-- of the same ack idempotently.
CREATE UNIQUE INDEX control_acks_cluster_jobid_seq_idx
  ON control_acks (cluster, job_id, seq)
  WHERE removed = false;

CREATE INDEX control_acks_instruction_idx
  ON control_acks (cluster, instruction_id);

CREATE INDEX control_acks_member_idx
  ON control_acks (cluster, member_id, seq);

CREATE INDEX control_acks_block_idx
  ON control_acks (cluster, block_number, log_index);

-- ---------------------------------------------------------------------------
-- Control-plane hole tracking (Track D2 — spec
-- docs/specs/control-plane-redesign.md §7.4).
--
-- The per-cluster ControlOrderer (Track D1) is strict-ordered: it
-- dispatches instructions in `nonce` order and stops the cluster's
-- stream when a gap is observed (buffer expired, MAX_BUFFER_AGE
-- exceeded, or buffer-bound exhausted with the lowest nonce still
-- missing). The hole row is the durable record of that stall — emitted
-- to the control-plane SSE stream as a `hole` frame and surfaced in
-- the hub UI so the cluster-owner Safe can rebroadcast at the missing
-- nonce per spec §5.7.
--
-- `(cluster, missing_nonce)` is unique so a re-trigger of the same
-- hole (e.g. the ordering loop re-evaluates after a new event arrives
-- but the gap persists) is an UPSERT — only the first observation
-- carries the original `observed_at`, and `resolved_at` is updated on
-- whichever path closes the hole first (backfill or rebroadcast).
-- ---------------------------------------------------------------------------

CREATE TABLE control_holes (
  id                bigserial NOT NULL,
  cluster           bytea NOT NULL,                 -- 20-byte cluster diamond address
  missing_nonce     bigint NOT NULL,                -- the nonce we're stuck waiting for
  highest_buffered  bigint NOT NULL,                -- highest nonce currently in the buffer (stuck-on telemetry)
  reason            text NOT NULL,                  -- 'buffer_expired' | 'buffer_full' | 'manual'
  observed_at       timestamptz NOT NULL DEFAULT now(),
  resolved_at       timestamptz,                    -- NULL while the hole is open
  PRIMARY KEY (id)
);

CREATE UNIQUE INDEX control_holes_cluster_nonce_idx
  ON control_holes (cluster, missing_nonce);

CREATE INDEX control_holes_open_idx
  ON control_holes (cluster, observed_at)
  WHERE resolved_at IS NULL;

-- ---------------------------------------------------------------------------
-- LISTEN channel: chain_indexer_control
--
-- Mirror of the existing `chain_indexer_events` fan-out (see
-- `crates/core/src/store.rs::notify` and
-- `crates/server/src/sse.rs::spawn_listen_worker`) but scoped to
-- control-plane events. The ingestor writes the row to
-- `control_instructions` / `control_acks` first, then fires a
-- `pg_notify` on this channel so downstream subscribers (the SSE
-- handler in Track D3, the hub log-fetch worker in Track F2) wake up
-- without polling. Payload shape mirrors the generic NotifyEvent —
-- a small JSON object the consumer rehydrates back into a typed row.
-- The full row stays in Postgres so the 8000-byte NOTIFY safe-limit
-- is never a concern.
--
-- The channel is created implicitly by the first NOTIFY; nothing to
-- declare here. Documented in this provision script so operators
-- searching for the channel name find it alongside the schema.
-- ---------------------------------------------------------------------------

-- Sequence access for chain_indexer_reader. Earlier revisions wrote
-- `IN SCHEMA chain_indexer`, which silently broke the script — no
-- `chain_indexer` schema exists; tables live in `public`. The
-- `ALTER DEFAULT PRIVILEGES` block above already covers SELECTs on
-- sequences created later; this explicit GRANT covers the bigserial
-- the events table created when this script ran. Keep both: the
-- ALTER handles future sequences, the GRANT handles already-created
-- ones.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO chain_indexer_reader;
