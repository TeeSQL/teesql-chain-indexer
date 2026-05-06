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
  registered_at    bigint,                     -- block timestamp
  retired_at       bigint,                     -- NULL = active
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, cluster_address, member_id)
);

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
