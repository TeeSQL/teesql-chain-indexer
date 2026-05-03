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
-- Partitioned by 100k-block ranges so we can drop very old partitions
-- without a slow DELETE if retention pressure ever shows up. Sub-partition
-- by chain_id at the LIST level so multi-chain writes don't hot-spot.
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
) PARTITION BY RANGE (block_number);

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

-- TODO: spec §5 references chain_indexer schema while tables are in public; flagged for spec-reconcile.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA chain_indexer TO chain_indexer_reader;
