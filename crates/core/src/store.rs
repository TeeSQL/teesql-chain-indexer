//! sqlx Postgres event sink. Spec §5 schema, §6 ingest pipeline.
//!
//! Every method is idempotent: an event ingested twice (WS replay,
//! cold-start overlap with steady-state) hits the
//! `(chain_id, contract, block_hash, log_index)` unique index and
//! becomes a no-op. The unique index is defined in `provision.sql`
//! as `events_dedup_idx` — every `INSERT` here references it via
//! `ON CONFLICT (...) DO NOTHING`.
//!
//! Byte conversions: every `[u8; 32]` / `[u8; 20]` argument lands in
//! Postgres as `bytea` via `&[u8]`, and reads come back as `Vec<u8>`
//! through the `as_addr` / `as_hash` helpers below. Keeping the byte
//! shape on the API surface (rather than alloy primitives) lets
//! callers build rows without dragging alloy through their tests.

use serde_json::Value as JsonValue;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::decode::DecodedEvent;

/// Postgres-backed event log. Owns the connection pool. One instance
/// per `(process, chain_id)` pair — the `chain_id` discriminator
/// scopes every query so multiple indexer processes can share one
/// database without coordination.
#[derive(Clone)]
pub struct EventStore {
    pool: PgPool,
    chain_id: i32,
}

/// Watched-contract registry row. Populated from config (factories) and
/// from `ClusterDeployed` decoding (per-cluster diamonds). Drives both
/// the cold-start backfill loop and the gas-webhook `contains?` query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedContract {
    pub address: [u8; 20],
    pub kind: String,
    pub parent: Option<[u8; 20]>,
    pub from_block: u64,
}

impl EventStore {
    /// Open a store against an already-built pool. Connection details
    /// (RA-TLS, role, credentials) live in `connection.rs`.
    ///
    /// `new` does not run migrations — `provision.sql` lives outside
    /// the binary and is operator-applied per spec §3.1.
    pub async fn new(pool: PgPool, chain_id: i32) -> anyhow::Result<Self> {
        Ok(Self { pool, chain_id })
    }

    /// Direct pool handle — Agent 6's SSE handler `LISTEN`s on it
    /// outside of any EventStore method, and reads from the read API
    /// hit it for the historical-replay path.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn chain_id(&self) -> i32 {
        self.chain_id
    }

    /// Upsert a `blocks` row. Returns the previously-stored hash when
    /// the row already existed AND the hash differs — the caller (the
    /// reorg handler) treats `Some(prev)` as the trigger to walk back
    /// and find a common ancestor. Returns `None` on first-write or
    /// when the hash matches what was already stored.
    ///
    /// Index used: PK `(chain_id, number)`.
    pub async fn upsert_block(
        &self,
        number: u64,
        hash: [u8; 32],
        parent_hash: [u8; 32],
        block_ts: i64,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        let number_i64 = i64::try_from(number)
            .map_err(|_| anyhow::anyhow!("block number {number} overflows i64"))?;

        // Two-step: SELECT the existing row, then INSERT / UPDATE.
        // We need the previous hash if it differed; an INSERT ... ON
        // CONFLICT ... RETURNING can't surface "the value before the
        // overwrite", so the read-then-write pattern is unavoidable.
        // The PK index makes each side a single B-tree probe.
        let prev: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT hash FROM blocks WHERE chain_id = $1 AND number = $2")
                .bind(self.chain_id)
                .bind(number_i64)
                .fetch_optional(&self.pool)
                .await?;

        let prev_hash = match prev.as_deref() {
            Some(bytes) if bytes == hash.as_slice() => None,
            Some(bytes) => Some(as_hash(bytes)?),
            None => None,
        };

        sqlx::query(
            "INSERT INTO blocks (chain_id, number, hash, parent_hash, block_ts) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (chain_id, number) DO UPDATE \
                SET hash = EXCLUDED.hash, \
                    parent_hash = EXCLUDED.parent_hash, \
                    block_ts = EXCLUDED.block_ts",
        )
        .bind(self.chain_id)
        .bind(number_i64)
        .bind(&hash[..])
        .bind(&parent_hash[..])
        .bind(block_ts)
        .execute(&self.pool)
        .await?;

        Ok(prev_hash)
    }

    /// Look up a block hash by number. Used by the reorg handler when
    /// walking back to find a common ancestor.
    ///
    /// Index used: PK `(chain_id, number)`.
    pub async fn block_hash_at(&self, number: u64) -> anyhow::Result<Option<[u8; 32]>> {
        let number_i64 = i64::try_from(number)
            .map_err(|_| anyhow::anyhow!("block number {number} overflows i64"))?;
        let row: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT hash FROM blocks WHERE chain_id = $1 AND number = $2")
                .bind(self.chain_id)
                .bind(number_i64)
                .fetch_optional(&self.pool)
                .await?;
        row.map(|b| as_hash(&b)).transpose()
    }

    /// Insert one event. Returns the assigned `id` on first write,
    /// `None` when the row already existed (idempotent under WS
    /// replay).
    ///
    /// Index used: unique `events_dedup_idx (chain_id, contract,
    /// block_hash, log_index)` for the conflict target. The
    /// `RETURNING id` only fires on a true insert; on conflict it
    /// returns no rows and we report `None`.
    pub async fn insert_event(&self, ev: &DecodedEvent) -> anyhow::Result<Option<i64>> {
        if ev.chain_id != self.chain_id {
            anyhow::bail!(
                "event chain_id {} does not match store chain_id {}",
                ev.chain_id,
                self.chain_id
            );
        }
        let block_number_i64 = i64::try_from(ev.block_number)
            .map_err(|_| anyhow::anyhow!("block number {} overflows i64", ev.block_number))?;
        let id: Option<i64> = sqlx::query_scalar(
            "INSERT INTO events (\
                 chain_id, contract, block_number, block_hash, log_index, \
                 tx_hash, topic0, topics_rest, data, decoded_kind, decoded\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (chain_id, contract, block_hash, log_index) DO NOTHING \
             RETURNING id",
        )
        .bind(ev.chain_id)
        .bind(&ev.contract[..])
        .bind(block_number_i64)
        .bind(&ev.block_hash[..])
        .bind(ev.log_index)
        .bind(&ev.tx_hash[..])
        .bind(&ev.topic0[..])
        .bind(&ev.topics_rest[..])
        .bind(&ev.data[..])
        .bind(ev.kind.as_deref())
        .bind(ev.decoded.as_ref())
        .fetch_optional(&self.pool)
        .await?;
        Ok(id)
    }

    /// Mark every event with `block_number > common_ancestor` as
    /// `removed = true`. Returns the count of rows flipped. Reorg
    /// orchestration then re-applies surviving events forward via the
    /// `View.apply()` path.
    ///
    /// Index used: PK `(chain_id, block_number, id)` — the
    /// `block_number > $2` predicate is the high-selectivity term.
    pub async fn mark_removed_after(&self, common_ancestor_block: u64) -> anyhow::Result<u64> {
        let n_i64 = i64::try_from(common_ancestor_block)
            .map_err(|_| anyhow::anyhow!("block {common_ancestor_block} overflows i64"))?;
        let result = sqlx::query(
            "UPDATE events \
             SET removed = true \
             WHERE chain_id = $1 AND block_number > $2 AND removed = false",
        )
        .bind(self.chain_id)
        .bind(n_i64)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Fire `pg_notify('chain_indexer_events', payload)`. The SSE
    /// handler in the server crate `LISTEN`s on this channel.
    ///
    /// Postgres caps notification payloads at 8000 bytes by default;
    /// we send the small `NotifyEvent` shape (cluster + kind +
    /// event_id) and let consumers fetch the full row by id.
    pub async fn notify(&self, payload: &JsonValue) -> anyhow::Result<()> {
        let payload_str = serde_json::to_string(payload)?;
        if payload_str.len() > 7900 {
            anyhow::bail!(
                "notify payload {} bytes exceeds Postgres NOTIFY safe limit",
                payload_str.len()
            );
        }
        // pg_notify(channel, payload) is parameterised, so the payload
        // can carry any UTF-8 (including JSON quotes) without escaping.
        sqlx::query("SELECT pg_notify('chain_indexer_events', $1)")
            .bind(payload_str)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Fire `pg_notify('chain_indexer_control', payload)`. Track A4.
    /// Twin of `notify` for the control-plane fan-out — the per-cluster
    /// `ControlOrderer` (Track D1) + hub log-fetch worker (Track F2)
    /// `LISTEN` on this channel. Same 8000-byte safe-limit guard as
    /// the generic events channel.
    pub async fn notify_control(&self, payload: &JsonValue) -> anyhow::Result<()> {
        let payload_str = serde_json::to_string(payload)?;
        if payload_str.len() > 7900 {
            anyhow::bail!(
                "notify_control payload {} bytes exceeds Postgres NOTIFY safe limit",
                payload_str.len()
            );
        }
        sqlx::query("SELECT pg_notify('chain_indexer_control', $1)")
            .bind(payload_str)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Insert a `ControlInstructionBroadcast` row. Returns the assigned
    /// `id` on first write, `None` when the unique
    /// `(cluster, nonce) WHERE removed=false` index swallows the
    /// duplicate (idempotent under WS replay / cold-start overlap).
    /// Spec §5.3.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_control_instruction(
        &self,
        cluster: [u8; 20],
        instruction_id: [u8; 32],
        nonce: u64,
        target_members: &[[u8; 32]],
        expiry: u64,
        salt: [u8; 32],
        ciphertext: &[u8],
        ciphertext_hash: [u8; 32],
        block_number: u64,
        log_index: i32,
        tx_hash: [u8; 32],
    ) -> anyhow::Result<Option<i64>> {
        let nonce_i64 =
            i64::try_from(nonce).map_err(|_| anyhow::anyhow!("nonce {nonce} overflows i64"))?;
        let expiry_i64 =
            i64::try_from(expiry).map_err(|_| anyhow::anyhow!("expiry {expiry} overflows i64"))?;
        let block_number_i64 = i64::try_from(block_number)
            .map_err(|_| anyhow::anyhow!("block_number {block_number} overflows i64"))?;

        // bytea[] passes through sqlx as `Vec<Vec<u8>>`. Materialise
        // the heap array once so the bind site doesn't capture a slice
        // reference into a temporary. Empty array = "broadcast to all
        // members" per spec §5.6 — preserve the empty shape rather
        // than coercing to NULL.
        let target_members_owned: Vec<Vec<u8>> =
            target_members.iter().map(|m| m.to_vec()).collect();

        let id: Option<i64> = sqlx::query_scalar(
            "INSERT INTO control_instructions (\
                 cluster, instruction_id, nonce, target_members, \
                 expiry, salt, ciphertext, ciphertext_hash, \
                 block_number, log_index, tx_hash\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (cluster, nonce) WHERE removed = false DO NOTHING \
             RETURNING id",
        )
        .bind(&cluster[..])
        .bind(&instruction_id[..])
        .bind(nonce_i64)
        .bind(target_members_owned)
        .bind(expiry_i64)
        .bind(&salt[..])
        .bind(ciphertext)
        .bind(&ciphertext_hash[..])
        .bind(block_number_i64)
        .bind(log_index)
        .bind(&tx_hash[..])
        .fetch_optional(&self.pool)
        .await?;
        Ok(id)
    }

    /// Insert a `ControlAck` row. Returns the assigned `id` on first
    /// write, `None` when the unique `(cluster, job_id, seq) WHERE
    /// removed=false` index swallows the duplicate. Spec §5.3 / §8.1.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_control_ack(
        &self,
        cluster: [u8; 20],
        instruction_id: [u8; 32],
        job_id: [u8; 32],
        member_id: [u8; 32],
        status: u8,
        seq: u64,
        log_pointer: Option<[u8; 32]>,
        summary: Option<&[u8]>,
        block_number: u64,
        log_index: i32,
        tx_hash: [u8; 32],
    ) -> anyhow::Result<Option<i64>> {
        let seq_i64 = i64::try_from(seq).map_err(|_| anyhow::anyhow!("seq {seq} overflows i64"))?;
        let block_number_i64 = i64::try_from(block_number)
            .map_err(|_| anyhow::anyhow!("block_number {block_number} overflows i64"))?;
        let log_pointer_bytes: Option<&[u8]> = log_pointer.as_ref().map(|p| &p[..]);

        let id: Option<i64> = sqlx::query_scalar(
            "INSERT INTO control_acks (\
                 cluster, instruction_id, job_id, member_id, status, \
                 seq, log_pointer, summary, block_number, log_index, \
                 tx_hash\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (cluster, job_id, seq) WHERE removed = false DO NOTHING \
             RETURNING id",
        )
        .bind(&cluster[..])
        .bind(&instruction_id[..])
        .bind(&job_id[..])
        .bind(&member_id[..])
        .bind(i16::from(status))
        .bind(seq_i64)
        .bind(log_pointer_bytes)
        .bind(summary)
        .bind(block_number_i64)
        .bind(log_index)
        .bind(&tx_hash[..])
        .fetch_optional(&self.pool)
        .await?;
        Ok(id)
    }

    /// Mark every control-plane row past the common ancestor as
    /// `removed = true`. Mirrors the per-event `mark_removed_after`
    /// path so the reorg handler in `Ingestor::handle_reorg` can
    /// roll back instructions + acks alongside the generic events
    /// table without leaving stale control rows visible.
    pub async fn mark_control_removed_after(
        &self,
        common_ancestor_block: u64,
    ) -> anyhow::Result<u64> {
        let n_i64 = i64::try_from(common_ancestor_block)
            .map_err(|_| anyhow::anyhow!("block {common_ancestor_block} overflows i64"))?;
        // Two updates rather than a CTE so each table's row count is
        // visible in tracing for debugging stuck reorg replays. The
        // queries are cheap (small index range scan over recent
        // blocks) so the round-trip cost is negligible.
        let instr = sqlx::query(
            "UPDATE control_instructions \
             SET removed = true \
             WHERE block_number > $1 AND removed = false",
        )
        .bind(n_i64)
        .execute(&self.pool)
        .await?;
        let acks = sqlx::query(
            "UPDATE control_acks \
             SET removed = true \
             WHERE block_number > $1 AND removed = false",
        )
        .bind(n_i64)
        .execute(&self.pool)
        .await?;
        Ok(instr.rows_affected() + acks.rows_affected())
    }

    /// Read the per-contract cursor. Returns 0 when absent so the
    /// caller can treat first-time contracts uniformly.
    ///
    /// Index used: PK `(chain_id, contract)`.
    pub async fn cursor(&self, contract: [u8; 20]) -> anyhow::Result<u64> {
        let row: Option<i64> = sqlx::query_scalar(
            "SELECT next_block FROM ingest_cursor \
             WHERE chain_id = $1 AND contract = $2",
        )
        .bind(self.chain_id)
        .bind(&contract[..])
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(n) if n < 0 => anyhow::bail!("cursor for contract has negative next_block: {n}"),
            Some(n) => Ok(n as u64),
            None => Ok(0),
        }
    }

    /// Advance the cursor. Idempotent — moving backwards is rejected
    /// to prevent reprocessing in steady state. (Reorg rollback uses
    /// `mark_removed_after` + targeted re-apply, not cursor rewind.)
    ///
    /// Index used: PK `(chain_id, contract)`.
    pub async fn advance_cursor(&self, contract: [u8; 20], next_block: u64) -> anyhow::Result<()> {
        let next_i64 = i64::try_from(next_block)
            .map_err(|_| anyhow::anyhow!("next_block {next_block} overflows i64"))?;
        sqlx::query(
            "INSERT INTO ingest_cursor (chain_id, contract, next_block) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (chain_id, contract) DO UPDATE \
                SET next_block = GREATEST(ingest_cursor.next_block, EXCLUDED.next_block)",
        )
        .bind(self.chain_id)
        .bind(&contract[..])
        .bind(next_i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Set a `chain_state` KV pair. Used for `head_block`,
    /// `finalized_block`, `last_subscription_seq`.
    pub async fn set_state(&self, key: &str, val: &str) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO chain_state (chain_id, k, v) VALUES ($1, $2, $3) \
             ON CONFLICT (chain_id, k) DO UPDATE \
                SET v = EXCLUDED.v, updated_at = now()",
        )
        .bind(self.chain_id)
        .bind(key)
        .bind(val)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Read a `chain_state` KV pair.
    pub async fn get_state(&self, key: &str) -> anyhow::Result<Option<String>> {
        let row: Option<String> =
            sqlx::query_scalar("SELECT v FROM chain_state WHERE chain_id = $1 AND k = $2")
                .bind(self.chain_id)
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row)
    }

    /// Look up a cached historical-query result by composite key.
    /// Returns the (payload, attestation envelope) pair when present.
    ///
    /// Index used: PK `(chain_id, cluster_address, endpoint,
    /// as_of_block)`.
    pub async fn cache_get(
        &self,
        cluster: [u8; 20],
        endpoint: &str,
        as_of_block: u64,
    ) -> anyhow::Result<Option<(JsonValue, JsonValue)>> {
        let n_i64 = i64::try_from(as_of_block)
            .map_err(|_| anyhow::anyhow!("as_of_block {as_of_block} overflows i64"))?;
        let row = sqlx::query(
            "SELECT payload, attestation FROM historical_query_cache \
             WHERE chain_id = $1 AND cluster_address = $2 \
               AND endpoint = $3 AND as_of_block = $4",
        )
        .bind(self.chain_id)
        .bind(&cluster[..])
        .bind(endpoint)
        .bind(n_i64)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r: PgRow| {
            (
                r.get::<JsonValue, _>("payload"),
                r.get::<JsonValue, _>("attestation"),
            )
        }))
    }

    /// Insert / replace a cached historical-query response.
    pub async fn cache_put(
        &self,
        cluster: [u8; 20],
        endpoint: &str,
        as_of_block: u64,
        payload: JsonValue,
        attestation: JsonValue,
    ) -> anyhow::Result<()> {
        let n_i64 = i64::try_from(as_of_block)
            .map_err(|_| anyhow::anyhow!("as_of_block {as_of_block} overflows i64"))?;
        sqlx::query(
            "INSERT INTO historical_query_cache \
                 (chain_id, cluster_address, endpoint, as_of_block, payload, attestation) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (chain_id, cluster_address, endpoint, as_of_block) DO UPDATE \
                SET payload = EXCLUDED.payload, \
                    attestation = EXCLUDED.attestation, \
                    cached_at = now()",
        )
        .bind(self.chain_id)
        .bind(&cluster[..])
        .bind(endpoint)
        .bind(n_i64)
        .bind(payload)
        .bind(attestation)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Register a watched contract. Idempotent — re-registering with a
    /// later `from_block` does NOT overwrite (we want the earliest
    /// known block as the backfill anchor).
    ///
    /// Index used: PK `(chain_id, address)`.
    pub async fn add_watched_contract(
        &self,
        address: [u8; 20],
        kind: &str,
        parent: Option<[u8; 20]>,
        from_block: u64,
    ) -> anyhow::Result<()> {
        let from_i64 = i64::try_from(from_block)
            .map_err(|_| anyhow::anyhow!("from_block {from_block} overflows i64"))?;
        let parent_bytes: Option<&[u8]> = parent.as_ref().map(|p| &p[..]);
        sqlx::query(
            "INSERT INTO watched_contracts (chain_id, address, kind, parent, from_block) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (chain_id, address) DO NOTHING",
        )
        .bind(self.chain_id)
        .bind(&address[..])
        .bind(kind)
        .bind(parent_bytes)
        .bind(from_i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// List every watched contract for this chain. Used by the
    /// cold-start loop, by the WS subscription filter builder, and
    /// (read-only) by the gas-webhook `contains?` endpoint.
    ///
    /// Index used: PK; partial scan over a small table (one row per
    /// factory + per cluster diamond — single thousands at fleet
    /// scale, not millions).
    pub async fn list_watched_contracts(&self) -> anyhow::Result<Vec<WatchedContract>> {
        let rows = sqlx::query(
            "SELECT address, kind, parent, from_block \
             FROM watched_contracts \
             WHERE chain_id = $1 \
             ORDER BY from_block ASC, address ASC",
        )
        .bind(self.chain_id)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let address_bytes: Vec<u8> = row.get("address");
            let kind: String = row.get("kind");
            let parent_bytes: Option<Vec<u8>> = row.get("parent");
            let from_block: i64 = row.get("from_block");
            out.push(WatchedContract {
                address: as_addr(&address_bytes)?,
                kind,
                parent: parent_bytes.map(|b| as_addr(&b)).transpose()?,
                from_block: u64::try_from(from_block)
                    .map_err(|_| anyhow::anyhow!("watched.from_block {from_block} negative"))?,
            });
        }
        Ok(out)
    }
}

/// Convert a Postgres `bytea` payload into a 20-byte address. Returns
/// an error rather than panicking so a corrupt row surfaces as a
/// caller-visible failure instead of a process crash.
pub fn as_addr(bytes: &[u8]) -> anyhow::Result<[u8; 20]> {
    let arr: [u8; 20] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("bytea length {} != 20 (address)", bytes.len()))?;
    Ok(arr)
}

/// Convert a Postgres `bytea` payload into a 32-byte hash.
pub fn as_hash(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("bytea length {} != 32 (hash)", bytes.len()))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_addr_roundtrip() {
        let raw = [0x55u8; 20];
        assert_eq!(as_addr(&raw).unwrap(), raw);
    }

    #[test]
    fn as_addr_rejects_wrong_length() {
        let raw = [0u8; 19];
        assert!(as_addr(&raw).is_err());
        let raw = [0u8; 21];
        assert!(as_addr(&raw).is_err());
    }

    #[test]
    fn as_hash_roundtrip() {
        let raw = [0xaau8; 32];
        assert_eq!(as_hash(&raw).unwrap(), raw);
    }

    #[test]
    fn as_hash_rejects_wrong_length() {
        let raw = [0u8; 31];
        assert!(as_hash(&raw).is_err());
    }

    #[test]
    fn watched_contract_eq_excludes_added_at() {
        // Sanity: WatchedContract is the comparable surface — there's
        // no `added_at` field on it, so two reads that produce the
        // same registry shape compare equal regardless of write time.
        let a = WatchedContract {
            address: [1u8; 20],
            kind: "factory".into(),
            parent: None,
            from_block: 100,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
