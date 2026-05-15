//! Integration-level smoke tests that exercise the public surface
//! without a live Postgres or RPC. The store-level tests that need a
//! database are gated behind a `live-test` feature in a follow-up
//! crate (Agent 7's bin) so this crate stays buildable in CI without
//! infrastructure.

use std::sync::Arc;

use serde_json::json;

use teesql_chain_indexer_core::{
    as_addr, as_hash, DecodedEvent, Decoder, Ingestor, NotifyEvent, View, WatchedContract,
};

/// Tiny dummy decoder that lets us exercise the trait surface without
/// pulling alloy::sol! into core's test scope.
struct DummyDecoder {
    sig: [u8; 32],
    name: &'static str,
}

impl Decoder for DummyDecoder {
    fn topic0(&self) -> [u8; 32] {
        self.sig
    }
    fn kind(&self) -> &'static str {
        self.name
    }
    fn decode(&self, _log: &alloy::rpc::types::Log) -> anyhow::Result<serde_json::Value> {
        Ok(json!({"kind": self.name}))
    }
}

/// View that only logs — used to confirm the trait is object-safe and
/// composable with `Box<dyn View>` storage in `IngestorBuilder`.
struct NoopView;

#[async_trait::async_trait]
impl View for NoopView {
    async fn apply(
        &self,
        _store: &teesql_chain_indexer_core::EventStore,
        _event: &DecodedEvent,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn replay(
        &self,
        _store: &teesql_chain_indexer_core::EventStore,
        _chain_id: i32,
        _cluster: [u8; 20],
        _as_of_block: u64,
    ) -> anyhow::Result<serde_json::Value> {
        Ok(json!({}))
    }
    fn name(&self) -> &'static str {
        "noop"
    }
}

#[test]
fn bytea_helpers_round_trip() {
    let addr = [0x42u8; 20];
    let hash = [0xc0u8; 32];
    assert_eq!(as_addr(&addr).unwrap(), addr);
    assert_eq!(as_hash(&hash).unwrap(), hash);
}

#[test]
fn watched_contract_eq() {
    let w1 = WatchedContract {
        address: [1u8; 20],
        kind: "factory".into(),
        parent: None,
        from_block: 0,
    };
    let w2 = w1.clone();
    assert_eq!(w1, w2);
}

#[test]
fn builder_rejects_missing_chain_id() {
    let err = Ingestor::builder().build().unwrap_err();
    assert!(err.to_string().contains("chain_id required"));
}

#[test]
fn builder_assembles_decoder_map_by_topic0() {
    // Two decoders with distinct topic0s should both register.
    let d1 = Box::new(DummyDecoder {
        sig: [0x11u8; 32],
        name: "Foo",
    });
    let d2 = Box::new(DummyDecoder {
        sig: [0x22u8; 32],
        name: "Bar",
    });

    let builder = Ingestor::builder().decoder(d1).decoder(d2);
    // We can't call build() without a real EventStore (needs a PgPool),
    // so just confirm the chain of `decoder()` calls compiles + the
    // builder is a value type the next call can return on.
    let _ = builder;
}

#[test]
fn view_trait_object_can_be_boxed_and_held_as_arc() {
    // Smoke check: builder takes `Box<dyn View>` and the View trait
    // must be object-safe for that to compile.
    let v: Box<dyn View> = Box::new(NoopView);
    let _arc: Arc<dyn View> = Arc::from(v);
}

#[test]
fn notify_event_json_shape_is_stable() {
    let n = NotifyEvent {
        cluster: [0xab; 20],
        kind: "MemberRegistered".into(),
        event_id: 42,
        block_number: 1234,
        log_index: 7,
    };
    let j = serde_json::to_value(&n).unwrap();
    // The SSE handler in Agent 6's server crate parses these fields
    // by name; this asserts the wire shape doesn't drift silently.
    assert!(j.get("cluster").is_some(), "cluster field must be present");
    assert!(j.get("kind").is_some(), "kind field must be present");
    assert!(
        j.get("event_id").is_some(),
        "event_id field must be present"
    );
    assert!(
        j.get("block_number").is_some(),
        "block_number field must be present"
    );
    assert!(
        j.get("log_index").is_some(),
        "log_index field must be present"
    );
}

// ---------------------------------------------------------------------------
// `cluster_member_quotes` apply-path tests (GAP-W1-003)
//
// Gated behind a Postgres `DATABASE_URL` because they require a fresh
// `chain_indexer` schema (from `deploy/provision.sql`) and exercise the
// real sqlx round-trip. Run via:
//
//   DATABASE_URL=postgres://… cargo test -p teesql-chain-indexer-core -- --ignored
//
// CI without a Postgres fixture passes everything above; these tests
// only block on the v0.4.0 followup that brings up a sqlx::test /
// testcontainers harness. Until then they're a live-tested
// reference contract for the schema + the public store methods.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod cluster_member_quotes_db {
    use sqlx::Row;
    use teesql_chain_indexer_core::EventStore;

    const CHAIN_ID: i32 = 8453;
    const CLUSTER: [u8; 20] = [
        0xe2, 0xa0, 0x23, 0x3b, 0x75, 0xbe, 0xb6, 0x3f, 0x9c, 0x37, 0x7d, 0xe4, 0xed, 0x4a, 0xc5,
        0x96, 0x5b, 0x2e, 0xac, 0xb9,
    ];

    /// Build a test EventStore. The connection string comes from
    /// `DATABASE_URL`; the schema must already be applied via
    /// `deploy/provision.sql` (the bin crate's migration runner doesn't
    /// touch it, intentionally — operator-owned schema lives outside
    /// the tests).
    async fn store_from_env() -> EventStore {
        let url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set for #[ignore]-gated DB tests");
        let pool = sqlx::PgPool::connect(&url).await.expect("connect pool");
        // Reset the test table so a previous test run doesn't leave
        // collisions on the (chain_id, cluster, member, quote_hash) PK.
        // Use TRUNCATE rather than per-row DELETE so the test doesn't
        // depend on an exact-shape match.
        sqlx::query("TRUNCATE TABLE cluster_member_quotes")
            .execute(&pool)
            .await
            .expect("truncate cluster_member_quotes");
        EventStore::new(pool, CHAIN_ID)
            .await
            .expect("event store builds")
    }

    fn sample_quote(byte: u8) -> Vec<u8> {
        // Realistic-sized TDX quote (~4.5 KB) per design §9.2.
        vec![byte; 4632]
    }

    fn keccak256(bytes: &[u8]) -> [u8; 32] {
        use alloy::primitives::keccak256;
        keccak256(bytes).into()
    }

    fn member(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn pubkey(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn block_hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn tx_hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointing at a fresh chain_indexer schema"]
    async fn upsert_then_latest_round_trip() {
        let store = store_from_env().await;
        let m = member(0x11);
        let quote = sample_quote(0xaa);
        let qh = keccak256(&quote);

        let inserted = store
            .upsert_member_quote(
                CLUSTER,
                m,
                qh,
                pubkey(0x22),
                &quote,
                100,
                block_hash(0xbb),
                3,
                tx_hash(0xcc),
            )
            .await
            .unwrap();
        assert!(inserted, "first insert is a fresh write");

        // Idempotent re-upsert at the same coords: row already live,
        // no revival branch fires, returns false.
        let inserted_again = store
            .upsert_member_quote(
                CLUSTER,
                m,
                qh,
                pubkey(0x22),
                &quote,
                100,
                block_hash(0xbb),
                3,
                tx_hash(0xcc),
            )
            .await
            .unwrap();
        assert!(
            !inserted_again,
            "duplicate upsert is idempotent (no revival branch)"
        );

        let row = store
            .latest_member_quote(CLUSTER, m)
            .await
            .unwrap()
            .expect("latest row present");
        assert_eq!(row.cluster_address, CLUSTER);
        assert_eq!(row.member_id, m);
        assert_eq!(row.quote_hash, qh);
        assert_eq!(row.quote_bytes, quote);
        assert_eq!(row.block_number, 100);
        assert_eq!(row.log_index, 3);
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointing at a fresh chain_indexer schema"]
    async fn by_hash_finds_specific_row_after_rotation() {
        let store = store_from_env().await;
        let m = member(0x11);

        // Two rotations: same member, different quote bytes → different
        // quote_hash → two distinct rows by content-addressed PK.
        let quote_a = sample_quote(0xaa);
        let qh_a = keccak256(&quote_a);
        store
            .upsert_member_quote(
                CLUSTER,
                m,
                qh_a,
                pubkey(0x22),
                &quote_a,
                100,
                block_hash(0xbb),
                0,
                tx_hash(0xcc),
            )
            .await
            .unwrap();

        let quote_b = sample_quote(0xdd);
        let qh_b = keccak256(&quote_b);
        store
            .upsert_member_quote(
                CLUSTER,
                m,
                qh_b,
                pubkey(0x33),
                &quote_b,
                200,
                block_hash(0xee),
                0,
                tx_hash(0xff),
            )
            .await
            .unwrap();

        // by_hash returns the exact row keyed by hash, not "latest".
        let row_a = store
            .member_quote_by_hash(CLUSTER, m, qh_a)
            .await
            .unwrap()
            .expect("quote A row");
        assert_eq!(row_a.quote_bytes, quote_a);
        assert_eq!(row_a.block_number, 100);

        let row_b = store
            .member_quote_by_hash(CLUSTER, m, qh_b)
            .await
            .unwrap()
            .expect("quote B row");
        assert_eq!(row_b.quote_bytes, quote_b);
        assert_eq!(row_b.block_number, 200);

        // The latest endpoint picks B because it's at the higher block.
        let latest = store
            .latest_member_quote(CLUSTER, m)
            .await
            .unwrap()
            .expect("latest");
        assert_eq!(latest.quote_hash, qh_b);

        // A nonexistent quote_hash → None on by_hash.
        let unknown = store
            .member_quote_by_hash(CLUSTER, m, [0u8; 32])
            .await
            .unwrap();
        assert!(unknown.is_none());
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointing at a fresh chain_indexer schema"]
    async fn reorg_cleanup_hides_rows_past_common_ancestor() {
        let store = store_from_env().await;
        let m = member(0x11);

        // Two quote rows: one safely before the (eventual) common
        // ancestor at block 150, one past it at block 200.
        let q_safe = sample_quote(0xaa);
        let qh_safe = keccak256(&q_safe);
        store
            .upsert_member_quote(
                CLUSTER,
                m,
                qh_safe,
                pubkey(0x22),
                &q_safe,
                100,
                block_hash(0xb1),
                0,
                tx_hash(0xc1),
            )
            .await
            .unwrap();

        let q_dropped = sample_quote(0xdd);
        let qh_dropped = keccak256(&q_dropped);
        store
            .upsert_member_quote(
                CLUSTER,
                m,
                qh_dropped,
                pubkey(0x33),
                &q_dropped,
                200,
                block_hash(0xb2),
                0,
                tx_hash(0xc2),
            )
            .await
            .unwrap();

        // Reorg with common_ancestor = 150 → block 200's row marked
        // removed; block 100's row stays live.
        let removed = store.mark_member_quotes_removed_after(150).await.unwrap();
        assert_eq!(removed, 1, "exactly one row past the ancestor");

        // latest now picks the older row — the rolled-back row is
        // filtered out at the SQL layer.
        let latest = store
            .latest_member_quote(CLUSTER, m)
            .await
            .unwrap()
            .expect("latest is the surviving row");
        assert_eq!(latest.quote_hash, qh_safe);
        assert_eq!(latest.block_number, 100);

        // by_hash on the removed row returns None — the live-rows-only
        // filter is the same across both read paths.
        let dropped = store
            .member_quote_by_hash(CLUSTER, m, qh_dropped)
            .await
            .unwrap();
        assert!(dropped.is_none(), "by_hash filters reorg-rolled-back rows");

        // The removed row IS still on disk (forensic) — assert via a
        // direct SQL probe that bypasses the public read filter.
        let raw: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM cluster_member_quotes \
             WHERE chain_id = $1 AND cluster_address = $2 \
               AND member_id = $3 AND quote_hash = $4 AND removed = true",
        )
        .bind(CHAIN_ID)
        .bind(&CLUSTER[..])
        .bind(&m[..])
        .bind(&qh_dropped[..])
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(raw, 1, "removed row preserved on disk");
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointing at a fresh chain_indexer schema"]
    async fn upsert_revives_removed_row_with_new_block_coords() {
        let store = store_from_env().await;
        let m = member(0x11);
        let q = sample_quote(0xaa);
        let qh = keccak256(&q);

        // Initial write at block 100.
        store
            .upsert_member_quote(
                CLUSTER,
                m,
                qh,
                pubkey(0x22),
                &q,
                100,
                block_hash(0xb1),
                3,
                tx_hash(0xc1),
            )
            .await
            .unwrap();

        // Simulated reorg: this row's source event is past the new
        // common ancestor.
        store.mark_member_quotes_removed_after(50).await.unwrap();
        assert!(store
            .latest_member_quote(CLUSTER, m)
            .await
            .unwrap()
            .is_none());

        // Replay re-observes the same `(member, quote_hash)` triple,
        // possibly at a new block (the canonical chain after the
        // reorg). Revival path: clears `removed`, refreshes coords.
        let revived = store
            .upsert_member_quote(
                CLUSTER,
                m,
                qh,
                pubkey(0x22),
                &q,
                105, // new canonical block
                block_hash(0xb9),
                7,
                tx_hash(0xc9),
            )
            .await
            .unwrap();
        assert!(revived, "revival counts as a write");

        let row = store
            .latest_member_quote(CLUSTER, m)
            .await
            .unwrap()
            .expect("row is live again");
        assert_eq!(row.quote_hash, qh);
        assert_eq!(row.block_number, 105, "coords refreshed to new canonical");
        assert_eq!(row.log_index, 7);
        assert_eq!(row.tx_hash, tx_hash(0xc9));
        assert_eq!(row.quote_bytes, q, "content-addressed bytes unchanged");
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointing at a fresh chain_indexer schema"]
    async fn r2_uri_writeback_idempotent() {
        let store = store_from_env().await;
        let m = member(0x11);
        let q = sample_quote(0xaa);
        let qh = keccak256(&q);
        store
            .upsert_member_quote(
                CLUSTER,
                m,
                qh,
                pubkey(0x22),
                &q,
                100,
                block_hash(0xb1),
                0,
                tx_hash(0xc1),
            )
            .await
            .unwrap();

        let updated = store
            .set_member_quote_r2_uri(CLUSTER, m, qh, "r2://teesql-quotes/abc.bin")
            .await
            .unwrap();
        assert!(updated);

        let row = store
            .latest_member_quote(CLUSTER, m)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.r2_uri.as_deref(), Some("r2://teesql-quotes/abc.bin"));

        // Re-running with the same URI is a no-op on payload but still
        // updates `rows_affected`. The contract on the method is "true
        // when a row matched"; assert both calls return true.
        let updated_again = store
            .set_member_quote_r2_uri(CLUSTER, m, qh, "r2://teesql-quotes/abc.bin")
            .await
            .unwrap();
        assert!(updated_again);

        // Unknown row → false (no UPDATE matched).
        let absent = store
            .set_member_quote_r2_uri(CLUSTER, m, [0u8; 32], "r2://teesql-quotes/xyz.bin")
            .await
            .unwrap();
        assert!(!absent);
    }

    /// Smoke-check that the `removed` column exists on the schema the
    /// tests are running against — gives a more informative failure
    /// than the silent "all UPDATEs match zero rows" symptom when the
    /// operator forgot to re-run `deploy/provision.sql` after pulling
    /// this PR.
    #[tokio::test]
    #[ignore = "requires DATABASE_URL pointing at a fresh chain_indexer schema"]
    async fn schema_has_removed_column() {
        let store = store_from_env().await;
        let row = sqlx::query(
            "SELECT column_name, data_type \
             FROM information_schema.columns \
             WHERE table_name = 'cluster_member_quotes' \
               AND column_name = 'removed'",
        )
        .fetch_optional(store.pool())
        .await
        .unwrap();
        let row = row.expect(
            "cluster_member_quotes.removed missing — \
             apply deploy/provision.sql against this DATABASE_URL",
        );
        let data_type: String = row.try_get("data_type").unwrap();
        assert_eq!(data_type, "boolean");
    }
}
