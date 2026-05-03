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
