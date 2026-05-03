//! Decoder trait + DecodedEvent. Spec §6.2 step 3.
//!
//! The trait is deliberately tiny: each implementation knows one event
//! signature (`topic0`), names it (`kind`), and turns a raw alloy [`Log`]
//! into a `serde_json::Value` payload that downstream views materialise.
//!
//! Core does not define any concrete decoders. TeeSQL's `teesql-abi`
//! crate brings the `sol!` bindings; other consumers can plug their own
//! decoders against the same trait.

use std::collections::HashMap;

use alloy::primitives::B256;
use alloy::rpc::types::Log;

/// Decoder for a single event signature.
///
/// `decode` is called only when `topic0()` matches `log.topics()[0]`, so
/// implementations can rely on that invariant — no need to re-check the
/// signature inside the function body.
pub trait Decoder: Send + Sync {
    /// keccak256(event_signature). Drives the dispatch map in the
    /// ingest loop.
    fn topic0(&self) -> [u8; 32];

    /// Stable, human-readable name persisted as `events.decoded_kind`
    /// (e.g. `"MemberRegistered"`). Used as a filter key in the read API
    /// (`?kind=MemberRegistered,LeaderClaimed`) and by views to dispatch
    /// on event type.
    fn kind(&self) -> &'static str;

    /// Turn the raw log into a JSON payload. The shape is opaque to core;
    /// views downstream agree with their paired decoder on the schema.
    fn decode(&self, log: &Log) -> anyhow::Result<serde_json::Value>;
}

/// Raw log + decoder output, normalised to the byte shapes the Postgres
/// store expects (no alloy types in `store.rs` signatures so callers can
/// build `DecodedEvent`s by hand in tests).
#[derive(Debug, Clone)]
pub struct DecodedEvent {
    pub chain_id: i32,
    pub contract: [u8; 20],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub log_index: i32,
    pub tx_hash: [u8; 32],
    pub topic0: [u8; 32],
    /// topics[1..] concatenated. Empty if the event is anonymous or has
    /// only `topic0`. Stored verbatim so consumers can re-derive the
    /// indexed argument values without us picking a particular ABI.
    pub topics_rest: Vec<u8>,
    pub data: Vec<u8>,
    /// `None` when no decoder matched `topic0`; the raw row is still
    /// persisted so a future decoder added in a later release can
    /// backfill `decoded_kind`/`decoded` by replaying the table.
    pub kind: Option<String>,
    pub decoded: Option<serde_json::Value>,
}

impl DecodedEvent {
    /// Build a `DecodedEvent` from an alloy [`Log`], looking up the
    /// matching decoder by `topic0`. Returns `Err` when the log is
    /// missing fields the persistence layer needs (block_hash,
    /// block_number, log_index, transaction_hash) — those are always
    /// populated for confirmed/subscription logs but `Option` in the
    /// alloy type because pending logs share the struct.
    pub fn from_log(
        chain_id: i32,
        log: &Log,
        decoders: &HashMap<[u8; 32], Box<dyn Decoder>>,
    ) -> anyhow::Result<Self> {
        let block_number = log
            .block_number
            .ok_or_else(|| anyhow::anyhow!("log missing block_number"))?;
        let block_hash = log
            .block_hash
            .ok_or_else(|| anyhow::anyhow!("log missing block_hash"))?;
        let tx_hash = log
            .transaction_hash
            .ok_or_else(|| anyhow::anyhow!("log missing transaction_hash"))?;
        let log_index = log
            .log_index
            .ok_or_else(|| anyhow::anyhow!("log missing log_index"))?;

        let topics: &[B256] = log.topics();
        let topic0_b256 = *topics
            .first()
            .ok_or_else(|| anyhow::anyhow!("anonymous log has no topic0"))?;
        let topic0: [u8; 32] = topic0_b256.0;

        // topics[1..] concatenated. Each topic is 32 bytes; reserving up
        // front avoids the three-allocations-as-we-grow that `extend` on
        // an empty Vec would do.
        let mut topics_rest = Vec::with_capacity((topics.len().saturating_sub(1)) * 32);
        for t in topics.iter().skip(1) {
            topics_rest.extend_from_slice(t.as_slice());
        }

        let (kind, decoded) = match decoders.get(&topic0) {
            Some(dec) => match dec.decode(log) {
                Ok(v) => (Some(dec.kind().to_string()), Some(v)),
                Err(e) => {
                    tracing::warn!(
                        topic0 = %hex::encode(topic0),
                        kind = dec.kind(),
                        error = %e,
                        "decoder failed; persisting raw event with NULL decoded payload"
                    );
                    (None, None)
                }
            },
            None => (None, None),
        };

        Ok(Self {
            chain_id,
            contract: log.address().0 .0,
            block_number,
            block_hash: block_hash.0,
            log_index: i32::try_from(log_index)
                .map_err(|_| anyhow::anyhow!("log_index {log_index} overflows i32"))?,
            tx_hash: tx_hash.0,
            topic0,
            topics_rest,
            data: log.data().data.to_vec(),
            kind,
            decoded,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivial decoder for unit tests — pretends every event with the
    /// configured `topic0` is "Ping" and returns its hex-encoded data.
    struct PingDecoder {
        topic0_bytes: [u8; 32],
    }

    impl Decoder for PingDecoder {
        fn topic0(&self) -> [u8; 32] {
            self.topic0_bytes
        }
        fn kind(&self) -> &'static str {
            "Ping"
        }
        fn decode(&self, log: &Log) -> anyhow::Result<serde_json::Value> {
            Ok(serde_json::json!({
                "data_hex": hex::encode(&log.data().data),
            }))
        }
    }

    #[test]
    fn decoder_trait_object_is_send_sync() {
        // Compile-time check: Box<dyn Decoder> must be Send + Sync so
        // it can live inside the Ingestor across awaits.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn Decoder>>();
    }

    #[test]
    fn ping_decoder_topic0_round_trip() {
        let topic0 = [0x42u8; 32];
        let dec = PingDecoder {
            topic0_bytes: topic0,
        };
        assert_eq!(dec.topic0(), topic0);
        assert_eq!(dec.kind(), "Ping");
    }
}
