//! `alloy::sol!` bindings for the TeeSQL contracts (cluster diamond
//! factory + cluster diamond) and `Decoder` implementations that turn
//! raw logs into typed event payloads written to `events.decoded`.
//!
//! The `Decoder` trait is defined in `crates/core/src/decode.rs`;
//! re-exported here for ergonomic `use teesql_chain_indexer_abi::Decoder`.

pub mod cluster_diamond;
pub mod encoding;
pub mod factory;

pub use teesql_chain_indexer_core::decode::Decoder;

use cluster_diamond::{
    ClusterDestroyedDecoder, LeaderClaimedDecoder, MemberRegisteredDecoder, MemberRetiredDecoder,
    PublicEndpointUpdatedDecoder,
};
use factory::ClusterDeployedDecoder;

/// Every `Decoder` implementation in this crate, in a fixed order
/// suitable for registering with the ingest dispatcher.
///
/// The ingest worker keys this list by `topic0()` to build a
/// `HashMap<[u8;32], Box<dyn Decoder>>` for O(1) lookup per log.
/// Order is irrelevant once it's hashed; deterministic order is
/// kept here purely so test assertions on the returned vec are
/// stable.
pub fn all_decoders() -> Vec<Box<dyn Decoder>> {
    vec![
        Box::new(ClusterDeployedDecoder),
        Box::new(MemberRegisteredDecoder),
        Box::new(LeaderClaimedDecoder),
        Box::new(PublicEndpointUpdatedDecoder),
        Box::new(MemberRetiredDecoder),
        Box::new(ClusterDestroyedDecoder),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_decoders_have_unique_topic0() {
        let mut seen = HashSet::new();
        for d in all_decoders() {
            assert!(seen.insert(d.topic0()), "duplicate topic0 for {}", d.kind());
        }
    }

    #[test]
    fn all_decoders_have_unique_kinds() {
        let mut seen = HashSet::new();
        for d in all_decoders() {
            assert!(seen.insert(d.kind()), "duplicate kind {}", d.kind());
        }
    }

    #[test]
    fn all_decoders_count_matches_spec() {
        // 1 factory event + 5 cluster-diamond events = 6 decoders.
        assert_eq!(all_decoders().len(), 6);
    }
}
