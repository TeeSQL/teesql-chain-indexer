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
    ClusterDestroyedDecoder, ComposeHashAllowedDecoder, ComposeHashRemovedDecoder,
    ControlAckDecoder, ControlInstructionBroadcastDecoder, LeaderClaimedDecoder,
    MemberRegisteredDecoder, MemberRetiredDecoder, MemberWgPubkeySetDecoder,
    MemberWgPubkeySetV2Decoder, PublicEndpointUpdatedDecoder, TcbDegradedDecoder,
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
        Box::new(ControlInstructionBroadcastDecoder),
        Box::new(ControlAckDecoder),
        Box::new(MemberWgPubkeySetDecoder),
        Box::new(MemberWgPubkeySetV2Decoder),
        Box::new(ComposeHashAllowedDecoder),
        Box::new(ComposeHashRemovedDecoder),
        Box::new(TcbDegradedDecoder),
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
        // 1 factory event + 5 lifecycle/membership cluster-diamond
        // events + 2 control-plane events + 1 V1 WG-mesh event +
        // 4 unified-network-design V2 events (MemberWgPubkeySetV2,
        // ComposeHashAllowed, ComposeHashRemoved, TcbDegraded)
        // = 13 decoders.
        assert_eq!(all_decoders().len(), 13);
    }

    /// Pin `MemberWgPubkeySet` decoder presence so a future
    /// `all_decoders()` shuffle that drops the registration trips
    /// here instead of silently letting fabric's mesh discovery
    /// drift off chain.
    #[test]
    fn all_decoders_includes_member_wg_pubkey_set() {
        let kinds: Vec<&'static str> = all_decoders().iter().map(|d| d.kind()).collect();
        assert!(
            kinds.contains(&"MemberWgPubkeySet"),
            "all_decoders() must register MemberWgPubkeySet: {kinds:?}"
        );
    }

    /// Pin the control-plane decoders' presence in `all_decoders()`
    /// by `kind()` so a future re-shuffle of the vec layout (or a
    /// regression that drops a `Box::new`) trips this test instead
    /// of silently leaving the new tables empty in production.
    #[test]
    fn all_decoders_includes_control_plane_pair() {
        let kinds: Vec<&'static str> = all_decoders().iter().map(|d| d.kind()).collect();
        assert!(
            kinds.contains(&"ControlInstructionBroadcast"),
            "all_decoders() must register ControlInstructionBroadcast: {kinds:?}"
        );
        assert!(
            kinds.contains(&"ControlAck"),
            "all_decoders() must register ControlAck: {kinds:?}"
        );
    }

    /// Pin the unified-network-design V2 decoders so a regression
    /// that drops any of them surfaces here rather than as silent
    /// missing rows in fabric's admission cache + allowlist views.
    #[test]
    fn all_decoders_includes_v2_unified_network_set() {
        let kinds: Vec<&'static str> = all_decoders().iter().map(|d| d.kind()).collect();
        for expected in [
            "MemberWgPubkeySetV2",
            "ComposeHashAllowed",
            "ComposeHashRemoved",
            "TcbDegraded",
        ] {
            assert!(
                kinds.contains(&expected),
                "all_decoders() must register {expected}: {kinds:?}"
            );
        }
    }
}
