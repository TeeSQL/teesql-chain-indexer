//! `ClusterDiamond` event bindings + decoders.
//!
//! Source of truth: `open-source/teesql-group-auth/src/interfaces/ICore.sol`
//! (CoreFacet emit-site declarations) and `AdminFacet.sol` for the
//! lifecycle events.
//!
//! Bound subset (one decoder each):
//! - `MemberRegistered(bytes32, address, address, string)`
//! - `LeaderClaimed(bytes32, uint256, bytes)` — both indexed args first
//! - `PublicEndpointUpdated(bytes32, bytes)`
//! - `MemberRetired(bytes32, uint256)`
//! - `ClusterDestroyed(uint256)`
//!
//! `EndpointUpdated`, `OnboardingPosted`, `MemberPassthroughCreated`,
//! and `InstanceBindingVerified` exist on the diamond but are out of
//! scope for the indexer's materialized views (cluster_leader,
//! cluster_members, cluster_lifecycle); they would be additional
//! `Decoder` impls in the same crate when needed.

use alloy::rpc::types::Log;
use alloy::sol;
use alloy::sol_types::SolEvent;
use anyhow::Context;
use serde_json::{json, Value};

use crate::encoding::{address_to_json, bytes32_to_json, bytes_to_json, uint256_to_json};
use teesql_chain_indexer_core::decode::Decoder;

sol! {
    #[sol(rpc)]
    contract IClusterDiamond {
        event MemberRegistered(
            bytes32 indexed memberId,
            address indexed instanceId,
            address indexed passthrough,
            string dnsLabel
        );
        event LeaderClaimed(
            bytes32 indexed memberId,
            uint256 indexed epoch,
            bytes endpoint
        );
        event PublicEndpointUpdated(
            bytes32 indexed memberId,
            bytes publicEndpoint
        );
        event MemberRetired(
            bytes32 indexed memberId,
            uint256 timestamp
        );
        event ClusterDestroyed(uint256 timestamp);
    }
}

// ---------------------------------------------------------------------------
// MemberRegistered
// ---------------------------------------------------------------------------

pub struct MemberRegisteredDecoder;

impl Decoder for MemberRegisteredDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::MemberRegistered::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "MemberRegistered"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamond::MemberRegistered::decode_log(&log.inner)
            .context("decode MemberRegistered log")?;
        Ok(json!({
            "memberId":    bytes32_to_json(&decoded.memberId),
            "instanceId":  address_to_json(&decoded.instanceId),
            "passthrough": address_to_json(&decoded.passthrough),
            "dnsLabel":    decoded.dnsLabel.clone(),
            "_topic0":     bytes32_to_json(&IClusterDiamond::MemberRegistered::SIGNATURE_HASH),
            "_signature":  IClusterDiamond::MemberRegistered::SIGNATURE,
        }))
    }
}

// ---------------------------------------------------------------------------
// LeaderClaimed
// ---------------------------------------------------------------------------

pub struct LeaderClaimedDecoder;

impl Decoder for LeaderClaimedDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::LeaderClaimed::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "LeaderClaimed"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamond::LeaderClaimed::decode_log(&log.inner)
            .context("decode LeaderClaimed log")?;
        Ok(json!({
            "memberId":   bytes32_to_json(&decoded.memberId),
            "epoch":      uint256_to_json(&decoded.epoch),
            "endpoint":   bytes_to_json(&decoded.endpoint),
            "_topic0":    bytes32_to_json(&IClusterDiamond::LeaderClaimed::SIGNATURE_HASH),
            "_signature": IClusterDiamond::LeaderClaimed::SIGNATURE,
        }))
    }
}

// ---------------------------------------------------------------------------
// PublicEndpointUpdated
// ---------------------------------------------------------------------------

pub struct PublicEndpointUpdatedDecoder;

impl Decoder for PublicEndpointUpdatedDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::PublicEndpointUpdated::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "PublicEndpointUpdated"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamond::PublicEndpointUpdated::decode_log(&log.inner)
            .context("decode PublicEndpointUpdated log")?;
        Ok(json!({
            "memberId":       bytes32_to_json(&decoded.memberId),
            "publicEndpoint": bytes_to_json(&decoded.publicEndpoint),
            "_topic0":        bytes32_to_json(&IClusterDiamond::PublicEndpointUpdated::SIGNATURE_HASH),
            "_signature":     IClusterDiamond::PublicEndpointUpdated::SIGNATURE,
        }))
    }
}

// ---------------------------------------------------------------------------
// MemberRetired
// ---------------------------------------------------------------------------

pub struct MemberRetiredDecoder;

impl Decoder for MemberRetiredDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::MemberRetired::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "MemberRetired"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamond::MemberRetired::decode_log(&log.inner)
            .context("decode MemberRetired log")?;
        Ok(json!({
            "memberId":   bytes32_to_json(&decoded.memberId),
            "timestamp":  uint256_to_json(&decoded.timestamp),
            "_topic0":    bytes32_to_json(&IClusterDiamond::MemberRetired::SIGNATURE_HASH),
            "_signature": IClusterDiamond::MemberRetired::SIGNATURE,
        }))
    }
}

// ---------------------------------------------------------------------------
// ClusterDestroyed
// ---------------------------------------------------------------------------

pub struct ClusterDestroyedDecoder;

impl Decoder for ClusterDestroyedDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::ClusterDestroyed::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "ClusterDestroyed"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamond::ClusterDestroyed::decode_log(&log.inner)
            .context("decode ClusterDestroyed log")?;
        Ok(json!({
            "timestamp":  uint256_to_json(&decoded.timestamp),
            "_topic0":    bytes32_to_json(&IClusterDiamond::ClusterDestroyed::SIGNATURE_HASH),
            "_signature": IClusterDiamond::ClusterDestroyed::SIGNATURE,
        }))
    }
}
