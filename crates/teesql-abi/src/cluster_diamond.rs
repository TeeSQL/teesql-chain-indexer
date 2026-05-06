//! `ClusterDiamond` event bindings + decoders.
//!
//! Source of truth: `open-source/teesql-group-auth/src/interfaces/ICore.sol`
//! (CoreFacet emit-site declarations) and `AdminFacet.sol` for the
//! lifecycle events. Control-plane events (`ControlInstructionBroadcast`,
//! `ControlAck`) are sourced from `IControlPlane.sol` (Track A1) and
//! their canonical Rust binding lives in
//! `crates/common/src/cluster_app.rs` in the parent monorepo — the
//! `sol!` block below mirrors those signatures so the indexer can
//! decode logs without depending on the parent crate.
//!
//! Bound subset (one decoder each):
//! - `MemberRegistered(bytes32, address, address, string)`
//! - `LeaderClaimed(bytes32, uint256, bytes)` — both indexed args first
//! - `PublicEndpointUpdated(bytes32, bytes)`
//! - `MemberRetired(bytes32, uint256)`
//! - `ClusterDestroyed(uint256)`
//! - `ControlInstructionBroadcast(bytes32, bytes32, uint64, bytes32[], uint64, bytes32, bytes32, bytes)`
//! - `ControlAck(bytes32, bytes32, bytes32, uint8, uint64, bytes32, bytes)`
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

use crate::encoding::{
    address_to_json, bytes32_array_to_json, bytes32_to_json, bytes_to_json, uint256_to_json,
    uint64_to_json, uint8_to_json,
};
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

        /// Spec docs/specs/control-plane-redesign.md §5.3.
        /// Mirrors `crates/common/src/cluster_app.rs` (parent monorepo).
        event ControlInstructionBroadcast(
            bytes32 indexed instructionId,
            bytes32 indexed clusterId,
            uint64  indexed nonce,
            bytes32[] targetMembers,
            uint64 expiry,
            bytes32 salt,
            bytes32 ciphertextHash,
            bytes ciphertext
        );

        /// Spec docs/specs/control-plane-redesign.md §5.3.
        /// Mirrors `crates/common/src/cluster_app.rs` (parent monorepo).
        event ControlAck(
            bytes32 indexed instructionId,
            bytes32 indexed jobId,
            bytes32 indexed memberId,
            uint8 status,
            uint64 seq,
            bytes32 logPointer,
            bytes summary
        );
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

// ---------------------------------------------------------------------------
// ControlInstructionBroadcast
//
// Spec docs/specs/control-plane-redesign.md §5.3. Emitted by the
// `ControlPlane` facet when the cluster-owner Safe broadcasts an
// encrypted instruction to one or more members. The decoder here
// produces the JSON payload that the indexer's `Ingestor::process_log`
// integration (Track A4) will pick up and INSERT into the dedicated
// `control_instructions` table — distinct from the generic `events`
// row, since downstream consumers (the per-cluster `ControlOrderer`,
// hub audit log, control sidecar SSE subscriber) want strongly-typed
// columns rather than fishing through `decoded` JSON for every nonce
// lookup.
// ---------------------------------------------------------------------------

pub struct ControlInstructionBroadcastDecoder;

impl Decoder for ControlInstructionBroadcastDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::ControlInstructionBroadcast::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "ControlInstructionBroadcast"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamond::ControlInstructionBroadcast::decode_log(&log.inner)
            .context("decode ControlInstructionBroadcast log")?;
        Ok(json!({
            "instructionId":   bytes32_to_json(&decoded.instructionId),
            "clusterId":       bytes32_to_json(&decoded.clusterId),
            "nonce":           uint64_to_json(decoded.nonce),
            "targetMembers":   bytes32_array_to_json(&decoded.targetMembers),
            "expiry":          uint64_to_json(decoded.expiry),
            "salt":            bytes32_to_json(&decoded.salt),
            "ciphertextHash":  bytes32_to_json(&decoded.ciphertextHash),
            "ciphertext":      bytes_to_json(&decoded.ciphertext),
            "_topic0":         bytes32_to_json(&IClusterDiamond::ControlInstructionBroadcast::SIGNATURE_HASH),
            "_signature":      IClusterDiamond::ControlInstructionBroadcast::SIGNATURE,
        }))
    }
}

// ---------------------------------------------------------------------------
// ControlAck
//
// Spec docs/specs/control-plane-redesign.md §5.3. Each member emits at
// minimum two acks per (instructionId, jobId): an `ACCEPTED` (status=1)
// followed by a terminal status. `seq` is monotonic per
// (jobId, memberId) so the dispatcher / hub can reorder out-of-order
// indexer deliveries. The decoder runs ahead of the dedicated
// `control_acks` table insert in `Ingestor::process_log`.
// ---------------------------------------------------------------------------

pub struct ControlAckDecoder;

impl Decoder for ControlAckDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::ControlAck::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "ControlAck"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded =
            IClusterDiamond::ControlAck::decode_log(&log.inner).context("decode ControlAck log")?;
        Ok(json!({
            "instructionId": bytes32_to_json(&decoded.instructionId),
            "jobId":         bytes32_to_json(&decoded.jobId),
            "memberId":      bytes32_to_json(&decoded.memberId),
            "status":        uint8_to_json(decoded.status),
            "seq":           uint64_to_json(decoded.seq),
            "logPointer":    bytes32_to_json(&decoded.logPointer),
            "summary":       bytes_to_json(&decoded.summary),
            "_topic0":       bytes32_to_json(&IClusterDiamond::ControlAck::SIGNATURE_HASH),
            "_signature":    IClusterDiamond::ControlAck::SIGNATURE,
        }))
    }
}
