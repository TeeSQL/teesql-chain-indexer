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
//! - `MemberWgPubkeySet(bytes32, string)` — fabric mesh WG pubkey registry
//!   (Phase 1 of fabric cross-boundary; source: WgMeshFacet.sol)
//! - `MemberWgPubkeySetV2(bytes32, bytes32, bytes32)` — attested admission
//!   event for the unified network design (`docs/designs/network-architecture-unified.md`
//!   §4.1, §9.1). Carries the raw 32-byte WG pubkey alongside a
//!   `quoteHash = keccak256(tdxQuote)` commitment.
//! - `ComposeHashAllowed(bytes32)` / `ComposeHashRemoved(bytes32)` —
//!   MRTD allowlist mutations (`AdminFacet`, source: IAdmin.sol §§4.2).
//!   Note: `composeHash` is NOT indexed on the contract side per
//!   IAdmin.sol L12-13; the decoder reflects the wire layout the
//!   contracts actually emit.
//! - `TcbDegraded(bytes32, uint8)` — periodic re-verify alert
//!   (`docs/designs/network-architecture-unified.md` §6.3, §7).
//!   Alert-only — fabric does not auto-evict. Bound here ahead of the
//!   on-chain emit so the indexer is ready when the contract surface
//!   ships the event.
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

        /// Emitted by `WgMeshFacet.setMemberWgPubkey` whenever a member
        /// publishes (or rotates) its WireGuard pubkey. Fabric reads the
        /// indexer's materialized `cluster_members.wg_pubkey_hex` column
        /// + SSE stream to discover peers and bring up wg0.
        event MemberWgPubkeySet(bytes32 indexed memberId, string wgPubkeyHex);

        /// V2 attested admission event per unified-network-design §4.1:
        /// `setMemberWgPubkeyAttested` validates a TDX quote on-chain
        /// and emits this event carrying the raw `wgPubkey` plus
        /// `quoteHash = keccak256(tdxQuote)`. Fabric verifies
        /// `keccak256(retrievedQuote) == quoteHash` before extending
        /// trust, so substituting a quote requires a hash collision.
        event MemberWgPubkeySetV2(
            bytes32 indexed memberId,
            bytes32 wgPubkey,
            bytes32 quoteHash
        );

        /// Compose-hash allowlist add (unified-network-design §4.2).
        /// `composeHash` is NOT indexed in `IAdmin.sol` (line 12) — the
        /// contract emits the bytes32 in the data slot, so the decoder
        /// must mirror that layout.
        event ComposeHashAllowed(bytes32 composeHash);

        /// Compose-hash allowlist remove (unified-network-design §4.2).
        /// Non-indexed for the same reason as `ComposeHashAllowed`.
        /// Fabric invalidates cached PASS verdicts whose `mrtd ==
        /// composeHash` on observing this event.
        event ComposeHashRemoved(bytes32 composeHash);

        /// Periodic TCB re-verify alert (unified-network-design §6.3,
        /// §7). Alert-only signal — fabric records the severity but
        /// does not auto-evict. Hard eviction is Safe-signed.
        ///
        /// Severity is a `uint8` enum tracked in the design doc:
        ///   1 = warn      (e.g. UpToDate → ConfigurationNeeded)
        ///   2 = critical  (e.g. * → Revoked)
        event TcbDegraded(bytes32 indexed memberId, uint8 severity);
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

// ---------------------------------------------------------------------------
// MemberWgPubkeySet
//
// Source: `open-source/teesql-group-auth/src/facets/WgMeshFacet.sol`.
// The fabric crate consumes this both via the materialized
// `cluster_members.wg_pubkey_hex` REST column and the SSE
// `member_wg_pubkey_set` stream to keep wg0 in sync with the chain.
// ---------------------------------------------------------------------------

pub struct MemberWgPubkeySetDecoder;

impl Decoder for MemberWgPubkeySetDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::MemberWgPubkeySet::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "MemberWgPubkeySet"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamond::MemberWgPubkeySet::decode_log(&log.inner)
            .context("decode MemberWgPubkeySet log")?;
        Ok(json!({
            "memberId":     bytes32_to_json(&decoded.memberId),
            "wgPubkeyHex":  decoded.wgPubkeyHex.clone(),
            "_topic0":      bytes32_to_json(&IClusterDiamond::MemberWgPubkeySet::SIGNATURE_HASH),
            "_signature":   IClusterDiamond::MemberWgPubkeySet::SIGNATURE,
        }))
    }
}

// ---------------------------------------------------------------------------
// MemberWgPubkeySetV2
//
// Source: unified-network-design §4.1 + §5. Carries `wgPubkey` as raw
// 32-byte Curve25519 + `quoteHash = keccak256(tdxQuote)`. Coexists with
// the V1 `MemberWgPubkeySet` decoder: V1 ships a hex-string pubkey,
// V2 ships raw bytes32 + a quote-hash commitment. Fabric prefers V2 if
// both are present for the same member, but the indexer treats them as
// independent event streams — neither subsumes the other in the
// materialized table because they describe different trust layers.
// ---------------------------------------------------------------------------

pub struct MemberWgPubkeySetV2Decoder;

impl Decoder for MemberWgPubkeySetV2Decoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::MemberWgPubkeySetV2::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "MemberWgPubkeySetV2"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamond::MemberWgPubkeySetV2::decode_log(&log.inner)
            .context("decode MemberWgPubkeySetV2 log")?;
        Ok(json!({
            "memberId":   bytes32_to_json(&decoded.memberId),
            "wgPubkey":   bytes32_to_json(&decoded.wgPubkey),
            "quoteHash":  bytes32_to_json(&decoded.quoteHash),
            "_topic0":    bytes32_to_json(&IClusterDiamond::MemberWgPubkeySetV2::SIGNATURE_HASH),
            "_signature": IClusterDiamond::MemberWgPubkeySetV2::SIGNATURE,
        }))
    }
}

// ---------------------------------------------------------------------------
// ComposeHashAllowed / ComposeHashRemoved
//
// Source: IAdmin.sol §§4.2. Both non-indexed on the contract side
// (the keccak256 cost of `indexed bytes32` on a frequently-mutated
// allowlist wasn't worth the topic-filter convenience), so the
// composeHash field arrives in the data slot. Fabric subscribes to
// the pair and treats `Allowed` as monotonic-add and `Removed` as
// monotonic-remove; replaying the full event history reconstructs
// the live allowlist.
// ---------------------------------------------------------------------------

pub struct ComposeHashAllowedDecoder;

impl Decoder for ComposeHashAllowedDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::ComposeHashAllowed::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "ComposeHashAllowed"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamond::ComposeHashAllowed::decode_log(&log.inner)
            .context("decode ComposeHashAllowed log")?;
        Ok(json!({
            "composeHash": bytes32_to_json(&decoded.composeHash),
            "_topic0":     bytes32_to_json(&IClusterDiamond::ComposeHashAllowed::SIGNATURE_HASH),
            "_signature":  IClusterDiamond::ComposeHashAllowed::SIGNATURE,
        }))
    }
}

pub struct ComposeHashRemovedDecoder;

impl Decoder for ComposeHashRemovedDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::ComposeHashRemoved::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "ComposeHashRemoved"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamond::ComposeHashRemoved::decode_log(&log.inner)
            .context("decode ComposeHashRemoved log")?;
        Ok(json!({
            "composeHash": bytes32_to_json(&decoded.composeHash),
            "_topic0":     bytes32_to_json(&IClusterDiamond::ComposeHashRemoved::SIGNATURE_HASH),
            "_signature":  IClusterDiamond::ComposeHashRemoved::SIGNATURE,
        }))
    }
}

// ---------------------------------------------------------------------------
// TcbDegraded
//
// Source: unified-network-design §6.3 / §7. Emitted on periodic
// re-verify when a member's TCB status drops out of the policy
// envelope. Alert signal only — fabric tracks the latest severity
// per member but does not auto-evict.
// ---------------------------------------------------------------------------

pub struct TcbDegradedDecoder;

impl Decoder for TcbDegradedDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamond::TcbDegraded::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "TcbDegraded"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamond::TcbDegraded::decode_log(&log.inner)
            .context("decode TcbDegraded log")?;
        Ok(json!({
            "memberId":   bytes32_to_json(&decoded.memberId),
            "severity":   uint8_to_json(decoded.severity),
            "_topic0":    bytes32_to_json(&IClusterDiamond::TcbDegraded::SIGNATURE_HASH),
            "_signature": IClusterDiamond::TcbDegraded::SIGNATURE,
        }))
    }
}
