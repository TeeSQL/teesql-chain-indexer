//! End-to-end fixture tests, one per bound event.
//!
//! Each test builds a synthetic `alloy::rpc::types::Log` whose
//! `topics` and `data` match the on-chain wire layout (indexed args
//! in `topics[1..]`, non-indexed args in `data`), routes it through
//! the matching `Decoder`, and asserts the decoded JSON equals the
//! hand-written expected `serde_json::Value`.
//!
//! The wire layout itself is produced by alloy's `sol!` types via
//! `MyEvent::encode_data()`, so a drift between our binding and the
//! actual contract ABI surfaces here as a `decode_log` failure or a
//! mismatched JSON shape.

use alloy::primitives::{Address, Bytes, FixedBytes, LogData, U256};
use alloy::rpc::types::Log as RpcLog;
use alloy::sol_types::SolEvent;
use serde_json::json;

use teesql_chain_indexer_abi::cluster_diamond::{
    ClusterDestroyedDecoder, ComposeHashAddedDecoder, ComposeHashAllowedDecoder,
    ComposeHashRemovedDecoder, IClusterDiamond, LeaderClaimedDecoder, MemberRegisteredDecoder,
    MemberRetiredDecoder, MemberWgPubkeySetV2Decoder, PublicEndpointUpdatedDecoder,
    TcbDegradedDecoder,
};
use teesql_chain_indexer_abi::factory::{ClusterDeployedDecoder, IClusterDiamondFactory};
use teesql_chain_indexer_abi::Decoder;

/// Wrap a synthesized `alloy::primitives::Log` in the rpc-types
/// envelope the `Decoder` trait consumes. All chain-context fields
/// (block_hash, log_index, etc.) are irrelevant for decoder logic
/// and stay `None`.
fn make_rpc_log(topics: Vec<FixedBytes<32>>, data: Vec<u8>) -> RpcLog {
    let inner = alloy::primitives::Log {
        address: Address::ZERO,
        data: LogData::new_unchecked(topics, Bytes::from(data)),
    };
    RpcLog {
        inner,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// ClusterDeployed (factory) — three indexed args, no data payload
// ---------------------------------------------------------------------------

#[test]
fn cluster_deployed_decodes_to_expected_json() {
    let diamond: Address = "0xfBd65E6b30f40db87159A5d3a390Fc9C2bd87E11"
        .parse()
        .unwrap();
    let deployer: Address = "0xd9f3803a0aFCec138D338aC29e66B2FEdd4edfE3"
        .parse()
        .unwrap();
    let salt = FixedBytes::<32>::from([0x77u8; 32]);

    // All three args are indexed → topics carry every field; data is empty.
    let topics = vec![
        IClusterDiamondFactory::ClusterDeployed::SIGNATURE_HASH,
        diamond.into_word(),
        deployer.into_word(),
        salt,
    ];
    let log = make_rpc_log(topics, Vec::new());

    let decoded = ClusterDeployedDecoder.decode(&log).unwrap();
    let expected = json!({
        "diamond":    "0xfbd65e6b30f40db87159a5d3a390fc9c2bd87e11",
        "deployer":   "0xd9f3803a0afcec138d338ac29e66b2fedd4edfe3",
        "salt":       "0x7777777777777777777777777777777777777777777777777777777777777777",
        "_topic0":    format!("0x{}", hex::encode(IClusterDiamondFactory::ClusterDeployed::SIGNATURE_HASH.as_slice())),
        "_signature": "ClusterDeployed(address,address,bytes32)",
    });
    assert_eq!(decoded, expected);
}

// ---------------------------------------------------------------------------
// MemberRegistered — three indexed args + one non-indexed `string`
// ---------------------------------------------------------------------------

#[test]
fn member_registered_decodes_to_expected_json() {
    let member_id = FixedBytes::<32>::from([0x11u8; 32]);
    let instance_id: Address = "0x1111111111111111111111111111111111111111"
        .parse()
        .unwrap();
    let passthrough: Address = "0x2222222222222222222222222222222222222222"
        .parse()
        .unwrap();
    let dns_label = "abc1234567".to_string();

    let topics = vec![
        IClusterDiamond::MemberRegistered::SIGNATURE_HASH,
        member_id,
        instance_id.into_word(),
        passthrough.into_word(),
    ];
    let data = IClusterDiamond::MemberRegistered {
        memberId: member_id,
        instanceId: instance_id,
        passthrough,
        dnsLabel: dns_label.clone(),
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = MemberRegisteredDecoder.decode(&log).unwrap();
    let expected = json!({
        "memberId":    "0x1111111111111111111111111111111111111111111111111111111111111111",
        "instanceId":  "0x1111111111111111111111111111111111111111",
        "passthrough": "0x2222222222222222222222222222222222222222",
        "dnsLabel":    "abc1234567",
        "_topic0":     format!("0x{}", hex::encode(IClusterDiamond::MemberRegistered::SIGNATURE_HASH.as_slice())),
        "_signature":  "MemberRegistered(bytes32,address,address,string)",
    });
    assert_eq!(decoded, expected);
}

// ---------------------------------------------------------------------------
// LeaderClaimed — two indexed args (memberId, epoch) + non-indexed `bytes`
// ---------------------------------------------------------------------------

#[test]
fn leader_claimed_decodes_to_expected_json() {
    let member_id = FixedBytes::<32>::from([0x22u8; 32]);
    let epoch = U256::from(7u64);
    // Cluster-private tailnet endpoint is opaque ciphertext on-chain;
    // a representative non-empty blob exercises the bytes path.
    let endpoint_bytes = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02];

    let topics = vec![
        IClusterDiamond::LeaderClaimed::SIGNATURE_HASH,
        member_id,
        FixedBytes::<32>::from(epoch.to_be_bytes::<32>()),
    ];
    let data = IClusterDiamond::LeaderClaimed {
        memberId: member_id,
        epoch,
        endpoint: Bytes::from(endpoint_bytes.clone()),
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = LeaderClaimedDecoder.decode(&log).unwrap();
    let expected = json!({
        "memberId":   "0x2222222222222222222222222222222222222222222222222222222222222222",
        "epoch":      "7",
        "endpoint":   "0xdeadbeef000102",
        "_topic0":    format!("0x{}", hex::encode(IClusterDiamond::LeaderClaimed::SIGNATURE_HASH.as_slice())),
        "_signature": "LeaderClaimed(bytes32,uint256,bytes)",
    });
    assert_eq!(decoded, expected);
}

// ---------------------------------------------------------------------------
// PublicEndpointUpdated — one indexed arg + non-indexed `bytes`
// ---------------------------------------------------------------------------

#[test]
fn public_endpoint_updated_decodes_to_expected_json() {
    let member_id = FixedBytes::<32>::from([0x33u8; 32]);
    let public_endpoint =
        b"https://aaaabbbbccccddddeeeeffff0011223344556677-5432.dstack-base-prod5.phala.network";

    let topics = vec![
        IClusterDiamond::PublicEndpointUpdated::SIGNATURE_HASH,
        member_id,
    ];
    let data = IClusterDiamond::PublicEndpointUpdated {
        memberId: member_id,
        publicEndpoint: Bytes::from_iter(public_endpoint.iter().copied()),
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = PublicEndpointUpdatedDecoder.decode(&log).unwrap();
    let expected = json!({
        "memberId":       "0x3333333333333333333333333333333333333333333333333333333333333333",
        "publicEndpoint": format!("0x{}", hex::encode(public_endpoint)),
        "_topic0":        format!("0x{}", hex::encode(IClusterDiamond::PublicEndpointUpdated::SIGNATURE_HASH.as_slice())),
        "_signature":     "PublicEndpointUpdated(bytes32,bytes)",
    });
    assert_eq!(decoded, expected);
}

// ---------------------------------------------------------------------------
// MemberRetired — one indexed arg + non-indexed `uint256`
// ---------------------------------------------------------------------------

#[test]
fn member_retired_decodes_to_expected_json() {
    let member_id = FixedBytes::<32>::from([0x44u8; 32]);
    let timestamp = U256::from(1_777_771_500u64);

    let topics = vec![IClusterDiamond::MemberRetired::SIGNATURE_HASH, member_id];
    let data = IClusterDiamond::MemberRetired {
        memberId: member_id,
        timestamp,
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = MemberRetiredDecoder.decode(&log).unwrap();
    let expected = json!({
        "memberId":   "0x4444444444444444444444444444444444444444444444444444444444444444",
        "timestamp":  "1777771500",
        "_topic0":    format!("0x{}", hex::encode(IClusterDiamond::MemberRetired::SIGNATURE_HASH.as_slice())),
        "_signature": "MemberRetired(bytes32,uint256)",
    });
    assert_eq!(decoded, expected);
}

// ---------------------------------------------------------------------------
// ClusterDestroyed — zero indexed args + non-indexed `uint256`
// ---------------------------------------------------------------------------

#[test]
fn cluster_destroyed_decodes_to_expected_json() {
    let timestamp = U256::from(1_777_900_000u64);

    let topics = vec![IClusterDiamond::ClusterDestroyed::SIGNATURE_HASH];
    let data = IClusterDiamond::ClusterDestroyed { timestamp }.encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = ClusterDestroyedDecoder.decode(&log).unwrap();
    let expected = json!({
        "timestamp":  "1777900000",
        "_topic0":    format!("0x{}", hex::encode(IClusterDiamond::ClusterDestroyed::SIGNATURE_HASH.as_slice())),
        "_signature": "ClusterDestroyed(uint256)",
    });
    assert_eq!(decoded, expected);
}

// ---------------------------------------------------------------------------
// MemberWgPubkeySetV2 — one indexed arg + two non-indexed `bytes32`
//
// Unified-network-design §4.1. The contract emits the raw 32-byte WG
// pubkey alongside a `quoteHash = keccak256(tdxQuote)` commitment.
// ---------------------------------------------------------------------------

#[test]
fn member_wg_pubkey_set_v2_decodes_to_expected_json() {
    let member_id = FixedBytes::<32>::from([0x55u8; 32]);
    let wg_pubkey = FixedBytes::<32>::from([0x66u8; 32]);
    let quote_hash = FixedBytes::<32>::from([0x77u8; 32]);

    let topics = vec![
        IClusterDiamond::MemberWgPubkeySetV2::SIGNATURE_HASH,
        member_id,
    ];
    let data = IClusterDiamond::MemberWgPubkeySetV2 {
        memberId: member_id,
        wgPubkey: wg_pubkey,
        quoteHash: quote_hash,
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = MemberWgPubkeySetV2Decoder.decode(&log).unwrap();
    let expected = json!({
        "memberId":   "0x5555555555555555555555555555555555555555555555555555555555555555",
        "wgPubkey":   "0x6666666666666666666666666666666666666666666666666666666666666666",
        "quoteHash":  "0x7777777777777777777777777777777777777777777777777777777777777777",
        "_topic0":    format!("0x{}", hex::encode(IClusterDiamond::MemberWgPubkeySetV2::SIGNATURE_HASH.as_slice())),
        "_signature": "MemberWgPubkeySetV2(bytes32,bytes32,bytes32)",
    });
    assert_eq!(decoded, expected);
}

/// Edge case from the task spec: a zero-byte `quoteHash` (e.g. a
/// degenerate or pre-attestation publish path) must still decode
/// cleanly. The on-chain validator rejects this, but the indexer is
/// downstream of validation and should never refuse to decode a
/// well-formed log payload — that would tank ingestion on a single
/// anomalous row.
#[test]
fn member_wg_pubkey_set_v2_zero_quote_hash_decodes() {
    let member_id = FixedBytes::<32>::from([0xaau8; 32]);
    let wg_pubkey = FixedBytes::<32>::from([0xbbu8; 32]);
    let quote_hash = FixedBytes::<32>::from([0u8; 32]);

    let topics = vec![
        IClusterDiamond::MemberWgPubkeySetV2::SIGNATURE_HASH,
        member_id,
    ];
    let data = IClusterDiamond::MemberWgPubkeySetV2 {
        memberId: member_id,
        wgPubkey: wg_pubkey,
        quoteHash: quote_hash,
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = MemberWgPubkeySetV2Decoder.decode(&log).unwrap();
    assert_eq!(
        decoded["quoteHash"].as_str().unwrap(),
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        decoded["wgPubkey"].as_str().unwrap(),
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
}

/// SSE-consumer contract pin (GAP-W1-003). The by-hash quote REST
/// route requires that an SSE consumer be able to read `quoteHash`
/// from the decoded event payload it pulls via `GET /events/:id`.
/// The full-shape match above (`member_wg_pubkey_set_v2_decodes_to_expected_json`)
/// already pins the JSON keys, but a future refactor that re-orders
/// or renames keys could slip past that test by also re-shaping the
/// `expected` literal. This focused test asserts the
/// SSE-consumer-visible field is named exactly `quoteHash`
/// (camelCase, the on-chain ABI spelling) and that its value is the
/// lowercase 0x-prefixed hex of the bytes32 commitment — exactly the
/// shape the by-hash REST route's `:quote_hash` path segment
/// accepts. Drift here breaks the SSE → by-hash GET handshake at the
/// wire level, so this test is intentionally narrow + load-bearing.
#[test]
fn member_wg_pubkey_set_v2_emits_quote_hash_for_sse_consumers() {
    let member_id = FixedBytes::<32>::from([0xabu8; 32]);
    let wg_pubkey = FixedBytes::<32>::from([0xcdu8; 32]);
    let quote_hash = FixedBytes::<32>::from([0xefu8; 32]);

    let topics = vec![
        IClusterDiamond::MemberWgPubkeySetV2::SIGNATURE_HASH,
        member_id,
    ];
    let data = IClusterDiamond::MemberWgPubkeySetV2 {
        memberId: member_id,
        wgPubkey: wg_pubkey,
        quoteHash: quote_hash,
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = MemberWgPubkeySetV2Decoder.decode(&log).unwrap();

    // Pin the SSE-consumer field name + value shape. A refactor that
    // accidentally renames this to `quote_hash` (snake_case),
    // `commitment`, etc. would silently break every fabric admission
    // path that derives the by-hash URL from the SSE frame.
    let qh = decoded
        .get("quoteHash")
        .and_then(|v| v.as_str())
        .expect("SSE consumers read `quoteHash` from the decoded payload");
    assert_eq!(
        qh, "0xefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
        "quoteHash must be lowercase 0x-prefixed hex of the bytes32 commitment"
    );
    // The same SSE consumer also reads `memberId` to build the
    // `.../members/:member_id/quote/:quote_hash` path. Pin its shape
    // too so a co-renamed pair would still trip.
    assert_eq!(
        decoded.get("memberId").and_then(|v| v.as_str()).unwrap(),
        "0xabababababababababababababababababababababababababababababababab"
    );
}

/// Two events emitted with identical payloads (a contract idempotency
/// edge case caught by WS replay) must each decode to the same JSON.
/// The indexer's `(chain_id, contract, block_hash, log_index)`
/// dedup index catches the duplicate at the persistence layer; here
/// we pin that decoding is itself pure-functional — no hidden state
/// makes the second decode differ.
#[test]
fn member_wg_pubkey_set_v2_decoder_is_pure_on_duplicate_logs() {
    let member_id = FixedBytes::<32>::from([0xccu8; 32]);
    let wg_pubkey = FixedBytes::<32>::from([0xddu8; 32]);
    let quote_hash = FixedBytes::<32>::from([0xeeu8; 32]);

    let topics = vec![
        IClusterDiamond::MemberWgPubkeySetV2::SIGNATURE_HASH,
        member_id,
    ];
    let data = IClusterDiamond::MemberWgPubkeySetV2 {
        memberId: member_id,
        wgPubkey: wg_pubkey,
        quoteHash: quote_hash,
    }
    .encode_data();
    let log1 = make_rpc_log(topics.clone(), data.clone());
    let log2 = make_rpc_log(topics, data);

    let d = MemberWgPubkeySetV2Decoder;
    assert_eq!(d.decode(&log1).unwrap(), d.decode(&log2).unwrap());
}

// ---------------------------------------------------------------------------
// ComposeHashAllowed / ComposeHashRemoved — zero indexed args + one
// non-indexed `bytes32`.
//
// IAdmin.sol L12-13 — the contract emits both with `composeHash`
// non-indexed, so the field lives in the data slot, not the topics.
// ---------------------------------------------------------------------------

#[test]
fn compose_hash_allowed_decodes_to_expected_json() {
    let compose_hash = FixedBytes::<32>::from([0x88u8; 32]);

    let topics = vec![IClusterDiamond::ComposeHashAllowed::SIGNATURE_HASH];
    let data = IClusterDiamond::ComposeHashAllowed {
        composeHash: compose_hash,
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = ComposeHashAllowedDecoder.decode(&log).unwrap();
    let expected = json!({
        "composeHash": "0x8888888888888888888888888888888888888888888888888888888888888888",
        "_topic0":     format!("0x{}", hex::encode(IClusterDiamond::ComposeHashAllowed::SIGNATURE_HASH.as_slice())),
        "_signature":  "ComposeHashAllowed(bytes32)",
    });
    assert_eq!(decoded, expected);
}

#[test]
fn compose_hash_removed_decodes_to_expected_json() {
    let compose_hash = FixedBytes::<32>::from([0x99u8; 32]);

    let topics = vec![IClusterDiamond::ComposeHashRemoved::SIGNATURE_HASH];
    let data = IClusterDiamond::ComposeHashRemoved {
        composeHash: compose_hash,
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = ComposeHashRemovedDecoder.decode(&log).unwrap();
    let expected = json!({
        "composeHash": "0x9999999999999999999999999999999999999999999999999999999999999999",
        "_topic0":     format!("0x{}", hex::encode(IClusterDiamond::ComposeHashRemoved::SIGNATURE_HASH.as_slice())),
        "_signature":  "ComposeHashRemoved(bytes32)",
    });
    assert_eq!(decoded, expected);
}

/// `ComposeHashAllowed` and `ComposeHashRemoved` must produce DIFFERENT
/// signature hashes so the dispatch map routes each to its own
/// decoder rather than swallowing both into a single bucket. This
/// caught a real bug elsewhere (a pasted `event` declaration left
/// the wrong name on the wire); pinning the property here makes
/// the regression visible at the unit-test layer.
#[test]
fn compose_hash_allowed_and_removed_have_distinct_topic0() {
    let allowed = ComposeHashAllowedDecoder.topic0();
    let removed = ComposeHashRemovedDecoder.topic0();
    assert_ne!(
        allowed, removed,
        "ComposeHashAllowed and ComposeHashRemoved must hash to distinct topic0 values"
    );
}

// ---------------------------------------------------------------------------
// ComposeHashAdded (legacy) — single non-indexed `bytes32`
//
// Source: `IAppAuthBasicManagement.sol` line 13 (mirrored from dstack's
// auth-eth contracts). Kept registered so the indexer can decode
// historical events emitted before the W0-001 rename to
// `ComposeHashAllowed`.
// ---------------------------------------------------------------------------

#[test]
fn compose_hash_added_decodes_to_expected_json() {
    let compose_hash = FixedBytes::<32>::from([0xa1u8; 32]);

    let topics = vec![IClusterDiamond::ComposeHashAdded::SIGNATURE_HASH];
    let data = IClusterDiamond::ComposeHashAdded {
        composeHash: compose_hash,
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = ComposeHashAddedDecoder.decode(&log).unwrap();
    let expected = json!({
        "composeHash": "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "_topic0":     format!("0x{}", hex::encode(IClusterDiamond::ComposeHashAdded::SIGNATURE_HASH.as_slice())),
        "_signature":  "ComposeHashAdded(bytes32)",
    });
    assert_eq!(decoded, expected);
}

/// Decode-time JSON shape parity with `ComposeHashAllowed`: both
/// decoders are routed through the same materializer apply path, so
/// the field names must match exactly (`composeHash` is the
/// load-bearing key the materializer pulls out via
/// `decoded::member_id`). A drift here would make legacy events
/// silently fail at materialization with a missing-field error.
#[test]
fn compose_hash_added_payload_shape_matches_compose_hash_allowed() {
    let compose_hash = FixedBytes::<32>::from([0xbeu8; 32]);

    let added_topics = vec![IClusterDiamond::ComposeHashAdded::SIGNATURE_HASH];
    let added_data = IClusterDiamond::ComposeHashAdded {
        composeHash: compose_hash,
    }
    .encode_data();
    let added_log = make_rpc_log(added_topics, added_data);
    let added = ComposeHashAddedDecoder.decode(&added_log).unwrap();

    let allowed_topics = vec![IClusterDiamond::ComposeHashAllowed::SIGNATURE_HASH];
    let allowed_data = IClusterDiamond::ComposeHashAllowed {
        composeHash: compose_hash,
    }
    .encode_data();
    let allowed_log = make_rpc_log(allowed_topics, allowed_data);
    let allowed = ComposeHashAllowedDecoder.decode(&allowed_log).unwrap();

    assert_eq!(added["composeHash"], allowed["composeHash"]);
}

// ---------------------------------------------------------------------------
// TcbDegraded — one indexed arg + one non-indexed `uint8`
//
// Unified-network-design §6.3, §7. Severity is a uint8 (1 = warn,
// 2 = critical at design time).
// ---------------------------------------------------------------------------

#[test]
fn tcb_degraded_decodes_warn_severity() {
    let member_id = FixedBytes::<32>::from([0xa5u8; 32]);

    let topics = vec![IClusterDiamond::TcbDegraded::SIGNATURE_HASH, member_id];
    let data = IClusterDiamond::TcbDegraded {
        memberId: member_id,
        severity: 1,
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = TcbDegradedDecoder.decode(&log).unwrap();
    let expected = json!({
        "memberId":   "0xa5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
        "severity":   1,
        "_topic0":    format!("0x{}", hex::encode(IClusterDiamond::TcbDegraded::SIGNATURE_HASH.as_slice())),
        "_signature": "TcbDegraded(bytes32,uint8)",
    });
    assert_eq!(decoded, expected);
}

#[test]
fn tcb_degraded_decodes_critical_severity() {
    let member_id = FixedBytes::<32>::from([0x5au8; 32]);

    let topics = vec![IClusterDiamond::TcbDegraded::SIGNATURE_HASH, member_id];
    let data = IClusterDiamond::TcbDegraded {
        memberId: member_id,
        severity: 2,
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = TcbDegradedDecoder.decode(&log).unwrap();
    assert_eq!(decoded["severity"].as_u64(), Some(2));
}

/// Boundary: severity `u8::MAX` (255) must decode cleanly even though
/// the design only uses `1` and `2` today. The encoder shouldn't
/// hard-cap the field; the indexer must round-trip whatever the
/// contract emits.
#[test]
fn tcb_degraded_decodes_u8_max_severity() {
    let member_id = FixedBytes::<32>::from([0x42u8; 32]);

    let topics = vec![IClusterDiamond::TcbDegraded::SIGNATURE_HASH, member_id];
    let data = IClusterDiamond::TcbDegraded {
        memberId: member_id,
        severity: u8::MAX,
    }
    .encode_data();
    let log = make_rpc_log(topics, data);

    let decoded = TcbDegradedDecoder.decode(&log).unwrap();
    assert_eq!(decoded["severity"].as_u64(), Some(255));
}
