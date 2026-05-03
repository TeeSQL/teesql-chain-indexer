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
    ClusterDestroyedDecoder, IClusterDiamond, LeaderClaimedDecoder, MemberRegisteredDecoder,
    MemberRetiredDecoder, PublicEndpointUpdatedDecoder,
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
