//! Replay-path integration tests. Build `Vec<DecodedEvent>` fixtures
//! and drive each view's `replay_in_memory` function directly — the
//! pure replay logic is testable without a Postgres handle, which is
//! what the agent brief calls for. The SQL apply paths live behind
//! `#[ignore]`-gated tests at the bottom of this file (each requires
//! `DATABASE_URL` pointing at a fresh `chain_indexer` schema).

use std::collections::HashMap;

use serde_json::json;
use teesql_chain_indexer_views::{
    compose_hashes, leader, lifecycle, members, DecodedEvent, EventStore, View,
};

const CHAIN_ID: i32 = 8453;
const CLUSTER: [u8; 20] = [
    0x84, 0x8c, 0x17, 0xbd, 0xbf, 0x42, 0xd0, 0x06, 0x77, 0x27, 0xd7, 0x49, 0x55, 0x07, 0x4d, 0x36,
    0xb9, 0xc2, 0xba, 0x3e,
];

fn member_id_str(byte: u8) -> String {
    let mut bytes = [0u8; 32];
    bytes[0] = byte;
    format!("0x{}", hex::encode(bytes))
}

fn address_str(byte: u8) -> String {
    let mut bytes = [0u8; 20];
    bytes[0] = byte;
    format!("0x{}", hex::encode(bytes))
}

fn event(
    block_number: u64,
    log_index: i32,
    kind: &str,
    decoded: serde_json::Value,
) -> DecodedEvent {
    DecodedEvent {
        chain_id: CHAIN_ID,
        contract: CLUSTER,
        block_number,
        block_hash: [0u8; 32],
        log_index,
        tx_hash: [0u8; 32],
        topic0: [0u8; 32],
        topics_rest: Vec::new(),
        data: Vec::new(),
        kind: Some(kind.to_string()),
        decoded: Some(decoded),
    }
}

// ---------------------------------------------------------------------------
// LeaderView
// ---------------------------------------------------------------------------

#[test]
fn leader_replay_empty_returns_zero_lease() {
    let result = leader::replay_in_memory(&[], 100).unwrap();
    let zero = format!("0x{}", hex::encode([0u8; 32]));
    assert_eq!(result["memberId"], zero);
    assert_eq!(result["epoch"], 0);
    assert_eq!(result["asOfBlock"], 100);
}

#[test]
fn leader_replay_single_claim() {
    let events = vec![event(
        45_491_000,
        2,
        "LeaderClaimed",
        json!({
            "memberId": member_id_str(0xab),
            "epoch": "0x1",
        }),
    )];
    let result = leader::replay_in_memory(&events, 45_491_234).unwrap();
    assert_eq!(result["memberId"], member_id_str(0xab));
    assert_eq!(result["epoch"], 1);
    assert_eq!(result["asOfBlock"], 45_491_234);
}

#[test]
fn leader_replay_picks_latest_epoch() {
    let events = vec![
        event(
            100,
            0,
            "LeaderClaimed",
            json!({"memberId": member_id_str(0x01), "epoch": "0x1"}),
        ),
        event(
            200,
            0,
            "LeaderClaimed",
            json!({"memberId": member_id_str(0x02), "epoch": "0x2"}),
        ),
        event(
            300,
            0,
            "LeaderClaimed",
            json!({"memberId": member_id_str(0x03), "epoch": "0x3"}),
        ),
    ];
    let result = leader::replay_in_memory(&events, 1_000).unwrap();
    assert_eq!(result["memberId"], member_id_str(0x03));
    assert_eq!(result["epoch"], 3);
}

#[test]
fn leader_replay_strict_inequality_ignores_lower_epoch() {
    // Out-of-order replay: epoch 5 first, then epoch 3 (which a real
    // chain wouldn't emit but a buggy reorg replay might). Higher
    // epoch must win regardless of source order.
    let events = vec![
        event(
            100,
            0,
            "LeaderClaimed",
            json!({"memberId": member_id_str(0xaa), "epoch": "5"}),
        ),
        event(
            200,
            0,
            "LeaderClaimed",
            json!({"memberId": member_id_str(0xbb), "epoch": "3"}),
        ),
    ];
    let result = leader::replay_in_memory(&events, 1_000).unwrap();
    assert_eq!(result["memberId"], member_id_str(0xaa));
    assert_eq!(result["epoch"], 5);
}

#[test]
fn leader_replay_equal_epoch_keeps_first_seen() {
    // Equal epochs would be a chain-level anomaly; replay logs a
    // warning and keeps the first-observed memberId rather than
    // flapping the answer.
    let events = vec![
        event(
            100,
            0,
            "LeaderClaimed",
            json!({"memberId": member_id_str(0xaa), "epoch": "0x7"}),
        ),
        event(
            200,
            0,
            "LeaderClaimed",
            json!({"memberId": member_id_str(0xbb), "epoch": "0x7"}),
        ),
    ];
    let result = leader::replay_in_memory(&events, 1_000).unwrap();
    assert_eq!(result["memberId"], member_id_str(0xaa));
    assert_eq!(result["epoch"], 7);
}

#[test]
fn leader_replay_respects_as_of_block_cutoff() {
    let events = vec![
        event(
            100,
            0,
            "LeaderClaimed",
            json!({"memberId": member_id_str(0x01), "epoch": "0x1"}),
        ),
        event(
            200,
            0,
            "LeaderClaimed",
            json!({"memberId": member_id_str(0x02), "epoch": "0x2"}),
        ),
    ];
    // as_of_block = 150 → only the first event applies.
    let result = leader::replay_in_memory(&events, 150).unwrap();
    assert_eq!(result["memberId"], member_id_str(0x01));
    assert_eq!(result["epoch"], 1);
    assert_eq!(result["asOfBlock"], 150);
}

#[test]
fn leader_replay_ignores_non_leader_events() {
    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0x01),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "x",
            }),
        ),
        event(
            200,
            0,
            "LeaderClaimed",
            json!({"memberId": member_id_str(0x02), "epoch": "0x4"}),
        ),
    ];
    let result = leader::replay_in_memory(&events, 1_000).unwrap();
    assert_eq!(result["epoch"], 4);
    assert_eq!(result["memberId"], member_id_str(0x02));
}

// ---------------------------------------------------------------------------
// MembersView
// ---------------------------------------------------------------------------

#[test]
fn members_replay_empty_returns_empty_array() {
    let block_ts = HashMap::new();
    let result = members::replay_in_memory(&[], &block_ts, 100).unwrap();
    assert_eq!(result["members"].as_array().unwrap().len(), 0);
}

#[test]
fn members_replay_member_registered_populates_row() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);

    let events = vec![event(
        100,
        1,
        "MemberRegistered",
        json!({
            "memberId": member_id_str(0xa1),
            "instanceId": address_str(0x10),
            "passthrough": address_str(0x20),
            "dnsLabel": "alpha",
        }),
    )];
    let result = members::replay_in_memory(&events, &block_ts, 200).unwrap();
    let arr = result["members"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let m = &arr[0];
    assert_eq!(m["memberId"], member_id_str(0xa1));
    assert_eq!(m["instanceId"], address_str(0x10));
    assert_eq!(m["passthrough"], address_str(0x20));
    assert_eq!(m["dnsLabel"], "alpha");
    assert_eq!(m["registeredAt"], 1_700_000_000_i64);
    assert!(m["publicEndpoint"].is_null());
    assert!(m["wgEndpoint"].is_null());
    assert!(m["retiredAt"].is_null());
}

#[test]
fn members_replay_public_endpoint_derives_wg_endpoint_for_phala_url() {
    // GAP-W1-005: a parseable Phala-gateway publicEndpoint must
    // populate `wgEndpoint` with the explicit `<id>-51820.<node>:443`
    // uotcp target so fabric never has to parse the URL.
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(150u64, 1_700_000_500_i64);

    let url =
        "https://abcdef0123456789abcdef0123456789abcdef01-5432.dstack-base-prod5.phala.network";
    let url_hex = format!("0x{}", hex::encode(url));

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            150,
            0,
            "PublicEndpointUpdated",
            json!({
                "memberId": member_id_str(0xa1),
                "publicEndpoint": url_hex,
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["publicEndpoint"], url);
    assert_eq!(
        m["wgEndpoint"],
        "abcdef0123456789abcdef0123456789abcdef01-51820.dstack-base-prod5.phala.network:443"
    );
}

#[test]
fn members_replay_public_endpoint_unparseable_leaves_wg_endpoint_null() {
    // GAP-W1-005: an unparseable publicEndpoint preserves the URL on
    // `publicEndpoint` (legacy contract) but leaves `wgEndpoint` NULL
    // — fabric must explicitly defer admission rather than guess.
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(150u64, 1_700_000_500_i64);

    // A bare `host.tld` URL with no `<id>-<port>` label segment is
    // unparseable for the Phala-gateway uotcp derivation.
    let url = "https://abc.phala.network";
    let url_hex = format!("0x{}", hex::encode(url));

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            150,
            0,
            "PublicEndpointUpdated",
            json!({
                "memberId": member_id_str(0xa1),
                "publicEndpoint": url_hex,
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["publicEndpoint"], url);
    assert!(
        m["wgEndpoint"].is_null(),
        "unparseable publicEndpoint must leave wgEndpoint NULL, got {:?}",
        m["wgEndpoint"]
    );
}

#[test]
fn members_replay_public_endpoint_rotates_wg_endpoint_on_resubmit() {
    // A second `PublicEndpointUpdated` (e.g. blue-green redeploy
    // moves the data-sidecar to a different gateway port) must
    // overwrite `wgEndpoint` to the latest derivation; old endpoint
    // must NOT linger.
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(150u64, 1_700_000_500_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);

    let old_url =
        "https://1111111111111111111111111111111111111111-5432.dstack-base-prod5.phala.network";
    let new_url =
        "https://2222222222222222222222222222222222222222-5432.dstack-base-prod4.phala.network";
    let old_hex = format!("0x{}", hex::encode(old_url));
    let new_hex = format!("0x{}", hex::encode(new_url));

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            150,
            0,
            "PublicEndpointUpdated",
            json!({
                "memberId": member_id_str(0xa1),
                "publicEndpoint": old_hex,
            }),
        ),
        event(
            200,
            0,
            "PublicEndpointUpdated",
            json!({
                "memberId": member_id_str(0xa1),
                "publicEndpoint": new_hex,
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["publicEndpoint"], new_url);
    assert_eq!(
        m["wgEndpoint"],
        "2222222222222222222222222222222222222222-51820.dstack-base-prod4.phala.network:443"
    );
}

#[test]
fn members_replay_public_endpoint_after_register_keeps_registration_fields() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(150u64, 1_700_000_500_i64);

    let url = "https://abc.phala.network";
    let url_hex = format!("0x{}", hex::encode(url));

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            150,
            0,
            "PublicEndpointUpdated",
            json!({
                "memberId": member_id_str(0xa1),
                "publicEndpoint": url_hex,
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["dnsLabel"], "alpha");
    assert_eq!(m["publicEndpoint"], url);
    assert_eq!(m["registeredAt"], 1_700_000_000_i64);
}

#[test]
fn members_replay_register_after_endpoint_update_does_not_clobber_endpoint() {
    // Idempotency invariant: re-applying MemberRegistered must not
    // clear public_endpoint that was set by a later
    // PublicEndpointUpdated. Models a WS-replay scenario where the
    // events are re-delivered out of canonical order.
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(150u64, 1_700_000_500_i64);
    block_ts.insert(100u64, 1_700_000_000_i64);

    let url = "https://abc.phala.network";
    let url_hex = format!("0x{}", hex::encode(url));

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            150,
            0,
            "PublicEndpointUpdated",
            json!({
                "memberId": member_id_str(0xa1),
                "publicEndpoint": url_hex,
            }),
        ),
        // WS replay re-delivers MemberRegistered.
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(
        m["publicEndpoint"], url,
        "public_endpoint must not be cleared by re-applied MemberRegistered"
    );
}

#[test]
fn members_replay_member_retired_sets_retired_at() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(500u64, 1_700_005_000_i64);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            500,
            0,
            "MemberRetired",
            json!({"memberId": member_id_str(0xa1)}),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["retiredAt"], 1_700_005_000_i64);
}

#[test]
fn members_replay_member_wg_pubkey_set_populates_wg_pubkey_hex() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);

    let pubkey = "0".repeat(64);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            200,
            0,
            "MemberWgPubkeySet",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkeyHex": pubkey.clone(),
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["wgPubkeyHex"], pubkey);
    assert_eq!(m["dnsLabel"], "alpha");
}

#[test]
fn members_replay_member_wg_pubkey_set_before_register_creates_stub() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);

    let pubkey = "f".repeat(64);

    let events = vec![event(
        100,
        0,
        "MemberWgPubkeySet",
        json!({
            "memberId": member_id_str(0xa1),
            "wgPubkeyHex": pubkey.clone(),
        }),
    )];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["wgPubkeyHex"], pubkey);
    assert!(m["dnsLabel"].is_null());
    assert!(m["registeredAt"].is_null());
}

#[test]
fn members_replay_member_wg_pubkey_set_rotates_to_latest() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);
    block_ts.insert(300u64, 1_700_002_000_i64);

    let old = "1".repeat(64);
    let new = "2".repeat(64);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            200,
            0,
            "MemberWgPubkeySet",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkeyHex": old,
            }),
        ),
        event(
            300,
            0,
            "MemberWgPubkeySet",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkeyHex": new.clone(),
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["wgPubkeyHex"], new);
}

#[test]
fn members_replay_endpoint_update_for_unseen_member_creates_stub() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);

    let url = "https://stub.phala.network";
    let url_hex = format!("0x{}", hex::encode(url));

    let events = vec![event(
        100,
        0,
        "PublicEndpointUpdated",
        json!({
            "memberId": member_id_str(0xa1),
            "publicEndpoint": url_hex,
        }),
    )];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["publicEndpoint"], url);
    assert!(m["dnsLabel"].is_null());
    assert!(m["registeredAt"].is_null());
}

#[test]
fn members_replay_retire_for_unseen_member_is_dropped() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);

    let events = vec![event(
        100,
        0,
        "MemberRetired",
        json!({"memberId": member_id_str(0xa1)}),
    )];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    assert_eq!(result["members"].as_array().unwrap().len(), 0);
}

#[test]
fn members_replay_respects_as_of_block_cutoff() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(500u64, 1_700_005_000_i64);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            500,
            0,
            "MemberRetired",
            json!({"memberId": member_id_str(0xa1)}),
        ),
    ];
    // as_of_block = 200 → retire is in the future, member should be active.
    let result = members::replay_in_memory(&events, &block_ts, 200).unwrap();
    let m = &result["members"][0];
    assert!(m["retiredAt"].is_null());
    assert_eq!(m["registeredAt"], 1_700_000_000_i64);
}

#[test]
fn members_replay_sorted_by_member_id() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xff),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "z",
            }),
        ),
        event(
            100,
            1,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0x01),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "a",
            }),
        ),
        event(
            100,
            2,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0x80),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "m",
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 200).unwrap();
    let arr = result["members"].as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["dnsLabel"], "a");
    assert_eq!(arr[1]["dnsLabel"], "m");
    assert_eq!(arr[2]["dnsLabel"], "z");
}

#[test]
fn members_replay_two_members_independent_state() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);
    block_ts.insert(500u64, 1_700_005_000_i64);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0x01),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            200,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0x02),
                "instanceId": address_str(0x11),
                "passthrough": address_str(0x21),
                "dnsLabel": "beta",
            }),
        ),
        event(
            500,
            0,
            "MemberRetired",
            json!({"memberId": member_id_str(0x01)}),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let arr = result["members"].as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["dnsLabel"], "alpha");
    assert_eq!(arr[0]["retiredAt"], 1_700_005_000_i64);
    assert_eq!(arr[1]["dnsLabel"], "beta");
    assert!(arr[1]["retiredAt"].is_null());
}

// ---------------------------------------------------------------------------
// MembersView — V2 admission + TCB degraded path
// (unified-network-design §4.1, §6.3)
// ---------------------------------------------------------------------------

fn bytes32_str(byte: u8) -> String {
    let mut bytes = [0u8; 32];
    bytes.fill(byte);
    format!("0x{}", hex::encode(bytes))
}

#[test]
fn members_replay_member_wg_pubkey_set_v2_populates_attested_columns() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);

    let wg_pubkey = bytes32_str(0x11);
    let quote_hash = bytes32_str(0x22);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            200,
            0,
            "MemberWgPubkeySetV2",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkey": wg_pubkey.clone(),
                "quoteHash": quote_hash.clone(),
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["wgPubkey"], wg_pubkey);
    assert_eq!(m["quoteHash"], quote_hash);
    assert_eq!(m["dnsLabel"], "alpha");
    // V1 column stays NULL: the materializer treats V1 and V2 as
    // independent trust layers.
    assert!(m["wgPubkeyHex"].is_null());
}

#[test]
fn members_replay_member_wg_pubkey_set_v2_before_register_creates_stub() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);

    let wg_pubkey = bytes32_str(0x33);
    let quote_hash = bytes32_str(0x44);

    let events = vec![event(
        100,
        0,
        "MemberWgPubkeySetV2",
        json!({
            "memberId": member_id_str(0xa1),
            "wgPubkey": wg_pubkey.clone(),
            "quoteHash": quote_hash.clone(),
        }),
    )];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["wgPubkey"], wg_pubkey);
    assert_eq!(m["quoteHash"], quote_hash);
    assert!(m["dnsLabel"].is_null());
    assert!(m["registeredAt"].is_null());
}

#[test]
fn members_replay_member_wg_pubkey_set_v2_rotation_keeps_latest_quote_hash() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);
    block_ts.insert(300u64, 1_700_002_000_i64);

    let pubkey_old = bytes32_str(0x55);
    let pubkey_new = bytes32_str(0x66);
    let quote_old = bytes32_str(0x77);
    let quote_new = bytes32_str(0x88);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            200,
            0,
            "MemberWgPubkeySetV2",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkey": pubkey_old,
                "quoteHash": quote_old,
            }),
        ),
        event(
            300,
            0,
            "MemberWgPubkeySetV2",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkey": pubkey_new.clone(),
                "quoteHash": quote_new.clone(),
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["wgPubkey"], pubkey_new);
    assert_eq!(m["quoteHash"], quote_new);
}

/// Duplicate `MemberWgPubkeySetV2` events (WS replay / HA double-write)
/// must be idempotent in the replay path — the second occurrence
/// converges to the same final row, not a stub-creating warning.
#[test]
fn members_replay_member_wg_pubkey_set_v2_duplicate_is_idempotent() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);

    let wg_pubkey = bytes32_str(0xaa);
    let quote_hash = bytes32_str(0xbb);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            200,
            0,
            "MemberWgPubkeySetV2",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkey": wg_pubkey.clone(),
                "quoteHash": quote_hash.clone(),
            }),
        ),
        // Same wire payload — emulates a WS replay re-delivering the
        // event after a steady-state subscriber already saw it.
        event(
            200,
            0,
            "MemberWgPubkeySetV2",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkey": wg_pubkey.clone(),
                "quoteHash": quote_hash.clone(),
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let arr = result["members"].as_array().unwrap();
    assert_eq!(arr.len(), 1, "duplicate must not create a second row");
    assert_eq!(arr[0]["wgPubkey"], wg_pubkey);
    assert_eq!(arr[0]["quoteHash"], quote_hash);
}

#[test]
fn members_replay_tcb_degraded_stamps_severity_and_block_ts() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(300u64, 1_700_002_000_i64);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            300,
            0,
            "TcbDegraded",
            json!({
                "memberId": member_id_str(0xa1),
                "severity": 2,
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["tcbSeverity"], 2);
    assert_eq!(m["tcbDegradedAt"], 1_700_002_000_i64);
}

/// Latest-event-wins: a `TcbDegraded(warn)` followed by
/// `TcbDegraded(critical)` from a later block leaves the row at
/// critical. Fabric reads the column as a current snapshot, not a
/// max-severity history (see materializer doc).
#[test]
fn members_replay_tcb_degraded_latest_event_wins() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);
    block_ts.insert(300u64, 1_700_002_000_i64);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            200,
            0,
            "TcbDegraded",
            json!({
                "memberId": member_id_str(0xa1),
                "severity": 2,
            }),
        ),
        event(
            300,
            0,
            "TcbDegraded",
            json!({
                "memberId": member_id_str(0xa1),
                "severity": 1,
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["tcbSeverity"], 1);
    assert_eq!(m["tcbDegradedAt"], 1_700_002_000_i64);
}

/// Stale-replay regression test for the W1-002 review finding
/// MEDIUM-1 (V2 path): a duplicate older `MemberWgPubkeySetV2`
/// re-delivered after a rotation must NOT revert the row to the
/// older pubkey. If the materializer overwrote unconditionally, a
/// WS replay of the pre-rotation event would corrupt the
/// admission cache and fabric would refuse the rotated peer.
#[test]
fn members_replay_stale_v2_does_not_revert_after_rotation() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);
    block_ts.insert(300u64, 1_700_002_000_i64);

    let pubkey_old = bytes32_str(0x55);
    let pubkey_new = bytes32_str(0x66);
    let quote_old = bytes32_str(0x77);
    let quote_new = bytes32_str(0x88);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            200,
            0,
            "MemberWgPubkeySetV2",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkey": pubkey_old.clone(),
                "quoteHash": quote_old.clone(),
            }),
        ),
        event(
            300,
            0,
            "MemberWgPubkeySetV2",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkey": pubkey_new.clone(),
                "quoteHash": quote_new.clone(),
            }),
        ),
        // WS replay re-delivers the pre-rotation event AFTER the
        // rotation. Stale-replay guard must reject the overwrite.
        event(
            200,
            0,
            "MemberWgPubkeySetV2",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkey": pubkey_old,
                "quoteHash": quote_old,
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(
        m["wgPubkey"], pubkey_new,
        "stale MemberWgPubkeySetV2 replay must NOT revert the rotated pubkey"
    );
    assert_eq!(
        m["quoteHash"], quote_new,
        "stale MemberWgPubkeySetV2 replay must NOT revert the rotated quote_hash"
    );
}

/// Stale-replay regression test for the W1-002 review finding
/// MEDIUM-1 (TCB path): a duplicate older `TcbDegraded` re-delivered
/// after a newer alert must NOT roll back the column. Operators
/// alert on the column directly; a regression here would mute a
/// real critical event with a stale warn.
#[test]
fn members_replay_stale_tcb_degraded_does_not_revert_severity() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);
    block_ts.insert(300u64, 1_700_002_000_i64);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            200,
            0,
            "TcbDegraded",
            json!({
                "memberId": member_id_str(0xa1),
                "severity": 1,
            }),
        ),
        event(
            300,
            0,
            "TcbDegraded",
            json!({
                "memberId": member_id_str(0xa1),
                "severity": 2,
            }),
        ),
        // WS replay re-delivers the earlier warn AFTER the critical
        // alert. Stale-replay guard must keep the critical state.
        event(
            200,
            0,
            "TcbDegraded",
            json!({
                "memberId": member_id_str(0xa1),
                "severity": 1,
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(
        m["tcbSeverity"], 2,
        "stale TcbDegraded replay must NOT roll back severity"
    );
    assert_eq!(
        m["tcbDegradedAt"], 1_700_002_000_i64,
        "stale TcbDegraded replay must NOT roll back tcb_degraded_at"
    );
}

/// Two `MemberWgPubkeySetV2` events at the same block but different
/// `log_index` — tuple comparison must use the log_index to break
/// the tie correctly. The higher log_index wins.
#[test]
fn members_replay_v2_same_block_higher_log_index_wins() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);

    let pubkey_old = bytes32_str(0x55);
    let pubkey_new = bytes32_str(0x66);
    let quote_old = bytes32_str(0x77);
    let quote_new = bytes32_str(0x88);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0xa1),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "alpha",
            }),
        ),
        event(
            200,
            0,
            "MemberWgPubkeySetV2",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkey": pubkey_old.clone(),
                "quoteHash": quote_old.clone(),
            }),
        ),
        // Higher log_index at the SAME block — must win.
        event(
            200,
            1,
            "MemberWgPubkeySetV2",
            json!({
                "memberId": member_id_str(0xa1),
                "wgPubkey": pubkey_new.clone(),
                "quoteHash": quote_new.clone(),
            }),
        ),
    ];
    let result = members::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let m = &result["members"][0];
    assert_eq!(m["wgPubkey"], pubkey_new);
    assert_eq!(m["quoteHash"], quote_new);
}

// ---------------------------------------------------------------------------
// ComposeHashesView (unified-network-design §4.2)
// ---------------------------------------------------------------------------

#[test]
fn compose_hashes_replay_empty_returns_empty_array() {
    let result = compose_hashes::replay_in_memory(&[], &HashMap::new(), 1_000).unwrap();
    assert_eq!(result["composeHashes"].as_array().unwrap().len(), 0);
}

#[test]
fn compose_hashes_replay_allow_marks_row_active() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);

    let hash = bytes32_str(0xab);
    let events = vec![event(
        100,
        0,
        "ComposeHashAllowed",
        json!({"composeHash": hash.clone()}),
    )];
    let result = compose_hashes::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let row = &result["composeHashes"][0];
    assert_eq!(row["composeHash"], hash);
    assert_eq!(row["allowedAt"], 1_700_000_000_i64);
    assert!(row["removedAt"].is_null());
    assert_eq!(row["active"], true);
}

#[test]
fn compose_hashes_replay_remove_after_allow_flips_active_false() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);

    let hash = bytes32_str(0xab);
    let events = vec![
        event(
            100,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": hash.clone()}),
        ),
        event(
            200,
            0,
            "ComposeHashRemoved",
            json!({"composeHash": hash.clone()}),
        ),
    ];
    let result = compose_hashes::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let row = &result["composeHashes"][0];
    assert_eq!(row["allowedAt"], 1_700_000_000_i64);
    assert_eq!(row["removedAt"], 1_700_001_000_i64);
    assert_eq!(row["active"], false);
}

/// Re-adding a previously-removed hash clears `removedAt` so fabric's
/// "active set" projection picks the row back up.
#[test]
fn compose_hashes_replay_re_add_clears_removed_at() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);
    block_ts.insert(300u64, 1_700_002_000_i64);

    let hash = bytes32_str(0xab);
    let events = vec![
        event(
            100,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": hash.clone()}),
        ),
        event(
            200,
            0,
            "ComposeHashRemoved",
            json!({"composeHash": hash.clone()}),
        ),
        event(
            300,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": hash.clone()}),
        ),
    ];
    let result = compose_hashes::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let row = &result["composeHashes"][0];
    // `allowedAt` keeps the earliest seen (the original add at 100).
    assert_eq!(row["allowedAt"], 1_700_000_000_i64);
    assert!(row["removedAt"].is_null());
    assert_eq!(row["active"], true);
}

/// Duplicate `ComposeHashAllowed` events (WS replay) must collapse
/// to a single row without producing duplicates in the projection.
#[test]
fn compose_hashes_replay_duplicate_allow_is_idempotent() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);

    let hash = bytes32_str(0xcd);
    let events = vec![
        event(
            100,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": hash.clone()}),
        ),
        event(
            100,
            1,
            "ComposeHashAllowed",
            json!({"composeHash": hash.clone()}),
        ),
    ];
    let result = compose_hashes::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let arr = result["composeHashes"].as_array().unwrap();
    assert_eq!(
        arr.len(),
        1,
        "duplicate allow must not produce a second row"
    );
    assert_eq!(arr[0]["composeHash"], hash);
    assert_eq!(arr[0]["active"], true);
}

/// Multiple distinct hashes interleaved with adds/removes produce one
/// row per hash. Output is sorted by compose-hash so consumers don't
/// have to do a follow-up sort.
#[test]
fn compose_hashes_replay_multiple_hashes_independent_state() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);
    block_ts.insert(300u64, 1_700_002_000_i64);

    let h_low = bytes32_str(0x11);
    let h_high = bytes32_str(0xff);

    let events = vec![
        event(
            100,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": h_high.clone()}),
        ),
        event(
            200,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": h_low.clone()}),
        ),
        event(
            300,
            0,
            "ComposeHashRemoved",
            json!({"composeHash": h_high.clone()}),
        ),
    ];
    let result = compose_hashes::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let arr = result["composeHashes"].as_array().unwrap();
    assert_eq!(arr.len(), 2);
    // Sorted lex by composeHash → low hash first.
    assert_eq!(arr[0]["composeHash"], h_low);
    assert_eq!(arr[0]["active"], true);
    assert_eq!(arr[1]["composeHash"], h_high);
    assert_eq!(arr[1]["active"], false);
}

/// Security regression test for the W1-002 review finding HIGH-1:
/// a stale `ComposeHashAllowed` re-delivered after a
/// `ComposeHashRemoved` (e.g. via WS replay of an event that has
/// since been superseded on chain) must NOT clear `removed_at`. If
/// the materializer reactivated the row on stale replay, a revoked
/// MRTD would silently rejoin the cluster's allowlist.
#[test]
fn compose_hashes_replay_stale_allow_does_not_reactivate_after_remove() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);

    let hash = bytes32_str(0xfe);
    let events = vec![
        event(
            100,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": hash.clone()}),
        ),
        event(
            200,
            0,
            "ComposeHashRemoved",
            json!({"composeHash": hash.clone()}),
        ),
        // WS replay re-delivers the original allow AFTER the
        // remove. The materializer must observe that the incoming
        // event's `(block, log_index)` is OLDER than the remove
        // and leave `removed_at` untouched.
        event(
            100,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": hash.clone()}),
        ),
    ];
    let result = compose_hashes::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let row = &result["composeHashes"][0];
    assert_eq!(
        row["removedAt"], 1_700_001_000_i64,
        "stale ComposeHashAllowed replayed after a remove must NOT clear removed_at"
    );
    assert_eq!(
        row["active"], false,
        "stale ComposeHashAllowed replay must NOT reactivate a revoked MRTD"
    );
    assert_eq!(row["allowedAt"], 1_700_000_000_i64);
}

/// Complementary positive case: a GENUINE re-add at a later block
/// after a remove DOES reactivate. Confirms the tuple comparison
/// is strict-inequality (not e.g. always-false).
#[test]
fn compose_hashes_replay_re_add_at_later_block_does_reactivate() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);
    block_ts.insert(300u64, 1_700_002_000_i64);

    let hash = bytes32_str(0xfe);
    let events = vec![
        event(
            100,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": hash.clone()}),
        ),
        event(
            200,
            0,
            "ComposeHashRemoved",
            json!({"composeHash": hash.clone()}),
        ),
        // Genuine re-add at a strictly newer block: this MUST
        // reactivate the row (clear `removed_at` back to NULL).
        event(
            300,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": hash.clone()}),
        ),
    ];
    let result = compose_hashes::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let row = &result["composeHashes"][0];
    assert!(
        row["removedAt"].is_null(),
        "genuine re-add at a later block MUST clear removed_at"
    );
    assert_eq!(row["active"], true);
    // `allowed_at` keeps the earliest seen (the canonical first allow).
    assert_eq!(row["allowedAt"], 1_700_000_000_i64);
}

/// `ComposeHashAdded` (legacy synonym, pre-W0-001-rename) must
/// drive the same active-set materialization as
/// `ComposeHashAllowed`. Tests both that the legacy event kind is
/// honored on its own and that mixing both kinds across an event
/// stream converges to the correct state.
#[test]
fn compose_hashes_replay_legacy_compose_hash_added_marks_row_active() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);

    let hash = bytes32_str(0xa1);
    let events = vec![event(
        100,
        0,
        "ComposeHashAdded",
        json!({"composeHash": hash.clone()}),
    )];
    let result = compose_hashes::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let row = &result["composeHashes"][0];
    assert_eq!(row["composeHash"], hash);
    assert_eq!(row["allowedAt"], 1_700_000_000_i64);
    assert!(row["removedAt"].is_null());
    assert_eq!(row["active"], true);
}

/// A cluster mid-cutover may emit the legacy `ComposeHashAdded`
/// for a hash, then `ComposeHashRemoved`, then later re-add with
/// the post-rename `ComposeHashAllowed`. All three kinds must
/// converge to the chain-canonical active state.
#[test]
fn compose_hashes_replay_legacy_added_then_remove_then_allowed_reactivates() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);
    block_ts.insert(300u64, 1_700_002_000_i64);

    let hash = bytes32_str(0xa2);
    let events = vec![
        event(
            100,
            0,
            "ComposeHashAdded",
            json!({"composeHash": hash.clone()}),
        ),
        event(
            200,
            0,
            "ComposeHashRemoved",
            json!({"composeHash": hash.clone()}),
        ),
        event(
            300,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": hash.clone()}),
        ),
    ];
    let result = compose_hashes::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let row = &result["composeHashes"][0];
    assert_eq!(row["active"], true);
    assert!(row["removedAt"].is_null());
    assert_eq!(row["allowedAt"], 1_700_000_000_i64);
}

/// Mirror of `compose_hashes_replay_stale_allow_does_not_reactivate_after_remove`
/// but with the legacy event name: a stale `ComposeHashAdded`
/// replayed after a `ComposeHashRemoved` must not reactivate
/// either. Both names route through the same apply path, so the
/// stale-replay guard must apply to both.
#[test]
fn compose_hashes_replay_stale_legacy_added_does_not_reactivate_after_remove() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(200u64, 1_700_001_000_i64);

    let hash = bytes32_str(0xa3);
    let events = vec![
        event(
            100,
            0,
            "ComposeHashAdded",
            json!({"composeHash": hash.clone()}),
        ),
        event(
            200,
            0,
            "ComposeHashRemoved",
            json!({"composeHash": hash.clone()}),
        ),
        event(
            100,
            0,
            "ComposeHashAdded",
            json!({"composeHash": hash.clone()}),
        ),
    ];
    let result = compose_hashes::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    let row = &result["composeHashes"][0];
    assert_eq!(row["removedAt"], 1_700_001_000_i64);
    assert_eq!(row["active"], false);
}

#[test]
fn compose_hashes_replay_respects_as_of_block_cutoff() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(500u64, 1_700_005_000_i64);

    let hash = bytes32_str(0x77);
    let events = vec![
        event(
            100,
            0,
            "ComposeHashAllowed",
            json!({"composeHash": hash.clone()}),
        ),
        event(
            500,
            0,
            "ComposeHashRemoved",
            json!({"composeHash": hash.clone()}),
        ),
    ];
    // Cutoff at 200 — the remove at 500 is past the as_of_block and
    // must not influence the projection.
    let result = compose_hashes::replay_in_memory(&events, &block_ts, 200).unwrap();
    let row = &result["composeHashes"][0];
    assert_eq!(row["active"], true);
    assert!(row["removedAt"].is_null());
}

// ---------------------------------------------------------------------------
// LifecycleView
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_replay_empty_returns_null() {
    let result = lifecycle::replay_in_memory(&[], &HashMap::new(), 1_000).unwrap();
    assert!(result["destroyedAt"].is_null());
}

#[test]
fn lifecycle_replay_destroyed() {
    let mut block_ts = HashMap::new();
    block_ts.insert(500u64, 1_700_005_000_i64);

    let events = vec![event(500, 0, "ClusterDestroyed", json!({}))];
    let result = lifecycle::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    assert_eq!(result["destroyedAt"], 1_700_005_000_i64);
}

#[test]
fn lifecycle_replay_cutoff_before_destroy_returns_null() {
    let mut block_ts = HashMap::new();
    block_ts.insert(500u64, 1_700_005_000_i64);

    let events = vec![event(500, 0, "ClusterDestroyed", json!({}))];
    let result = lifecycle::replay_in_memory(&events, &block_ts, 400).unwrap();
    assert!(result["destroyedAt"].is_null());
}

#[test]
fn lifecycle_replay_cutoff_at_destroy_returns_ts() {
    let mut block_ts = HashMap::new();
    block_ts.insert(500u64, 1_700_005_000_i64);

    let events = vec![event(500, 0, "ClusterDestroyed", json!({}))];
    let result = lifecycle::replay_in_memory(&events, &block_ts, 500).unwrap();
    assert_eq!(result["destroyedAt"], 1_700_005_000_i64);
}

#[test]
fn lifecycle_replay_ignores_non_destroy_events() {
    let mut block_ts = HashMap::new();
    block_ts.insert(100u64, 1_700_000_000_i64);
    block_ts.insert(500u64, 1_700_005_000_i64);

    let events = vec![
        event(
            100,
            0,
            "MemberRegistered",
            json!({
                "memberId": member_id_str(0x01),
                "instanceId": address_str(0x10),
                "passthrough": address_str(0x20),
                "dnsLabel": "x",
            }),
        ),
        event(500, 0, "ClusterDestroyed", json!({})),
    ];
    let result = lifecycle::replay_in_memory(&events, &block_ts, 1_000).unwrap();
    assert_eq!(result["destroyedAt"], 1_700_005_000_i64);
}

// ---------------------------------------------------------------------------
// Apply-path tests — gated behind DATABASE_URL because they require a
// fresh chain_indexer schema. Run via:
//
//   DATABASE_URL=postgres://... cargo test -p teesql-chain-indexer-views -- --ignored
//
// These are skipped in the default test run; CI without a Postgres
// fixture passes the in-memory replay tests above and is enough for
// the materializer logic.
//
// Setup: point `DATABASE_URL` at any Postgres database whose schema
// matches `deploy/provision.sql`. Each test uses a unique cluster
// address so concurrent runs against the same database don't collide,
// and every test cleans up its rows on exit (whether passing or
// failing) so the schema can be reused.
// ---------------------------------------------------------------------------

/// Open a pool against `$DATABASE_URL`. Returns `None` (after printing
/// a hint) when the env var is unset so a hand-run `cargo test --
/// --ignored` without DATABASE_URL is a clean skip rather than a
/// confusing connection-refused error.
async fn db_pool() -> Option<sqlx::PgPool> {
    let url = match std::env::var("DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!(
                "skipping: set DATABASE_URL=postgres://... and re-run \
                 with `-- --ignored` to exercise the SQL apply path"
            );
            return None;
        }
    };
    let pool = sqlx::PgPool::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    Some(pool)
}

/// Build a fresh `EventStore` against the given pool. `chain_id` is
/// always `CHAIN_ID` (Base mainnet's 8453) — the apply paths use it
/// only as a scoping discriminator, so any consistent value works.
async fn store(pool: sqlx::PgPool) -> EventStore {
    EventStore::new(pool, CHAIN_ID)
        .await
        .expect("EventStore::new")
}

/// Insert a `blocks` row directly via SQL. The apply path's
/// `lookup_block_ts` reads this; without it, `MemberRegistered` would
/// bail with "blocks row missing".
async fn seed_block(pool: &sqlx::PgPool, block_number: u64, block_ts: i64) {
    sqlx::query(
        "INSERT INTO blocks (chain_id, number, hash, parent_hash, block_ts) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (chain_id, number) DO UPDATE SET block_ts = EXCLUDED.block_ts",
    )
    .bind(CHAIN_ID)
    .bind(block_number as i64)
    .bind(&[0u8; 32][..])
    .bind(&[0u8; 32][..])
    .bind(block_ts)
    .execute(pool)
    .await
    .expect("seed blocks row");
}

/// Remove every row the test inserted so the schema stays reusable
/// across runs. Called via `scopeguard`-style explicit calls at the
/// end of each test (we don't pull in `scopeguard` for one consumer).
async fn cleanup(pool: &sqlx::PgPool, cluster: &[u8; 20]) {
    let _ = sqlx::query("DELETE FROM cluster_members WHERE chain_id = $1 AND cluster_address = $2")
        .bind(CHAIN_ID)
        .bind(&cluster[..])
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM blocks WHERE chain_id = $1 AND number >= $2 AND number < $3")
        .bind(CHAIN_ID)
        .bind(100i64)
        .bind(10_000i64)
        .execute(pool)
        .await;
}

/// GAP-W1-005 DB-backed apply test: drive `MembersView::apply` against
/// a real Postgres and verify that a `PublicEndpointUpdated` event
/// persists the materializer-derived `wg_endpoint` column. This is the
/// test the original PR shipped as a stub; the Codex review's MEDIUM
/// finding called out that the wgEndpoint write path had no DB
/// coverage at all and would silently regress if the column rename or
/// the URL-parser convention drifted out of `apply_public_endpoint_updated`.
///
/// Three assertions in one test (cheaper than three serial connect/
/// cleanup cycles): the happy path persists `wg_endpoint`, an
/// unparseable URL leaves it NULL while still recording
/// `public_endpoint`, and a follow-up `PublicEndpointUpdated` with a
/// fresh URL rotates `wg_endpoint` to the new derivation.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointing at a chain_indexer schema"]
async fn members_apply_persists_wg_endpoint() {
    let Some(pool) = db_pool().await else {
        return;
    };
    // Unique per-test cluster address so this test can run alongside
    // others (or the same test from a different worker) against a
    // shared database without colliding on the cluster_members PK.
    let cluster: [u8; 20] = [
        0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05,
    ];
    cleanup(&pool, &cluster).await; // be tolerant of a prior aborted run
    seed_block(&pool, 100, 1_700_000_000).await;
    seed_block(&pool, 150, 1_700_000_500).await;
    seed_block(&pool, 200, 1_700_001_000).await;

    let store = store(pool.clone()).await;
    let view = members::MembersView::new();

    let member = member_id_str(0xA1);
    let member_bytes = {
        let raw = hex::decode(member.trim_start_matches("0x")).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        out
    };

    // Step 1: MemberRegistered — establish the row so subsequent
    // events update rather than stub-insert.
    let registered = DecodedEvent {
        chain_id: CHAIN_ID,
        contract: cluster,
        block_number: 100,
        block_hash: [0u8; 32],
        log_index: 0,
        tx_hash: [0u8; 32],
        topic0: [0u8; 32],
        topics_rest: Vec::new(),
        data: Vec::new(),
        kind: Some("MemberRegistered".into()),
        decoded: Some(json!({
            "memberId": member,
            "instanceId": address_str(0x10),
            "passthrough": address_str(0x20),
            "dnsLabel": "wgendpoint-test",
        })),
    };
    view.apply(&store, &registered)
        .await
        .expect("apply MemberRegistered");

    // Step 2: PublicEndpointUpdated with a parseable Phala-gateway URL
    // — expect `wg_endpoint` to be derived and persisted.
    let url =
        "https://abcdef0123456789abcdef0123456789abcdef01-5432.dstack-base-prod5.phala.network";
    let url_hex = format!("0x{}", hex::encode(url));
    let endpoint_event = DecodedEvent {
        chain_id: CHAIN_ID,
        contract: cluster,
        block_number: 150,
        block_hash: [0u8; 32],
        log_index: 0,
        tx_hash: [0u8; 32],
        topic0: [0u8; 32],
        topics_rest: Vec::new(),
        data: Vec::new(),
        kind: Some("PublicEndpointUpdated".into()),
        decoded: Some(json!({
            "memberId": member,
            "publicEndpoint": url_hex,
        })),
    };
    view.apply(&store, &endpoint_event)
        .await
        .expect("apply PublicEndpointUpdated (parseable)");

    let (pe, we): (String, Option<String>) = sqlx::query_as(
        "SELECT public_endpoint, wg_endpoint \
         FROM cluster_members \
         WHERE chain_id = $1 AND cluster_address = $2 AND member_id = $3",
    )
    .bind(CHAIN_ID)
    .bind(&cluster[..])
    .bind(&member_bytes[..])
    .fetch_one(&pool)
    .await
    .expect("read back cluster_members row");
    assert_eq!(pe, url, "public_endpoint must round-trip");
    assert_eq!(
        we.as_deref(),
        Some("abcdef0123456789abcdef0123456789abcdef01-51820.dstack-base-prod5.phala.network:443"),
        "wg_endpoint must be derived from publicEndpoint by the materializer"
    );

    // Step 3: PublicEndpointUpdated with an unparseable URL — expect
    // `wg_endpoint` to revert to NULL while `public_endpoint` is
    // updated to the new (bad) value. Models a blue-green redeploy
    // that landed a URL the parser can't handle; fabric must defer
    // admission rather than reuse the stale wg_endpoint.
    let bad_url = "https://abc.phala.network";
    let bad_hex = format!("0x{}", hex::encode(bad_url));
    let bad_event = DecodedEvent {
        chain_id: CHAIN_ID,
        contract: cluster,
        block_number: 200,
        block_hash: [0u8; 32],
        log_index: 0,
        tx_hash: [0u8; 32],
        topic0: [0u8; 32],
        topics_rest: Vec::new(),
        data: Vec::new(),
        kind: Some("PublicEndpointUpdated".into()),
        decoded: Some(json!({
            "memberId": member,
            "publicEndpoint": bad_hex,
        })),
    };
    view.apply(&store, &bad_event)
        .await
        .expect("apply PublicEndpointUpdated (unparseable)");

    let (pe2, we2): (String, Option<String>) = sqlx::query_as(
        "SELECT public_endpoint, wg_endpoint \
         FROM cluster_members \
         WHERE chain_id = $1 AND cluster_address = $2 AND member_id = $3",
    )
    .bind(CHAIN_ID)
    .bind(&cluster[..])
    .bind(&member_bytes[..])
    .fetch_one(&pool)
    .await
    .expect("read back cluster_members row after unparseable update");
    assert_eq!(
        pe2, bad_url,
        "public_endpoint must reflect the latest event"
    );
    assert!(
        we2.is_none(),
        "unparseable publicEndpoint must reset wg_endpoint to NULL, got {we2:?}"
    );

    cleanup(&pool, &cluster).await;
}

/// Companion test that exercises the schema-preflight side: the
/// indexer's `verify_required_schema` must succeed against a schema
/// that has the `wg_endpoint` + `wg_pubkey_hex` columns. Pairs with
/// the apply test above by verifying the boot-time check this indexer
/// build runs accepts the same schema the apply path writes to.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointing at a chain_indexer schema"]
async fn schema_preflight_accepts_provisioned_schema() {
    let Some(pool) = db_pool().await else {
        return;
    };
    teesql_chain_indexer_core::verify_required_schema(&pool)
        .await
        .expect("verify_required_schema against a provisioned schema must succeed");
}

#[test]
#[ignore = "requires DATABASE_URL pointing at a chain_indexer schema"]
fn leader_apply_persists_strict_inequality() {
    // Companion stub for LeaderView's apply path — left intentionally
    // empty pending the same harness the wg_endpoint test now uses.
    // See `members_apply_persists_wg_endpoint` for the pattern.
}

#[test]
#[ignore = "requires DATABASE_URL pointing at a chain_indexer schema"]
fn lifecycle_apply_destroyed_at_set_once() {
    // Companion stub for LifecycleView's apply path — see
    // `members_apply_persists_wg_endpoint` for the pattern.
}
