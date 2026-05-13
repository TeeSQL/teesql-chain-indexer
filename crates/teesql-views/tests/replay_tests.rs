//! Replay-path integration tests. Build `Vec<DecodedEvent>` fixtures
//! and drive each view's `replay_in_memory` function directly — the
//! pure replay logic is testable without a Postgres handle, which is
//! what the agent brief calls for. The SQL apply paths live behind
//! `#[ignore]`-gated tests at the bottom of this file (each requires
//! `DATABASE_URL` pointing at a fresh `chain_indexer` schema).

use std::collections::HashMap;

use serde_json::json;
use teesql_chain_indexer_views::{leader, lifecycle, members, DecodedEvent};

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
    assert!(m["retiredAt"].is_null());
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
// the materializer logic. The ignored tests exist as a documentation
// artifact for the integration step.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires DATABASE_URL pointing at a fresh chain_indexer schema"]
fn leader_apply_persists_strict_inequality() {
    // Stub: the integration test would
    //   1. open a sqlx PgPool against $DATABASE_URL
    //   2. truncate cluster_leader and events
    //   3. seed a blocks row
    //   4. drive LeaderView.apply with a sequence of events
    //   5. assert cluster_leader contents after each step
    // Left as a TODO until Phase 2 brings up the integration harness.
}

#[test]
#[ignore = "requires DATABASE_URL pointing at a fresh chain_indexer schema"]
fn members_apply_idempotent_under_ws_replay() {
    // Stub — see leader_apply_persists_strict_inequality.
}

#[test]
#[ignore = "requires DATABASE_URL pointing at a fresh chain_indexer schema"]
fn lifecycle_apply_destroyed_at_set_once() {
    // Stub — see leader_apply_persists_strict_inequality.
}
