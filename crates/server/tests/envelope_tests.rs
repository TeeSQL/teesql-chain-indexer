//! Envelope round-trip tests.
//!
//! Builds a signed envelope through the same path the REST + gRPC
//! handlers use, then ECDSA-recovers the signer from the signature
//! and asserts it matches `Signer::signer_address()`. This exercises
//! the canonicalization + hashing + signing pipeline end-to-end
//! without a Postgres pool — the tests stand up only the [`Signer`]
//! and the `envelope::build` function.

use serde_json::json;
use sha3::{Digest, Keccak256};

use teesql_chain_indexer_attest::{payload_hash, AttestConfig, Signer};
use teesql_chain_indexer_server::as_of::{AsOf, Safety};
use teesql_chain_indexer_server::envelope;

/// Build a Signer in env-override mode. The override path bypasses
/// dstack (no real quote, no remote attestation) and lets the
/// envelope round-trip exercise the canonicalization + sign + recover
/// pipeline against a deterministic key.
fn override_signer(env: &str, response_lifetime_s: u64) -> Signer {
    std::env::set_var(
        env,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    let cfg = AttestConfig {
        kms_purpose: "test".into(),
        kms_path: String::new(),
        override_key_env: env.into(),
        response_lifetime_s,
    };
    let signer = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(Signer::from_dstack(&cfg))
        .unwrap();
    std::env::remove_var(env);
    signer
}

#[test]
fn envelope_round_trip_recovers_signer() {
    let signer = override_signer("TEESQL_CHAIN_INDEXER_ENVELOPE_TEST_RT", 300);

    let data = json!({
        "member_id": "0x0000000000000000000000000000000000000000000000000000000000000001",
        "epoch": 42,
    });
    let as_of = AsOf {
        block_number: 45_491_234,
        block_hash: "0x".to_string() + &"ab".repeat(32),
        block_timestamp: 1_777_771_500,
        finalized_block: 45_491_222,
        safety: Safety::Head,
    };

    let env = envelope::build(data.clone(), &as_of, &signer);

    // Envelope shape — three top-level keys per spec §7.1.
    let obj = env.as_object().expect("envelope is object");
    assert!(obj.contains_key("data"), "envelope has data");
    assert!(obj.contains_key("as_of"), "envelope has as_of");
    assert!(obj.contains_key("attestation"), "envelope has attestation");

    // Hash check — payload_hash in the envelope must equal what we
    // recompute against `data` + `as_of`.
    let attestation = obj.get("attestation").unwrap();
    let payload_hash_hex = attestation
        .get("payload_hash")
        .and_then(|v| v.as_str())
        .expect("payload_hash is string");
    let envelope_data = obj.get("data").unwrap();
    let envelope_as_of = obj.get("as_of").unwrap();
    let expected_hash = payload_hash(envelope_data, envelope_as_of);
    assert_eq!(
        payload_hash_hex,
        format!("0x{}", hex::encode(expected_hash)),
        "envelope payload_hash matches recomputed hash"
    );

    // Signer-recovery check — extract sig + recid, recover the
    // verifying key from the prehashed digest, derive the address,
    // and assert equality with the signer's advertised address.
    let signature_hex = attestation
        .get("signature")
        .and_then(|v| v.as_str())
        .expect("signature is string");
    let advertised_address = attestation
        .get("signer_address")
        .and_then(|v| v.as_str())
        .expect("signer_address is string");
    let recovered = recover_address(signature_hex, expected_hash);
    assert_eq!(
        recovered.to_lowercase(),
        advertised_address.to_lowercase(),
        "recovered address matches advertised signer"
    );
    assert_eq!(
        recovered.to_lowercase(),
        format!("0x{}", hex::encode(signer.signer_address().as_slice())).to_lowercase(),
        "recovered address matches Signer::signer_address()"
    );
}

#[test]
fn envelope_attestation_lifetime_matches_config() {
    let signer = override_signer("TEESQL_CHAIN_INDEXER_ENVELOPE_TEST_LIFETIME", 120);
    let data = json!({"x": 1});
    let as_of = AsOf {
        block_number: 1,
        block_hash: "0x".to_string() + &"00".repeat(32),
        block_timestamp: 1,
        finalized_block: 0,
        safety: Safety::Head,
    };
    let env = envelope::build(data, &as_of, &signer);
    let attestation = env.get("attestation").unwrap();
    let signed_at = attestation
        .get("signed_at")
        .and_then(|v| v.as_u64())
        .unwrap();
    let expires_at = attestation
        .get("expires_at")
        .and_then(|v| v.as_u64())
        .unwrap();
    assert_eq!(expires_at - signed_at, 120, "lifetime threaded through");
}

#[test]
fn as_of_safety_renders_correctly() {
    let h = AsOf {
        block_number: 7,
        block_hash: "0xdead".to_string(),
        block_timestamp: 1,
        finalized_block: 0,
        safety: Safety::Head,
    };
    let f = AsOf {
        safety: Safety::Finalized,
        ..h.clone()
    };
    assert_eq!(h.to_json().get("safety").unwrap(), "head");
    assert_eq!(f.to_json().get("safety").unwrap(), "finalized");
}

// ---- helpers ----

fn recover_address(signature_hex: &str, message_hash: [u8; 32]) -> String {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let raw = signature_hex.strip_prefix("0x").unwrap_or(signature_hex);
    let bytes = hex::decode(raw).expect("hex decode");
    assert_eq!(bytes.len(), 65, "recoverable signature is 65 bytes");
    let recid_byte = bytes[64];
    let recid = RecoveryId::from_byte(recid_byte.wrapping_sub(27)).expect("recid in range");
    let sig = Signature::from_slice(&bytes[..64]).expect("signature parse");
    let vk = VerifyingKey::recover_from_prehash(&message_hash, &sig, recid).expect("recover");
    let encoded = vk.to_encoded_point(false);
    let pubkey = encoded.as_bytes();
    let mut hasher = Keccak256::new();
    hasher.update(&pubkey[1..]);
    let h = hasher.finalize();
    format!("0x{}", hex::encode(&h[12..]))
}
