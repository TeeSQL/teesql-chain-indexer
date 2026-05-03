//! End-to-end signing tests.
//!
//! Boots a `Signer` via the env-override path, signs a representative
//! payload, recovers the signer address from the signature, and asserts
//! the recovered address matches the one in the envelope. This is what
//! a consumer SDK verifies on every signed response, so the test
//! mirrors that exact recovery path.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde_json::json;
use teesql_chain_indexer_attest::{payload_hash, verifying_key_to_address, AttestConfig, Signer};

const FIXED_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn cfg(env: &str) -> AttestConfig {
    AttestConfig {
        kms_purpose: "test".into(),
        kms_path: String::new(),
        override_key_env: env.into(),
        response_lifetime_s: 300,
    }
}

async fn boot_signer(env: &str) -> Signer {
    std::env::set_var(env, FIXED_HEX);
    let s = Signer::from_dstack(&cfg(env)).await.unwrap();
    std::env::remove_var(env);
    s
}

#[tokio::test]
async fn signer_address_is_deterministic_across_boots() {
    let a = boot_signer("TEESQL_INDEXER_E2E_DET_A").await;
    let b = boot_signer("TEESQL_INDEXER_E2E_DET_B").await;
    assert_eq!(a.signer_address(), b.signer_address());
}

#[tokio::test]
async fn signed_envelope_recovers_to_signer_address() {
    let signer = boot_signer("TEESQL_INDEXER_E2E_RECOVER").await;
    let data = json!({
        "cluster_address": "0x848c17bdbf42d0067727d74955074d36b9c2ba3e",
        "epoch": 7u64,
        "member_id": "0xea23198e3419ebbb240571a29d0112d9bcbe69c0",
    });
    let as_of = json!({
        "block_hash": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "block_number": 45491234u64,
        "block_timestamp": 1777771500u64,
        "finalized_block": 45491222u64,
        "safety": "head",
    });

    let att = signer.sign(&data, &as_of);

    // payload_hash matches independent computation
    let expected_hash = payload_hash(&data, &as_of);
    assert_eq!(
        att.payload_hash,
        format!("0x{}", hex::encode(expected_hash))
    );

    // signed_at <= expires_at, lifetime is exactly response_lifetime_s
    assert_eq!(att.expires_at - att.signed_at, 300);

    // recover the verifying key and confirm the address matches
    let sig_bytes = hex::decode(att.signature.strip_prefix("0x").unwrap()).unwrap();
    assert_eq!(sig_bytes.len(), 65);
    let signature = Signature::try_from(&sig_bytes[..64]).unwrap();
    let v = sig_bytes[64];
    assert!(
        v == 27 || v == 28,
        "v must be Ethereum-style 27/28, got {v}"
    );
    let recovery = RecoveryId::try_from(v - 27).unwrap();
    let vk = VerifyingKey::recover_from_prehash(&expected_hash, &signature, recovery).unwrap();
    let recovered_addr = verifying_key_to_address(&vk);
    let recovered_hex = format!("0x{}", hex::encode(recovered_addr));
    assert_eq!(recovered_hex, att.signer_address);
}

#[tokio::test]
async fn different_payloads_produce_different_signatures() {
    let signer = boot_signer("TEESQL_INDEXER_E2E_DIFF").await;
    let as_of = json!({"block_number": 100u64});
    let s1 = signer.sign(&json!({"x": 1}), &as_of);
    let s2 = signer.sign(&json!({"x": 2}), &as_of);
    assert_ne!(s1.signature, s2.signature);
    assert_ne!(s1.payload_hash, s2.payload_hash);
}

#[tokio::test]
async fn signer_address_is_lowercase_hex_with_prefix() {
    let signer = boot_signer("TEESQL_INDEXER_E2E_CASE").await;
    let att = signer.sign(&json!({}), &json!({}));
    assert!(att.signer_address.starts_with("0x"));
    let stripped = att.signer_address.strip_prefix("0x").unwrap();
    assert_eq!(stripped.len(), 40);
    assert!(
        stripped
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "address must be lowercase hex"
    );
}

#[tokio::test]
async fn payload_hash_is_canonical_concatenation() {
    // Sanity check that our payload_hash exposes the same digest the
    // signer is signing over. Consumers compute payload_hash themselves
    // and compare; this guarantees the wire payload_hash matches.
    let signer = boot_signer("TEESQL_INDEXER_E2E_HASH").await;
    let data = json!({"x": "y"});
    let as_of = json!({"block_number": 5u64});
    let envelope = signer.sign(&data, &as_of);
    let expected = payload_hash(&data, &as_of);
    assert_eq!(
        envelope.payload_hash,
        format!("0x{}", hex::encode(expected))
    );
}

#[tokio::test]
async fn fresh_quote_returns_empty_in_override_mode() {
    let signer = boot_signer("TEESQL_INDEXER_E2E_FRESH").await;
    assert!(signer.attestation_disabled());
    let q = signer.fresh_quote([1u8; 32], [2u8; 32]).await.unwrap();
    assert_eq!(q, "");
}
