//! Recover raw TDX quote bytes from `setMemberWgPubkeyAttested` tx
//! calldata. Unified-network-design §9.2.
//!
//! The V2 admission event `MemberWgPubkeySetV2` carries the triple
//! `(memberId, wgPubkey, quoteHash)` only — the ~4.5 KB TDX quote bytes
//! are not in the event payload (a single keccak commitment is much
//! cheaper to emit than the raw blob, and storing 4.5 KB in event topics
//! would blow gas / log budgets). To populate `cluster_member_quotes`
//! for the REST quote surface, the indexer recovers the bytes from the
//! originating tx's calldata.
//!
//! The submission path is the data-sidecar's AA UserOp (design §4.4),
//! so the cluster diamond's `setMemberWgPubkeyAttested(...)` invocation
//! may be nested inside an `EntryPoint.handleOps([...])` outer call.
//! Rather than walking AA wrappers explicitly (which would couple this
//! crate to EntryPoint internals + bundler conventions), the extractor
//! scans the raw `tx.input` bytes for the function's 4-byte selector at
//! every possible offset and attempts an ABI decode of the trailing
//! slice. The first decode whose `(memberId, quoteHash)` match the
//! emitting event's bindings wins.
//!
//! The membership check on `(memberId, quoteHash)` defeats a malicious
//! inner-call construction where unrelated bytes inside a larger AA
//! wrapper happen to start with the selector: those decodes either fail
//! outright or produce mismatched bindings.
//!
//! This module deliberately uses alloy's runtime ABI decoder (`DynSolType`)
//! rather than a sol!-generated Call struct, so the core crate stays
//! free of TeeSQL-specific contract bindings (those live in the abi
//! crate, which already depends on core in the other direction).

use alloy::dyn_abi::{DynSolType, DynSolValue};
use alloy::primitives::keccak256;

/// `setMemberWgPubkeyAttested(bytes32,bytes32,bytes)` — the canonical
/// signature used to derive both the 4-byte function selector and the
/// dynamic ABI type used to decode the trailing argument tuple.
const V2_ADMISSION_FN_SIGNATURE: &str = "setMemberWgPubkeyAttested(bytes32,bytes32,bytes)";

/// 4-byte selector for `setMemberWgPubkeyAttested`. Derived from
/// `keccak256(signature)[..4]` at the call site rather than cached in
/// a static so the constant is verifiable by inspection without
/// reaching for lazy-init machinery. The hash is ~free on a 50-byte
/// input on modern CPUs.
pub fn set_member_wg_pubkey_attested_selector() -> [u8; 4] {
    let digest = keccak256(V2_ADMISSION_FN_SIGNATURE.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&digest.as_slice()[..4]);
    out
}

/// Recover the raw TDX quote bytes from a `setMemberWgPubkeyAttested`
/// transaction's calldata. Returns `Ok(Some(quote))` on a successful
/// extraction whose `(memberId, quoteHash)` match the event bindings.
/// Returns `Ok(None)` when no valid match is found — the caller decides
/// whether that's an error (it always is for a real V2 emit, but the
/// caller owns the metric labeling).
pub fn extract_attested_quote_bytes(
    tx_input: &[u8],
    member_id: &[u8; 32],
    quote_hash: &[u8; 32],
) -> anyhow::Result<Option<Vec<u8>>> {
    let selector = set_member_wg_pubkey_attested_selector();
    if tx_input.len() < selector.len() {
        return Ok(None);
    }
    let arg_type = DynSolType::Tuple(vec![
        DynSolType::FixedBytes(32),
        DynSolType::FixedBytes(32),
        DynSolType::Bytes,
    ]);
    // `windows(4)` scans every byte offset cheaply (no allocation per
    // step). The selector is a high-entropy 4-byte value; spurious
    // matches are statistically rare and filtered out by the typed-
    // field check below.
    for (offset, window) in tx_input.windows(selector.len()).enumerate() {
        if window != selector {
            continue;
        }
        let args_start = offset + selector.len();
        if args_start >= tx_input.len() {
            continue;
        }
        let args = &tx_input[args_start..];
        let decoded = match arg_type.abi_decode_params(args) {
            Ok(DynSolValue::Tuple(t)) => t,
            // Non-tuple values cannot match — the type spec is fixed.
            _ => continue,
        };
        if decoded.len() != 3 {
            continue;
        }
        let DynSolValue::FixedBytes(decoded_member, 32) = &decoded[0] else {
            continue;
        };
        let DynSolValue::FixedBytes(decoded_hash, 32) = &decoded[1] else {
            continue;
        };
        let DynSolValue::Bytes(quote) = &decoded[2] else {
            continue;
        };
        if decoded_member.as_slice() == member_id && decoded_hash.as_slice() == quote_hash {
            return Ok(Some(quote.clone()));
        }
        // Selector matched but the decoded `(memberId, quoteHash)`
        // disagree with the event — keep scanning. The most common
        // shape that hits this branch is an AA wrapper whose outer
        // calldata happens to contain a 4-byte sequence equal to the
        // selector; the properly-aligned inner call still wins.
    }
    Ok(None)
}

/// Verify that `keccak256(quote_bytes) == quote_hash`. Returns the
/// computed digest on mismatch so callers can include it in error
/// payloads. The V2 contract already enforces this on chain — this is
/// defense-in-depth so a buggy ingest path cannot silently store bytes
/// that disagree with the on-chain commitment.
pub fn verify_quote_hash_commitment(
    quote_bytes: &[u8],
    expected_quote_hash: &[u8; 32],
) -> Result<(), [u8; 32]> {
    let digest = keccak256(quote_bytes);
    let actual: [u8; 32] = digest.into();
    if &actual == expected_quote_hash {
        Ok(())
    } else {
        Err(actual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, FixedBytes};
    use alloy::sol;
    use alloy::sol_types::SolCall;

    // Local sol!-generated call type — used ONLY by the unit tests to
    // produce canonical ABI-encoded calldata. The runtime decoder under
    // test (`extract_attested_quote_bytes`) reaches for the same shape
    // via dyn-abi without needing this binding.
    sol! {
        #[allow(missing_docs)]
        function setMemberWgPubkeyAttested(
            bytes32 memberId,
            bytes32 quoteHash,
            bytes tdxQuote
        ) external;
    }

    fn make_call_bytes(member_id: [u8; 32], quote_hash: [u8; 32], quote: Vec<u8>) -> Vec<u8> {
        let call = setMemberWgPubkeyAttestedCall {
            memberId: FixedBytes(member_id),
            quoteHash: FixedBytes(quote_hash),
            tdxQuote: Bytes::from(quote),
        };
        call.abi_encode()
    }

    #[test]
    fn selector_matches_keccak256_of_signature() {
        let selector = set_member_wg_pubkey_attested_selector();
        // keccak256("setMemberWgPubkeyAttested(bytes32,bytes32,bytes)")[..4]
        // computed here independently of the helper to keep the test
        // hermetic.
        let digest = keccak256(b"setMemberWgPubkeyAttested(bytes32,bytes32,bytes)");
        assert_eq!(&selector, &digest.as_slice()[..4]);
    }

    #[test]
    fn extracts_quote_from_bare_function_call() {
        let member_id = [0x11u8; 32];
        let quote_hash = [0x22u8; 32];
        let quote = vec![0x33u8; 256];
        let calldata = make_call_bytes(member_id, quote_hash, quote.clone());

        let extracted = extract_attested_quote_bytes(&calldata, &member_id, &quote_hash)
            .unwrap()
            .expect("quote bytes recovered");
        assert_eq!(extracted, quote);
    }

    #[test]
    fn extracts_quote_from_nested_aa_wrapper() {
        // Simulate an outer AA call that hides the V2 call inside an
        // arbitrary prefix + arbitrary suffix. The scan picks up the
        // properly-aligned selector and ignores the surrounding bytes.
        let member_id = [0x44u8; 32];
        let quote_hash = [0x55u8; 32];
        let quote = vec![0x66u8; 128];
        let inner = make_call_bytes(member_id, quote_hash, quote.clone());

        let mut outer = Vec::new();
        outer.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]); // arbitrary prefix
        outer.extend_from_slice(&inner);
        outer.extend_from_slice(&[0xff, 0xee, 0xdd, 0xcc, 0xbb]); // arbitrary suffix

        let extracted = extract_attested_quote_bytes(&outer, &member_id, &quote_hash)
            .unwrap()
            .expect("nested quote recovered");
        assert_eq!(extracted, quote);
    }

    #[test]
    fn rejects_mismatched_member_id() {
        let member_id = [0x77u8; 32];
        let quote_hash = [0x88u8; 32];
        let quote = vec![0x99u8; 64];
        let calldata = make_call_bytes(member_id, quote_hash, quote);

        let other_member = [0xaau8; 32];
        let result = extract_attested_quote_bytes(&calldata, &other_member, &quote_hash).unwrap();
        assert!(
            result.is_none(),
            "decoded mismatching memberId must be rejected"
        );
    }

    #[test]
    fn rejects_mismatched_quote_hash() {
        let member_id = [0xbbu8; 32];
        let quote_hash = [0xccu8; 32];
        let quote = vec![0xddu8; 64];
        let calldata = make_call_bytes(member_id, quote_hash, quote);

        let other_hash = [0xeeu8; 32];
        let result = extract_attested_quote_bytes(&calldata, &member_id, &other_hash).unwrap();
        assert!(
            result.is_none(),
            "decoded mismatching quoteHash must be rejected"
        );
    }

    #[test]
    fn returns_none_when_selector_absent() {
        let input = vec![0u8; 1024];
        let result = extract_attested_quote_bytes(&input, &[0u8; 32], &[0u8; 32]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn returns_none_on_input_shorter_than_selector() {
        let input = vec![0u8; 2];
        let result = extract_attested_quote_bytes(&input, &[0u8; 32], &[0u8; 32]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn round_trip_with_realistic_quote_size() {
        // A real TDX quote is ~4.5 KB. The round-trip should handle
        // that comfortably without exhausting decode buffers.
        let member_id = [0xdeu8; 32];
        let quote_hash = keccak256(vec![0xefu8; 4632]).into();
        let quote = vec![0xefu8; 4632];
        let calldata = make_call_bytes(member_id, quote_hash, quote.clone());

        let extracted = extract_attested_quote_bytes(&calldata, &member_id, &quote_hash)
            .unwrap()
            .expect("4.5 KB quote recovered");
        assert_eq!(extracted, quote);
        assert!(verify_quote_hash_commitment(&extracted, &quote_hash).is_ok());
    }

    #[test]
    fn verify_quote_hash_commitment_accepts_matching_digest() {
        let quote = b"hello world".to_vec();
        let expected: [u8; 32] = keccak256(&quote).into();
        assert!(verify_quote_hash_commitment(&quote, &expected).is_ok());
    }

    #[test]
    fn verify_quote_hash_commitment_rejects_mismatch() {
        let quote = b"hello world".to_vec();
        let wrong = [0u8; 32];
        let err = verify_quote_hash_commitment(&quote, &wrong).unwrap_err();
        let expected: [u8; 32] = keccak256(&quote).into();
        assert_eq!(err, expected, "error carries the actual digest");
    }

    /// End-to-end helper chain that `Ingestor::recover_attested_quote_from_event`
    /// composes:
    ///
    ///   1. parse `(memberId, wgPubkey, quoteHash)` out of the decoded
    ///      event JSON (`parse_bytes32_field`, in `ingest.rs`),
    ///   2. extract the raw quote bytes from the tx calldata
    ///      (`extract_attested_quote_bytes`, here),
    ///   3. verify the on-chain hash commitment
    ///      (`verify_quote_hash_commitment`, here).
    ///
    /// The full method also calls `provider.get_transaction_by_hash`
    /// (skipped here — would need a mock alloy Provider, which is too
    /// heavy a dependency for a unit test) and
    /// `EventStore::upsert_member_quote` (covered by the `#[ignore]`-
    /// gated DB tests in `crates/core/tests/store_tests.rs`). This
    /// test stitches the pure-helper subset together so a refactor
    /// that breaks the round-trip between the decoded payload's
    /// field names and the calldata extractor's bindings trips here.
    #[test]
    fn recovers_quote_end_to_end_from_synthetic_event_and_calldata() {
        // Step 0: synthesize a `MemberWgPubkeySetV2` decoded payload
        // (the shape emitted by `MemberWgPubkeySetV2Decoder` in the
        // abi crate). Hex field names match the contract's camelCase
        // sol! event spelling — this is exactly what the ingestor's
        // `event.decoded` carries.
        let member_id_bytes = [0xa1u8; 32];
        let wg_pubkey_bytes = [0xb2u8; 32];
        let quote = vec![0xc3u8; 4632]; // realistic 4.5 KB TDX quote
        let quote_hash_bytes: [u8; 32] = keccak256(&quote).into();
        let payload = serde_json::json!({
            "memberId":  format!("0x{}", hex::encode(member_id_bytes)),
            "wgPubkey":  format!("0x{}", hex::encode(wg_pubkey_bytes)),
            "quoteHash": format!("0x{}", hex::encode(quote_hash_bytes)),
        });

        // Step 1: pull the three bytes32 fields by name. Inline a
        // local clone of `parse_bytes32_field` to avoid pulling the
        // whole `ingest` module in as a test dep (it's `pub` but lives
        // in a sibling module of `quote_recovery`).
        fn pull_bytes32(payload: &serde_json::Value, field: &str) -> [u8; 32] {
            let s = payload.get(field).and_then(|v| v.as_str()).unwrap();
            let raw = s.strip_prefix("0x").unwrap_or(s);
            let bytes = hex::decode(raw).unwrap();
            let arr: [u8; 32] = bytes.try_into().unwrap();
            arr
        }
        let member_id = pull_bytes32(&payload, "memberId");
        let quote_hash = pull_bytes32(&payload, "quoteHash");
        assert_eq!(member_id, member_id_bytes);
        assert_eq!(quote_hash, quote_hash_bytes);

        // Step 2: synthesize the originating tx's calldata, then
        // recover the quote bytes through the extractor. This mirrors
        // exactly what the real `recover_attested_quote_from_event`
        // does once it has the tx body from `provider.get_transaction_by_hash`.
        let calldata = make_call_bytes(member_id_bytes, quote_hash_bytes, quote.clone());
        let recovered = extract_attested_quote_bytes(&calldata, &member_id, &quote_hash)
            .unwrap()
            .expect("extractor finds the call");
        assert_eq!(recovered, quote);

        // Step 3: defense-in-depth commitment check, same one the
        // ingestor runs before the DB upsert.
        verify_quote_hash_commitment(&recovered, &quote_hash)
            .expect("recovered bytes match the on-chain commitment");
    }

    /// Companion to the success-path helper test above: if the
    /// extractor returns bytes that don't hash to `quoteHash` (bug
    /// in the scanner picked up the wrong inner call), the commitment
    /// check rejects them. This is the safety net that keeps a bad
    /// scan from polluting the `cluster_member_quotes` table.
    #[test]
    fn rejects_recovered_quote_whose_commitment_mismatches() {
        let member_id = [0x11u8; 32];
        let real_quote = vec![0x22u8; 64];
        let real_hash: [u8; 32] = keccak256(&real_quote).into();

        // Tampered: bytes claim to be the quote but the on-chain
        // `quoteHash` is keccak256(some_OTHER_payload). The contract
        // would never have admitted this on chain — the extractor
        // wouldn't ever recover it in practice — but the defensive
        // check ensures a buggy extractor branch can't silently
        // bypass the invariant.
        let tampered = vec![0x99u8; 64];
        let err = verify_quote_hash_commitment(&tampered, &real_hash).unwrap_err();
        let tampered_digest: [u8; 32] = keccak256(&tampered).into();
        assert_eq!(err, tampered_digest);
        assert_ne!(
            err, real_hash,
            "the error carries the bad digest, not the expected one"
        );

        // And explicitly: the (member_id, quote_hash) tuple match
        // inside the scanner is the SECOND line of defense. A
        // tampered calldata constructed with a different `quoteHash`
        // wouldn't even pass the extractor's bindings filter; pin
        // that here too with synthesized calldata.
        let bad_hash = keccak256(b"different payload").into();
        let bad_calldata = make_call_bytes(member_id, bad_hash, tampered);
        let result = extract_attested_quote_bytes(&bad_calldata, &member_id, &real_hash).unwrap();
        assert!(
            result.is_none(),
            "extractor rejects calldata whose embedded quoteHash disagrees with the event's"
        );
    }

    #[test]
    fn ignores_random_selector_collisions_in_surrounding_bytes() {
        // Craft an input where the first 4 bytes happen to equal the
        // selector but the trailing data is garbage that won't decode
        // as our argument tuple. The real call appears later. The
        // scanner must skip the garbage decode-failure and find the
        // real one.
        let member_id = [0x12u8; 32];
        let quote_hash = [0x34u8; 32];
        let quote = vec![0x56u8; 100];
        let real_call = make_call_bytes(member_id, quote_hash, quote.clone());

        let mut input = Vec::new();
        input.extend_from_slice(&set_member_wg_pubkey_attested_selector()); // fake selector at offset 0
        input.extend_from_slice(&[0xffu8; 8]); // garbage that won't decode as bytes32+bytes32+bytes
        input.extend_from_slice(&real_call);

        let extracted = extract_attested_quote_bytes(&input, &member_id, &quote_hash)
            .unwrap()
            .expect("real call recovered after garbage prefix");
        assert_eq!(extracted, quote);
    }
}
