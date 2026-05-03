//! Signed-envelope shape (spec §7.1) and the canonical-JSON / payload-hash
//! helpers it depends on.
//!
//! `payload_hash = keccak256(canonical_json(data) || canonical_json(as_of))`.
//!
//! Canonicalization is RFC-8785, restricted to the JSON shapes the indexer
//! actually emits: nested objects with string and integer values, integer
//! arrays, arrays of objects. Floats and NaN/±∞ are rejected with a panic —
//! the indexer never produces them (block numbers are ints, addresses and
//! hashes are 0x-prefixed hex strings, timestamps are unix seconds), so a
//! float reaching this layer is a programming bug worth surfacing loudly.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha3::{Digest, Keccak256};

/// Signed-envelope sub-object embedded in every signed API response.
///
/// All hex fields are lowercase, `0x`-prefixed. The signature is 65 bytes
/// (`r || s || v`) recoverable; `v` is `27 + recovery_id` per Ethereum
/// convention, so `ecrecover(payload_hash, signature)` yields the address
/// in `signer_address`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Attestation {
    pub signer_address: String,
    pub signature: String,
    pub payload_hash: String,
    pub signed_at: u64,
    pub expires_at: u64,
}

/// RFC-8785 canonical JSON for the subset of inputs the indexer emits.
///
/// Rules applied:
/// - Object keys sorted ascending by their UTF-16 code-unit sequence.
///   For all-ASCII keys (which is what the indexer ever emits) this
///   collapses to byte-ordered sort, so we sort by the underlying String.
/// - Numbers serialized as their canonical decimal form (i64 or u64
///   `to_string()`; floats panic — see module doc).
/// - Strings JSON-escaped per RFC 8259 with the minimum escape set:
///   `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, plus `\u00XX` for any
///   other control char < 0x20. `/` is NOT escaped.
/// - Arrays preserve insertion order.
/// - No whitespace anywhere.
///
/// # Panics
///
/// Panics if `value` contains a non-integer number (NaN, infinity, or
/// any `f64`). The indexer never produces floats; a float arriving here
/// is a programmer error and should be caught immediately.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    write_value(&mut out, value);
    out
}

/// `keccak256(canonical_json(data) || canonical_json(as_of))` — the
/// digest the response signature is computed over.
pub fn payload_hash(data: &Value, as_of: &Value) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(canonical_json(data));
    h.update(canonical_json(as_of));
    h.finalize().into()
}

fn write_value(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_string(out, s),
        Value::Array(arr) => write_array(out, arr),
        Value::Object(obj) => write_object(out, obj),
    }
}

fn write_number(out: &mut Vec<u8>, n: &serde_json::Number) {
    if let Some(i) = n.as_i64() {
        out.extend_from_slice(i.to_string().as_bytes());
    } else if let Some(u) = n.as_u64() {
        out.extend_from_slice(u.to_string().as_bytes());
    } else {
        // serde_json without `arbitrary_precision` only stores f64 in
        // this branch; we never sign floats. A NaN/inf would already
        // have been rejected by serde_json's parser, so this is the
        // float-with-decimal-point case (e.g. `1.5`).
        panic!(
            "canonical_json: non-integer numbers are not supported \
             (got {n}); the indexer must convert to integer or string \
             before signing"
        );
    }
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{0009}' => out.extend_from_slice(b"\\t"),
            '\u{000A}' => out.extend_from_slice(b"\\n"),
            '\u{000C}' => out.extend_from_slice(b"\\f"),
            '\u{000D}' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                use std::io::Write as _;
                write!(out, "\\u{:04x}", c as u32).expect("Vec<u8> write_fmt cannot fail");
            }
            c => {
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf);
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_array(out: &mut Vec<u8>, arr: &[Value]) {
    out.push(b'[');
    let mut first = true;
    for v in arr {
        if !first {
            out.push(b',');
        }
        first = false;
        write_value(out, v);
    }
    out.push(b']');
}

fn write_object(out: &mut Vec<u8>, obj: &Map<String, Value>) {
    // RFC-8785 sorts by UTF-16 code units. For ASCII keys (all the
    // indexer emits) this is identical to byte-ordered sort. For non-
    // ASCII keys the orderings can differ — guarded against below.
    let mut entries: Vec<(&String, &Value)> = obj.iter().collect();
    debug_assert!(
        entries.iter().all(|(k, _)| k.is_ascii()),
        "canonical_json: non-ASCII object key found; UTF-16 ordering \
         is not implemented for this subset of RFC-8785"
    );
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    out.push(b'{');
    let mut first = true;
    for (k, v) in entries {
        if !first {
            out.push(b',');
        }
        first = false;
        write_string(out, k);
        out.push(b':');
        write_value(out, v);
    }
    out.push(b'}');
}
