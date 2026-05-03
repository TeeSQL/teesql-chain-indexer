//! Conformance tests for `canonical_json` against the JSON shapes the
//! indexer actually emits. Covers RFC-8785's relevant rules for our
//! subset (sorted object keys, no whitespace, integer numbers, minimal
//! string escapes, array order preserved) and a few golden vectors so
//! consumer-side re-implementations have something to mirror.

use serde_json::json;
use teesql_chain_indexer_attest::canonical_json;

fn cj(v: serde_json::Value) -> String {
    String::from_utf8(canonical_json(&v)).unwrap()
}

#[test]
fn null_bool_int() {
    assert_eq!(cj(serde_json::Value::Null), "null");
    assert_eq!(cj(json!(true)), "true");
    assert_eq!(cj(json!(false)), "false");
    assert_eq!(cj(json!(0)), "0");
    assert_eq!(cj(json!(-1)), "-1");
    assert_eq!(cj(json!(42)), "42");
}

#[test]
fn unsigned_extremes() {
    assert_eq!(cj(json!(u64::MAX)), "18446744073709551615");
    assert_eq!(cj(json!(i64::MIN)), "-9223372036854775808");
    assert_eq!(cj(json!(i64::MAX)), "9223372036854775807");
}

#[test]
fn empty_string_and_basic() {
    assert_eq!(cj(json!("")), "\"\"");
    assert_eq!(cj(json!("hello")), "\"hello\"");
    assert_eq!(cj(json!("0xabc123")), "\"0xabc123\"");
}

#[test]
fn string_escapes_minimal() {
    // RFC 8259 mandates these be escaped; canonical JSON uses the short
    // forms for them and only those.
    assert_eq!(cj(json!("\"")), r#""\"""#);
    assert_eq!(cj(json!("\\")), r#""\\""#);
    assert_eq!(cj(json!("\n")), r#""\n""#);
    assert_eq!(cj(json!("\t")), r#""\t""#);
    assert_eq!(cj(json!("\r")), r#""\r""#);
    assert_eq!(cj(json!("\u{0008}")), r#""\b""#);
    assert_eq!(cj(json!("\u{000C}")), r#""\f""#);
    // Other control chars go to \u00XX (lowercase hex).
    assert_eq!(cj(json!("\u{0001}")), "\"\\u0001\"");
    assert_eq!(cj(json!("\u{001F}")), "\"\\u001f\"");
}

#[test]
fn slash_is_not_escaped() {
    // RFC 8259 lets you escape `/` as `\/`, but RFC-8785 says don't.
    assert_eq!(cj(json!("/")), "\"/\"");
    assert_eq!(cj(json!("https://example.com")), "\"https://example.com\"");
}

#[test]
fn unicode_chars_pass_through() {
    // Non-control chars above 0x1F are emitted as their UTF-8 bytes,
    // not as \uXXXX escape sequences.
    assert_eq!(cj(json!("é")), "\"é\"");
    assert_eq!(cj(json!("中文")), "\"中文\"");
    // emoji (4-byte UTF-8) — pass through as bytes
    assert_eq!(cj(json!("🦀")), "\"🦀\"");
}

#[test]
fn empty_collections() {
    assert_eq!(cj(json!([])), "[]");
    assert_eq!(cj(json!({})), "{}");
}

#[test]
fn array_preserves_order() {
    assert_eq!(cj(json!([3, 1, 2])), "[3,1,2]");
    assert_eq!(cj(json!(["c", "a", "b"])), "[\"c\",\"a\",\"b\"]");
}

#[test]
fn object_keys_sorted() {
    // Insertion order: c, a, b. Sorted output: a, b, c.
    let v = json!({"c": 3, "a": 1, "b": 2});
    assert_eq!(cj(v), r#"{"a":1,"b":2,"c":3}"#);
}

#[test]
fn nested_object_each_level_sorted() {
    let v = json!({
        "outer_b": {"y": 2, "x": 1},
        "outer_a": {"d": 4, "c": 3},
    });
    assert_eq!(
        cj(v),
        r#"{"outer_a":{"c":3,"d":4},"outer_b":{"x":1,"y":2}}"#
    );
}

#[test]
fn no_whitespace_anywhere() {
    let v = json!({
        "a": 1,
        "b": [1, 2, 3],
        "c": {"d": "e"}
    });
    let out = cj(v);
    assert!(!out.contains(' '));
    assert!(!out.contains('\n'));
    assert!(!out.contains('\t'));
}

#[test]
fn realistic_indexer_payload_golden() {
    // Approximates a `/v1/:chain/clusters/:addr/leader` data payload —
    // the canonical form is a stable golden string consumers must
    // produce byte-identically when verifying signed responses.
    let v = json!({
        "cluster_address": "0x848c17bdbf42d0067727d74955074d36b9c2ba3e",
        "epoch": 7u64,
        "member_id": "0xea23198e3419ebbb240571a29d0112d9bcbe69c0",
    });
    let expected = "\
        {\"cluster_address\":\"0x848c17bdbf42d0067727d74955074d36b9c2ba3e\",\
        \"epoch\":7,\
        \"member_id\":\"0xea23198e3419ebbb240571a29d0112d9bcbe69c0\"}";
    assert_eq!(cj(v), expected);
}

#[test]
fn realistic_as_of_golden() {
    let v = json!({
        "block_number": 45491234u64,
        "block_hash": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "block_timestamp": 1777771500u64,
        "finalized_block": 45491222u64,
        "safety": "head",
    });
    let expected = "\
        {\"block_hash\":\"0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\",\
        \"block_number\":45491234,\
        \"block_timestamp\":1777771500,\
        \"finalized_block\":45491222,\
        \"safety\":\"head\"}";
    assert_eq!(cj(v), expected);
}

#[test]
fn array_of_objects_each_sorted() {
    let v = json!([
        {"b": 2, "a": 1},
        {"d": 4, "c": 3},
    ]);
    assert_eq!(cj(v), r#"[{"a":1,"b":2},{"c":3,"d":4}]"#);
}

#[test]
fn idempotent_under_parse_roundtrip() {
    // canonical_json(parse(canonical_json(v))) == canonical_json(v).
    // Stronger than just round-tripping serde_json — it confirms the
    // canonical output is itself parseable JSON whose canonicalization
    // is a fixed point.
    let inputs = vec![
        json!(null),
        json!(true),
        json!(0),
        json!("hello"),
        json!([1, 2, 3]),
        json!({"a": 1, "b": [true, false, null]}),
        json!({"nested": {"keys": "are sorted", "and": ["order", "preserved"]}}),
    ];
    for v in inputs {
        let first = canonical_json(&v);
        let reparsed: serde_json::Value = serde_json::from_slice(&first).unwrap();
        let second = canonical_json(&reparsed);
        assert_eq!(first, second, "canonical form must be a fixed point");
    }
}

#[test]
#[should_panic(expected = "non-integer numbers are not supported")]
fn float_panics() {
    let v = json!(1.5);
    let _ = canonical_json(&v);
}
