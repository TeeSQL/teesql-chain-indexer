//! Shared encoding helpers for converting Solidity primitive types
//! into the JSON shape stored in `events.decoded`.
//!
//! Encoding rules (from the chain-indexer spec):
//! - `address` → `"0x"` + 20-byte lowercase hex (no checksum)
//! - `bytes32` → `"0x"` + 32-byte lowercase hex
//! - `bytes` / `bytesN` → `"0x"` + lowercase hex
//! - `string` → JSON string (handled inline, no helper)
//! - `uintN` for `N >= 64` → JSON string of decimal (avoid f64 precision loss)
//! - `uintN` for `N <= 32` → JSON number (no precision loss in f64)

use alloy::primitives::{Address, FixedBytes, U256};
use serde_json::Value;

/// `address` → `"0x"` + 40 lowercase hex chars. No EIP-55 mixed-case;
/// consumers checksum-format on display if they want.
pub fn address_to_json(addr: &Address) -> Value {
    Value::String(format!("0x{}", hex::encode(addr.as_slice())))
}

/// `bytes32` (and any `FixedBytes<32>`-shaped value like a topic) →
/// `"0x"` + 64 lowercase hex chars.
pub fn bytes32_to_json(b: &FixedBytes<32>) -> Value {
    Value::String(format!("0x{}", hex::encode(b.as_slice())))
}

/// Variable-length `bytes` → `"0x"` + lowercase hex of the bytes.
/// Empty input → `"0x"`.
pub fn bytes_to_json(b: &[u8]) -> Value {
    Value::String(format!("0x{}", hex::encode(b)))
}

/// `uint256` → JSON string of the decimal value. f64 cannot represent
/// values past 2^53 without precision loss; serializing as a string
/// keeps the full 256-bit width intact across any consumer.
pub fn uint256_to_json(u: &U256) -> Value {
    Value::String(u.to_string())
}

/// `uint64` → JSON string of the decimal value. Encoded as a string
/// for the same reason as `uint256_to_json`: `uint64::MAX = 2^64 - 1`
/// is past f64's 2^53 lossless range, so serializing through a JSON
/// number would silently round on extreme values. Operationally
/// nonces and timestamps stay well below 2^53, but keeping the wire
/// shape consistent across all uintN avoids special-casing on the
/// consumer side.
pub fn uint64_to_json(u: u64) -> Value {
    Value::String(u.to_string())
}

/// `uint8` → JSON number. `uint8` fits trivially in f64 (max 255), so
/// emitting a number rather than a string is both safe and the more
/// natural shape for downstream JSON consumers (e.g. status codes
/// like `1=ACCEPTED`, `3=COMPLETED`). Spec §5.3 uses uint8 for the
/// `status` enum on `ControlAck`.
pub fn uint8_to_json(u: u8) -> Value {
    Value::Number(serde_json::Number::from(u))
}

/// `bytes32[]` → JSON array of `"0x"` + 64-hex-char strings. Used by
/// `ControlInstructionBroadcast.targetMembers` (spec §5.3) where the
/// array is non-indexed (an indexed dynamic-array topic only hashes
/// the array head, defeating per-member filtering). Empty array
/// preserves "broadcast to all" semantics — see spec §5.6.
pub fn bytes32_array_to_json(items: &[FixedBytes<32>]) -> Value {
    Value::Array(items.iter().map(bytes32_to_json).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_lowercases_no_checksum() {
        let addr: Address = "0xfBd65E6b30f40db87159A5d3a390Fc9C2bd87E11"
            .parse()
            .unwrap();
        let v = address_to_json(&addr);
        assert_eq!(
            v.as_str().unwrap(),
            "0xfbd65e6b30f40db87159a5d3a390fc9c2bd87e11"
        );
    }

    #[test]
    fn bytes32_lowercases() {
        let b = FixedBytes::<32>::from([0xab; 32]);
        let v = bytes32_to_json(&b);
        assert_eq!(
            v.as_str().unwrap(),
            "0xabababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn bytes_empty_is_zero_x() {
        assert_eq!(bytes_to_json(&[]).as_str().unwrap(), "0x");
    }

    #[test]
    fn bytes_arbitrary_lowercases() {
        assert_eq!(
            bytes_to_json(&[0xde, 0xad, 0xbe, 0xef]).as_str().unwrap(),
            "0xdeadbeef"
        );
    }

    #[test]
    fn uint256_serializes_as_decimal_string() {
        let u = U256::from(45_491_234u64);
        assert_eq!(uint256_to_json(&u).as_str().unwrap(), "45491234");
    }

    #[test]
    fn uint256_max_keeps_full_width() {
        // 2^256 - 1, well past f64 representable range.
        let u = U256::MAX;
        assert_eq!(
            uint256_to_json(&u).as_str().unwrap(),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }

    #[test]
    fn uint64_serializes_as_decimal_string() {
        assert_eq!(uint64_to_json(0).as_str().unwrap(), "0");
        assert_eq!(uint64_to_json(42).as_str().unwrap(), "42");
        assert_eq!(
            uint64_to_json(u64::MAX).as_str().unwrap(),
            "18446744073709551615"
        );
    }

    #[test]
    fn uint8_serializes_as_json_number() {
        // Status codes from spec §5.3 — 1=ACCEPTED through 6=EXPIRED.
        let v = uint8_to_json(1);
        assert_eq!(v.as_u64(), Some(1));
        let v = uint8_to_json(6);
        assert_eq!(v.as_u64(), Some(6));
        // Boundary: u8::MAX still fits.
        let v = uint8_to_json(255);
        assert_eq!(v.as_u64(), Some(255));
    }

    #[test]
    fn bytes32_array_empty_serializes_as_empty_array() {
        // `targetMembers = []` is the wire shape for "broadcast to
        // all members" per spec §5.6. Pin the empty array keeping
        // its array shape (not null, not omitted) so consumers can
        // pattern-match without a presence check.
        let v = bytes32_array_to_json(&[]);
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 0);
    }

    #[test]
    fn bytes32_array_serializes_each_element_as_hex_string() {
        let items = vec![
            FixedBytes::<32>::from([0xaa; 32]),
            FixedBytes::<32>::from([0x55; 32]),
        ];
        let v = bytes32_array_to_json(&items);
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[0].as_str().unwrap(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            arr[1].as_str().unwrap(),
            "0x5555555555555555555555555555555555555555555555555555555555555555"
        );
    }
}
