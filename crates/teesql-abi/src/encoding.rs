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
}
