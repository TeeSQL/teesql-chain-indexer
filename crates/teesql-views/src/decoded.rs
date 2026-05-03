//! Typed parsers over the decoder's JSON output. Agent 2's `Decoder`
//! impls emit `serde_json::Value` shapes per event kind; the materializers
//! consume those shapes through this layer so JSON parsing failure modes
//! surface as structured errors rather than panics inside SQL bind paths.
//!
//! Encoding conventions (matched against `alloy`'s default JSON
//! serialization for `sol!`-derived events):
//!
//! - `bytes32` / `address` are 0x-prefixed lowercase hex strings.
//! - `uint256` is a 0x-prefixed hex string (we accept decimal too as
//!   a defensive measure).
//! - `bytes` we treat as text are 0x-prefixed hex; we decode the
//!   bytes and try UTF-8 (TeeSQL `publicEndpoint` values are URLs).
//! - `string` is a bare JSON string.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("missing field `{0}` in decoded payload")]
    MissingField(&'static str),

    #[error("field `{0}` is not a JSON string")]
    NotString(&'static str),

    #[error("invalid hex in field `{field}`: {source}")]
    Hex {
        field: &'static str,
        #[source]
        source: hex::FromHexError,
    },

    #[error("field `{field}` has wrong byte length: expected {expected}, got {got}")]
    WrongLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },

    #[error("invalid integer in field `{field}`: {value}")]
    InvalidInt { field: &'static str, value: String },

    #[error("integer in field `{field}` overflows i64: {value}")]
    Overflow { field: &'static str, value: String },
}

/// Pull a JSON string out by key.
fn get_str<'a>(v: &'a serde_json::Value, key: &'static str) -> Result<&'a str, DecodeError> {
    v.get(key)
        .ok_or(DecodeError::MissingField(key))?
        .as_str()
        .ok_or(DecodeError::NotString(key))
}

/// Decode a 0x-prefixed (or unprefixed) hex string into bytes.
fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, DecodeError> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(stripped).map_err(|source| DecodeError::Hex { field, source })
}

/// Decode a fixed-size byte field (e.g. `bytes32` → `[u8; 32]`).
pub fn fixed_bytes<const N: usize>(
    v: &serde_json::Value,
    key: &'static str,
) -> Result<[u8; N], DecodeError> {
    let raw = decode_hex(key, get_str(v, key)?)?;
    if raw.len() != N {
        return Err(DecodeError::WrongLength {
            field: key,
            expected: N,
            got: raw.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Decode a `bytes32` field — used for `memberId`.
pub fn member_id(v: &serde_json::Value, key: &'static str) -> Result<[u8; 32], DecodeError> {
    fixed_bytes::<32>(v, key)
}

/// Decode an `address` field (20 bytes).
pub fn address(v: &serde_json::Value, key: &'static str) -> Result<[u8; 20], DecodeError> {
    fixed_bytes::<20>(v, key)
}

/// Pull a `string` field as `&str`.
pub fn string<'a>(v: &'a serde_json::Value, key: &'static str) -> Result<&'a str, DecodeError> {
    get_str(v, key)
}

/// Decode a `uint256` field, narrowed to i64 (the storage type for
/// epochs/block numbers in the materialized tables). Accepts hex
/// (`0x...`) or decimal string forms; rejects values that exceed
/// `i64::MAX`. Real epoch values are tiny (single digits in the
/// fleet to date), so a 9-quintillion ceiling is comfortable.
pub fn uint_as_i64(v: &serde_json::Value, key: &'static str) -> Result<i64, DecodeError> {
    let s = get_str(v, key)?.trim();

    let parsed: u128 = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.is_empty() {
            return Err(DecodeError::InvalidInt {
                field: key,
                value: s.to_string(),
            });
        }
        u128::from_str_radix(hex, 16).map_err(|_| DecodeError::InvalidInt {
            field: key,
            value: s.to_string(),
        })?
    } else {
        s.parse::<u128>().map_err(|_| DecodeError::InvalidInt {
            field: key,
            value: s.to_string(),
        })?
    };

    if parsed > i64::MAX as u128 {
        return Err(DecodeError::Overflow {
            field: key,
            value: s.to_string(),
        });
    }
    Ok(parsed as i64)
}

/// Decode a `bytes` field that we treat as a UTF-8 string at the
/// storage layer (`publicEndpoint` is the only such case today —
/// it's an `https://...` URL persisted to `cluster_members.public_endpoint`).
///
/// Falls back to the lowercase 0x-hex repr (and logs a warning at the
/// caller's discretion via the second tuple element being `Err`) if
/// the bytes don't decode as UTF-8.
pub fn bytes_as_utf8_text(
    v: &serde_json::Value,
    key: &'static str,
) -> Result<Result<String, String>, DecodeError> {
    let s = get_str(v, key)?;
    // Defensive: accept bare strings too — if Agent 2 ever switches to
    // emitting `bytes` as decoded UTF-8 directly, we keep working.
    if !s.starts_with("0x") && !s.starts_with("0X") {
        return Ok(Ok(s.to_string()));
    }
    let raw = decode_hex(key, s)?;
    Ok(match String::from_utf8(raw.clone()) {
        Ok(text) => Ok(text),
        Err(_) => Err(format!("0x{}", hex::encode(&raw))),
    })
}

/// Format bytes as 0x-prefixed lowercase hex — the canonical
/// JSON encoding the materializers emit on the read side.
pub fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn member_id_roundtrip() {
        let v = json!({"memberId": "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"});
        let got = member_id(&v, "memberId").unwrap();
        assert_eq!(got[0], 0x01);
        assert_eq!(got[31], 0x20);
    }

    #[test]
    fn address_wrong_length_errors() {
        let v = json!({"a": "0x0102"});
        match address(&v, "a") {
            Err(DecodeError::WrongLength {
                expected: 20,
                got: 2,
                ..
            }) => {}
            other => panic!("expected WrongLength, got {:?}", other),
        }
    }

    #[test]
    fn uint_hex_and_decimal() {
        let v_hex = json!({"epoch": "0x2a"});
        assert_eq!(uint_as_i64(&v_hex, "epoch").unwrap(), 42);
        let v_dec = json!({"epoch": "42"});
        assert_eq!(uint_as_i64(&v_dec, "epoch").unwrap(), 42);
    }

    #[test]
    fn uint_rejects_overflow() {
        let v = json!({"e": "0x80000000000000000000000000000000"}); // > 2^127
        assert!(matches!(
            uint_as_i64(&v, "e"),
            Err(DecodeError::Overflow { .. })
        ));
    }

    #[test]
    fn bytes_as_utf8_decodes_url() {
        let url = "https://abc.phala.network";
        let hex_url = format!("0x{}", hex::encode(url));
        let v = json!({"publicEndpoint": hex_url});
        let got = bytes_as_utf8_text(&v, "publicEndpoint").unwrap().unwrap();
        assert_eq!(got, url);
    }

    #[test]
    fn bytes_as_utf8_falls_back_on_invalid_utf8() {
        let v = json!({"x": "0xff"});
        let got = bytes_as_utf8_text(&v, "x").unwrap();
        assert!(got.is_err(), "expected UTF-8 fallback");
    }

    #[test]
    fn missing_field_is_typed() {
        let v = json!({});
        assert!(matches!(
            member_id(&v, "memberId"),
            Err(DecodeError::MissingField("memberId"))
        ));
    }
}
