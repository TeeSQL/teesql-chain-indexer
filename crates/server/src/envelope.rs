//! Signed-response envelope builder. Spec §7.1 fixes the wire shape:
//!
//! ```json
//! {
//!   "data": {...},
//!   "as_of": { "block_number", "block_hash", "block_timestamp",
//!              "finalized_block", "safety" },
//!   "attestation": { "signer_address", "signature",
//!                    "payload_hash", "signed_at", "expires_at" }
//! }
//! ```
//!
//! Every read endpoint that returns a signed answer flows through
//! [`build`]. The function is transport-agnostic — REST returns the
//! `serde_json::Value` directly under `axum::Json`; gRPC converts it
//! into `prost_types::Struct` via the `to_proto_struct` helper.

use serde_json::{json, Value};

use crate::as_of::AsOf;
use teesql_chain_indexer_attest::Signer;

/// Build the signed envelope for a successful read.
///
/// Caller passes the materialized payload plus the resolved
/// `as_of`; this fn renders both into JSON, asks the Signer to
/// produce an attestation, and assembles the §7.1 envelope. The
/// envelope is also the cache value persisted in
/// `historical_query_cache` for hot historical re-reads — the
/// `attestation` is pre-signed and safe to serve as-is until
/// `expires_at`.
pub fn build(data: Value, as_of: &AsOf, signer: &Signer) -> Value {
    let as_of_value = as_of.to_json();
    let attestation = signer.sign(&data, &as_of_value);
    json!({
        "data": data,
        "as_of": as_of_value,
        "attestation": attestation,
    })
}

/// Same as [`build`], but inlines a freshly generated TDX quote
/// committing to `keccak256(payload_hash || nonce)`. Used by the
/// `?attest=full&nonce=<hex>` opt-in path; spec §4.2.
pub async fn build_with_fresh_quote(
    data: Value,
    as_of: &AsOf,
    signer: &Signer,
    nonce: [u8; 32],
) -> anyhow::Result<Value> {
    let as_of_value = as_of.to_json();
    let attestation = signer.sign(&data, &as_of_value);
    let payload_hash = parse_hex32(&attestation.payload_hash)?;
    let quote_b64 = signer.fresh_quote(payload_hash, nonce).await?;
    Ok(json!({
        "data": data,
        "as_of": as_of_value,
        "attestation": attestation,
        "quote_b64": quote_b64,
    }))
}

/// Convert a JSON envelope's `data` and `as_of` (both `Value`)
/// plus the [`Attestation`] into the proto-side `SignedResponse`.
/// gRPC handlers call this to mirror the REST shape over the wire.
///
/// Errors only when JSON contains a non-finite f64; in practice
/// every value we put in the envelope is finite.
#[allow(dead_code)]
pub fn into_proto_struct(value: &Value) -> anyhow::Result<prost_types::Struct> {
    use prost_types::value::Kind;
    use prost_types::{ListValue, NullValue, Struct, Value as PValue};

    fn convert(v: &Value) -> anyhow::Result<PValue> {
        let kind = match v {
            Value::Null => Kind::NullValue(NullValue::NullValue as i32),
            Value::Bool(b) => Kind::BoolValue(*b),
            Value::Number(n) => {
                let f = n
                    .as_f64()
                    .ok_or_else(|| anyhow::anyhow!("number not representable as f64: {}", n))?;
                if !f.is_finite() {
                    anyhow::bail!("non-finite f64 in envelope");
                }
                Kind::NumberValue(f)
            }
            Value::String(s) => Kind::StringValue(s.clone()),
            Value::Array(arr) => {
                let mut values = Vec::with_capacity(arr.len());
                for x in arr {
                    values.push(convert(x)?);
                }
                Kind::ListValue(ListValue { values })
            }
            Value::Object(obj) => {
                let mut fields = std::collections::BTreeMap::new();
                for (k, v) in obj {
                    fields.insert(k.clone(), convert(v)?);
                }
                Kind::StructValue(Struct {
                    fields: fields.into_iter().collect(),
                })
            }
        };
        Ok(PValue { kind: Some(kind) })
    }

    let value = convert(value)?;
    match value.kind {
        Some(Kind::StructValue(s)) => Ok(s),
        _ => anyhow::bail!("envelope value is not an object"),
    }
}

fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(raw)?;
    if bytes.len() != 32 {
        anyhow::bail!("payload_hash must be 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
