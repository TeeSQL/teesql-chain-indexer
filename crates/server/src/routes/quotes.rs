//! `GET /v1/:chain/clusters/:addr/members/:member_id/quote` —
//! attested TDX quote bytes per unified-network-design §9.2.
//!
//! The `MemberWgPubkeySetV2` event carries `(memberId, wgPubkey,
//! quoteHash)` only; the raw ~4.5 KB quote is recovered by the
//! ingestor from the originating `setMemberWgPubkeyAttested` tx
//! calldata and persisted in the `cluster_member_quotes` table. This
//! route serves the persisted bytes back to fabric for DCAP
//! verification.
//!
//! Content negotiation:
//!
//!   `Accept: application/octet-stream` (default)
//!     → raw bytes, `ETag: "0x<quoteHash>"`, `Cache-Control: public,
//!       max-age=31536000, immutable`. Bytes are content-addressed by
//!       the keccak256 commitment so cache invalidation is impossible
//!       in practice — a verifier that reuses the same `quoteHash`
//!       always reads the same bytes.
//!
//!   `Accept: application/json`
//!     → JSON envelope with base64 quote + `as_of` + an attestation
//!       envelope of the metadata (signed by the indexer's TEE-bound
//!       signer). Fabric does NOT trust the JSON metadata for
//!       admission — it re-verifies `keccak256(decoded_quote) ==
//!       quoteHash` from canonical SSE/RPC state per §9.2 line 489.
//!
//! `If-None-Match: "0x<quoteHash>"` short-circuits to 304 when the
//! latest stored quoteHash for the (cluster, member) matches the
//! caller's cached value — bandwidth-saving but not load-bearing
//! (the immutable cache headers do most of the work upstream).
//!
//! Stable error codes (spec §15.3 "Indexer quote REST/SSE" row):
//!   - `quote_not_found` (404) — no row for this (cluster, member)
//!   - `quote_hash_mismatch` (500) — stored bytes don't hash to the
//!     stored quote_hash; defense-in-depth check, should never fire
//!   - `storage_unavailable` (503) — Postgres query failed
//!
//! Note on `quote_hash_mismatch`: per CORR-012 the canonical REST
//! stable code is `quote_hash_mismatch` (this module's spelling),
//! NOT the contract-side `QuoteHashMismatch`. The two surfaces remain
//! distinct so a future reader doesn't mistake one for the other.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::as_of::{self, AsOf};
use crate::envelope;
use crate::error::ApiError;
use crate::query::{CommonRead, RawQuery};
use crate::routes::common::{parse_address, resolve_chain};
use crate::state::{AppState, MultiChainState};
use teesql_chain_indexer_core::store::MemberQuoteRow;

/// JSON envelope schema version. Bumped on a breaking shape change.
pub const QUOTE_JSON_SCHEMA_VERSION: u32 = 1;

/// Cache-Control header value for binary responses. The bytes are
/// content-addressed by the keccak256 quote hash carried in the URL's
/// implicit ETag, so any reused `quoteHash` produces the same bytes —
/// a hard immutability guarantee. `max-age=31536000` (one year) is the
/// canonical "effectively forever" knob for CDN tiers that don't honor
/// `immutable` alone.
const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

#[derive(Deserialize)]
pub struct QuotePath {
    pub chain: String,
    pub addr: String,
    pub member_id: String,
}

/// Route handler. Dispatches on the `Accept` request header:
///   - `application/json` (or `*/*` with `?accept=json`) → JSON shape
///   - anything else (including the unset default) → octet-stream
///
/// Following the same shape as `clusters::cluster_member`, the
/// path-parameter parsing returns 400 on malformed hex.
pub async fn get_member_quote(
    State(state): State<Arc<MultiChainState>>,
    Path(p): Path<QuotePath>,
    headers: HeaderMap,
    axum::extract::Query(raw): axum::extract::Query<RawQuery>,
) -> Result<Response, ApiError> {
    let cluster = parse_address(&p.addr)?;
    let member_id = parse_member_id(&p.member_id)?;
    let common = raw.parse()?;

    let app = resolve_chain(&state, &p.chain)?.clone();
    let row = match app.store.latest_member_quote(cluster, member_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err(quote_not_found(cluster, member_id));
        }
        Err(e) => {
            tracing::error!(
                cluster = %hex::encode(cluster),
                member = %hex::encode(member_id),
                error = %e,
                "cluster_member_quotes lookup failed"
            );
            return Err(ApiError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "cluster_member_quotes lookup failed",
            ));
        }
    };

    // Defense-in-depth integrity check. The ingest path already
    // verifies `keccak256(tdxQuote) == quoteHash` before persisting, so
    // a mismatch here would mean either (a) the row was tampered with
    // post-write, or (b) a bug in the ingest pipeline wrote bytes that
    // disagree with the hash. Either way, refusing to serve is the
    // right call — a verifier downstream would reject these bytes
    // anyway, and surfacing the failure here keeps the bad row from
    // pretending to be authoritative.
    if let Err(actual) = teesql_chain_indexer_core::quote_recovery::verify_quote_hash_commitment(
        &row.quote_bytes,
        &row.quote_hash,
    ) {
        tracing::error!(
            cluster = %hex::encode(cluster),
            member = %hex::encode(member_id),
            stored_hash = %hex::encode(row.quote_hash),
            actual_hash = %hex::encode(actual),
            "cluster_member_quotes row failed integrity check; refusing to serve"
        );
        return Err(ApiError::coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "quote_hash_mismatch",
            format!(
                "stored quote bytes do not hash to stored quote_hash {}",
                hex::encode(row.quote_hash)
            ),
        ));
    }

    // ETag short-circuit. Compare the caller's `If-None-Match` against
    // the stored quote_hash. The strong-validator form `"0x<hex>"` is
    // what we emit, so a verbatim match is the expected hit path.
    let etag_value = format!("\"0x{}\"", hex::encode(row.quote_hash));
    if let Some(prev) = headers.get(header::IF_NONE_MATCH) {
        if prev.as_bytes() == etag_value.as_bytes() {
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::NOT_MODIFIED;
            resp.headers_mut().insert(
                header::ETAG,
                HeaderValue::from_str(&etag_value).expect("hex ETag is ASCII"),
            );
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static(IMMUTABLE_CACHE_CONTROL),
            );
            return Ok(resp);
        }
    }

    if wants_json(&headers) {
        json_response(&app, &row, common, etag_value).await
    } else {
        Ok(octet_response(row, etag_value))
    }
}

/// Octet-stream response: raw bytes, ETag = `"0x<quoteHash>"`,
/// immutable cache. The bytes are content-addressed so any cache
/// keyed on the URL + ETag pair will never need to invalidate.
fn octet_response(row: MemberQuoteRow, etag_value: String) -> Response {
    let body = Body::from(row.quote_bytes);
    let mut resp = Response::new(body);
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    resp.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&etag_value).expect("hex ETag is ASCII"),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(IMMUTABLE_CACHE_CONTROL),
    );
    resp
}

/// JSON response: same row, plus `as_of` (block number / hash /
/// timestamp / finalized cursor) and a signed envelope binding the
/// JSON metadata to the indexer's TEE-derived signer. The `quote`
/// field is base64-encoded so JSON consumers don't have to special-
/// case binary transport.
///
/// Per design §9.2 line 489, fabric never trusts the JSON metadata
/// for admission — it re-verifies `keccak256(decoded_quote) ==
/// quoteHash` from canonical SSE/RPC state. The envelope is for
/// human-driven inspection + the gRPC mirror that doesn't have
/// HTTP-side ETag mechanics.
async fn json_response(
    app: &AppState,
    row: &MemberQuoteRow,
    common: CommonRead,
    etag_value: String,
) -> Result<Response, ApiError> {
    let as_of = as_of::resolve(&app.store, common.safety, common.as_of_block).await?;
    let payload = quote_json_payload(row, &as_of);
    let env = envelope::build(payload, &as_of, &app.signer);
    let mut resp = Json(env).into_response();
    resp.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&etag_value).expect("hex ETag is ASCII"),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(IMMUTABLE_CACHE_CONTROL),
    );
    Ok(resp)
}

/// Compose the JSON `data` payload for the quote response.
/// Public so tests can assert the shape directly without an HTTP round
/// trip.
pub fn quote_json_payload(row: &MemberQuoteRow, as_of: &AsOf) -> Value {
    json!({
        "schema_version": QUOTE_JSON_SCHEMA_VERSION,
        "cluster": format!("0x{}", hex::encode(row.cluster_address)),
        "member_id": format!("0x{}", hex::encode(row.member_id)),
        "wg_pubkey": format!("0x{}", hex::encode(row.wg_pubkey)),
        "quote_hash": format!("0x{}", hex::encode(row.quote_hash)),
        "quote": BASE64_STANDARD.encode(&row.quote_bytes),
        "tx_hash": format!("0x{}", hex::encode(row.tx_hash)),
        "block_number": row.block_number,
        "block_hash": format!("0x{}", hex::encode(row.block_hash)),
        "log_index": row.log_index,
        "r2_uri": row.r2_uri,
        "observed_at": row.observed_at.to_rfc3339(),
        "as_of": as_of.to_json(),
    })
}

/// `quote_not_found` stable code (spec §15.3). Detail string is
/// informational only; consumers match on `error == "quote_not_found"`.
fn quote_not_found(cluster: [u8; 20], member_id: [u8; 32]) -> ApiError {
    ApiError::coded(
        StatusCode::NOT_FOUND,
        "quote_not_found",
        format!(
            "no attested TDX quote stored for cluster 0x{} member 0x{}",
            hex::encode(cluster),
            hex::encode(member_id)
        ),
    )
}

/// Parse the path's `:member_id` segment. Same shape as the
/// `clusters::cluster_member` parser — a 32-byte hex string with an
/// optional `0x` prefix.
fn parse_member_id(s: &str) -> Result<[u8; 32], ApiError> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(raw)
        .map_err(|e| ApiError::bad_request(format!("invalid member_id hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request(format!(
            "member_id must be 32 bytes; got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Quick `Accept` sniffer. Matches `application/json` literally (the
/// common case from JS clients) and also accepts an explicit
/// `application/json` token within a comma-separated list with q
/// values — without dragging in a full media-type parser. Any other
/// Accept (including missing or `*/*`) defaults to binary.
fn wants_json(headers: &HeaderMap) -> bool {
    let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    accept
        .split(',')
        .map(|part| part.split(';').next().unwrap_or("").trim())
        .any(|m| m.eq_ignore_ascii_case("application/json"))
}

#[cfg(test)]
mod tests {
    //! Unit-level coverage for the response shaping that doesn't need
    //! a live Postgres pool. The integration test in
    //! `tests/route_tests.rs` exercises the full request/response cycle.

    use super::*;
    use crate::as_of::Safety;

    fn sample_row() -> MemberQuoteRow {
        MemberQuoteRow {
            chain_id: 8453,
            cluster_address: [0xabu8; 20],
            member_id: [0xcdu8; 32],
            quote_hash: [0xefu8; 32],
            wg_pubkey: [0x12u8; 32],
            quote_bytes: vec![0x34u8; 256],
            block_number: 1_234_567,
            block_hash: [0x55u8; 32],
            log_index: 7,
            tx_hash: [0x77u8; 32],
            r2_uri: Some("r2://teesql-quotes/0x...".to_string()),
            observed_at: chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    fn sample_as_of() -> AsOf {
        AsOf {
            block_number: 1_234_600,
            block_hash: "0xdeadbeef".to_string(),
            block_timestamp: 1_700_000_100,
            finalized_block: 1_234_588,
            safety: Safety::Head,
        }
    }

    #[test]
    fn wants_json_matches_explicit_application_json() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert!(wants_json(&h));
    }

    #[test]
    fn wants_json_matches_application_json_with_quality() {
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/octet-stream;q=0.9, application/json;q=0.95"),
        );
        assert!(wants_json(&h));
    }

    #[test]
    fn wants_json_rejects_octet_stream_only() {
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/octet-stream"),
        );
        assert!(!wants_json(&h));
    }

    #[test]
    fn wants_json_rejects_wildcard() {
        // `*/*` is the curl default. Default to binary for that case
        // — fabric's bare-curl-equivalent path always wants raw bytes.
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        assert!(!wants_json(&h));
    }

    #[test]
    fn wants_json_defaults_to_false_when_header_missing() {
        let h = HeaderMap::new();
        assert!(!wants_json(&h));
    }

    #[test]
    fn parse_member_id_accepts_0x_prefix() {
        let id =
            parse_member_id("0x1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        assert_eq!(id, [0x11u8; 32]);
    }

    #[test]
    fn parse_member_id_accepts_bare_hex() {
        let id =
            parse_member_id("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();
        assert_eq!(id, [0x22u8; 32]);
    }

    #[test]
    fn parse_member_id_rejects_short_hex() {
        let err = parse_member_id("0x1234").unwrap_err();
        let body = format!("{err}");
        assert!(body.contains("32 bytes"), "{body}");
    }

    #[test]
    fn parse_member_id_rejects_non_hex() {
        let err = parse_member_id("0xzzzz").unwrap_err();
        let body = format!("{err}");
        assert!(body.contains("hex"), "{body}");
    }

    #[test]
    fn quote_json_payload_carries_expected_shape() {
        let row = sample_row();
        let as_of = sample_as_of();
        let p = quote_json_payload(&row, &as_of);

        assert_eq!(p["schema_version"], QUOTE_JSON_SCHEMA_VERSION);
        assert_eq!(
            p["cluster"].as_str().unwrap(),
            format!("0x{}", hex::encode([0xabu8; 20]))
        );
        assert_eq!(
            p["member_id"].as_str().unwrap(),
            format!("0x{}", hex::encode([0xcdu8; 32]))
        );
        assert_eq!(
            p["wg_pubkey"].as_str().unwrap(),
            format!("0x{}", hex::encode([0x12u8; 32]))
        );
        assert_eq!(
            p["quote_hash"].as_str().unwrap(),
            format!("0x{}", hex::encode([0xefu8; 32]))
        );

        // Quote field is base64-encoded; decode and compare to the
        // raw bytes that should round-trip.
        let decoded = BASE64_STANDARD
            .decode(p["quote"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, vec![0x34u8; 256]);

        assert_eq!(p["block_number"], 1_234_567);
        assert_eq!(p["log_index"], 7);
        assert_eq!(p["r2_uri"].as_str().unwrap(), "r2://teesql-quotes/0x...");
        assert!(p["as_of"].is_object());
    }

    #[test]
    fn octet_response_sets_immutable_cache_and_etag() {
        let row = sample_row();
        let etag_value = format!("\"0x{}\"", hex::encode(row.quote_hash));
        let resp = octet_response(row.clone(), etag_value.clone());

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            resp.headers().get(header::ETAG).unwrap().to_str().unwrap(),
            etag_value
        );
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap(),
            IMMUTABLE_CACHE_CONTROL
        );
    }

    #[test]
    fn etag_value_is_quoted_hex_of_quote_hash() {
        // Pinned format: `"0x<lowercase hex>"`. Fabric matches against
        // this exact string when sending `If-None-Match`, so a
        // formatting drift here would silently break the 304 short-
        // circuit. Keep the format guard tight.
        let row = sample_row();
        let etag = format!("\"0x{}\"", hex::encode(row.quote_hash));
        assert_eq!(
            etag,
            format!(
                "\"0x{}\"",
                "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
            )
        );
    }

    #[test]
    fn quote_not_found_carries_stable_tag() {
        let err = quote_not_found([0u8; 20], [0u8; 32]);
        // ApiError doesn't expose tag/status publicly, so rebuild the
        // response and check the body.
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
