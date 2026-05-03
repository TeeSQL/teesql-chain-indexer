//! Shared query-string surface every signed REST endpoint accepts.
//!
//! - `?safety=head|finalized` (default `head`)
//! - `?as_of_block=<u64>` (mutually exclusive with `safety`)
//! - `?attest=full&nonce=<hex>` (opt-in fresh-quote)
//!
//! `parse` validates the combination and produces a [`CommonRead`]
//! the route layer threads through to `as_of::resolve` and the
//! envelope builder.

use serde::Deserialize;

use crate::as_of::Safety;
use crate::error::ApiError;

/// Raw query-string params; deserialized by axum's `Query`.
#[derive(Debug, Deserialize, Default)]
pub struct RawQuery {
    pub safety: Option<String>,
    pub as_of_block: Option<u64>,
    pub attest: Option<String>,
    pub nonce: Option<String>,
}

/// Parsed common-read query params, post-validation.
#[derive(Debug, Clone)]
pub struct CommonRead {
    pub safety: Safety,
    pub as_of_block: Option<u64>,
    pub fresh_quote_nonce: Option<[u8; 32]>,
}

impl RawQuery {
    pub fn parse(self) -> Result<CommonRead, ApiError> {
        let safety_set = self.safety.is_some();
        let as_of_set = self.as_of_block.is_some();
        if safety_set && as_of_set {
            return Err(ApiError::bad_request(
                "?safety and ?as_of_block are mutually exclusive",
            ));
        }
        let safety = match self.safety.as_deref() {
            Some(s) => Safety::parse(s)?,
            None => Safety::Head,
        };
        let fresh_quote_nonce = match (self.attest.as_deref(), self.nonce.as_deref()) {
            (Some("full"), Some(n)) => Some(parse_nonce(n)?),
            (Some("full"), None) => {
                return Err(ApiError::bad_request("?attest=full requires ?nonce=<hex>"))
            }
            (Some(other), _) if other != "full" => {
                return Err(ApiError::bad_request(format!(
                    "?attest must be 'full' or omitted; got '{other}'"
                )))
            }
            _ => None,
        };
        Ok(CommonRead {
            safety,
            as_of_block: self.as_of_block,
            fresh_quote_nonce,
        })
    }
}

fn parse_nonce(s: &str) -> Result<[u8; 32], ApiError> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let bytes =
        hex::decode(raw).map_err(|e| ApiError::bad_request(format!("nonce hex decode: {e}")))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request(format!(
            "nonce must be 32 bytes; got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
