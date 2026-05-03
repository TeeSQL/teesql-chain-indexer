//! Helpers shared by every signed REST handler — and by the gRPC
//! mirror that calls into the same code path.
//!
//! Every signed read funnels through [`build_signed`], which:
//!   1. Resolves the chain shortname against the multi-chain state.
//!   2. Validates the common query-string surface (parsed already
//!      into [`CommonRead`] by the caller).
//!   3. Resolves the `as_of` block envelope from `chain_state`.
//!   4. Invokes the caller-supplied async closure that builds the
//!      `data` payload (typed JSON returned via serde).
//!   5. Wraps the result in the signed envelope; on `?attest=full`
//!      tacks the fresh quote on as `quote_b64`.
//!   6. On `?as_of_block`, persists the envelope into
//!      `historical_query_cache` so subsequent identical reads
//!      short-circuit through `cache_get`.

use std::future::Future;

use alloy::primitives::Address;
use serde_json::Value;

use crate::as_of::{self, AsOf};
use crate::envelope;
use crate::error::ApiError;
use crate::query::CommonRead;
use crate::state::{AppState, MultiChainState};

/// 0x-prefixed lowercase hex parser for `[u8; 20]` cluster + factory
/// addresses.
pub fn parse_address(s: &str) -> Result<[u8; 20], ApiError> {
    let addr: Address = s
        .parse()
        .map_err(|e| ApiError::bad_request(format!("invalid address '{s}': {e}")))?;
    Ok(addr.into_array())
}

/// Resolve `:chain` against the multi-chain state. 404 on miss.
pub fn resolve_chain<'a>(
    state: &'a MultiChainState,
    chain: &str,
) -> Result<&'a AppState, ApiError> {
    state
        .lookup(chain)
        .ok_or_else(|| ApiError::not_found(format!("unknown chain '{chain}'")))
}

/// Build a signed-envelope response by handing the caller a resolved
/// AppState + AsOf and signing whatever JSON they return. Returns the
/// envelope as `serde_json::Value` so REST and gRPC can wrap it in
/// their respective transports.
///
/// `cache_endpoint`: when `Some(name)` and the request carries
/// `?as_of_block=N`, the rendered envelope (`data` + `attestation`)
/// is upserted into `historical_query_cache` keyed on
/// `(chain_id, cluster, name, as_of_block)`. The hot-historical path
/// short-circuits via [`try_cache_hit`].
///
/// The payload closure receives owned `AppState` (cheap-clone, all
/// Arc fields), `AsOf`, and `CommonRead` so the future can be
/// `'static` and the call-site doesn't have to wrestle with HRTB
/// inference around `&` captures.
pub async fn build_signed<F, Fut>(
    state: &MultiChainState,
    chain: &str,
    common: CommonRead,
    cache_key: Option<CacheKey<'_>>,
    payload_fn: F,
) -> Result<Value, ApiError>
where
    F: FnOnce(AppState, AsOf, CommonRead) -> Fut,
    Fut: Future<Output = Result<Value, ApiError>>,
{
    let app = resolve_chain(state, chain)?.clone();

    if let Some(key) = cache_key.as_ref() {
        if let Some(env) = try_cache_hit(&app, key, &common).await? {
            return Ok(env);
        }
    }

    let as_of = as_of::resolve(&app.store, common.safety, common.as_of_block).await?;
    let data = payload_fn(app.clone(), as_of.clone(), common.clone()).await?;

    let env = if let Some(nonce) = common.fresh_quote_nonce {
        envelope::build_with_fresh_quote(data, &as_of, &app.signer, nonce)
            .await
            .map_err(ApiError::from)?
    } else {
        envelope::build(data, &as_of, &app.signer)
    };

    if let Some(key) = cache_key {
        if let Some(as_of_block) = common.as_of_block {
            persist_cache(&app, &key, as_of_block, &env).await?;
        }
    }

    Ok(env)
}

#[derive(Clone, Copy)]
pub struct CacheKey<'a> {
    pub cluster: [u8; 20],
    pub endpoint: &'a str,
}

async fn try_cache_hit(
    app: &AppState,
    key: &CacheKey<'_>,
    common: &CommonRead,
) -> Result<Option<Value>, ApiError> {
    let Some(as_of_block) = common.as_of_block else {
        return Ok(None);
    };
    if common.fresh_quote_nonce.is_some() {
        // Fresh-quote responses must include a quote bound to a
        // per-request nonce, so they cannot be cached.
        return Ok(None);
    }
    let Some((data, attestation)) = app
        .store
        .cache_get(key.cluster, key.endpoint, as_of_block)
        .await
        .map_err(ApiError::from)?
    else {
        return Ok(None);
    };
    let as_of = as_of::resolve(&app.store, crate::as_of::Safety::Head, Some(as_of_block)).await?;
    Ok(Some(serde_json::json!({
        "data": data,
        "as_of": as_of.to_json(),
        "attestation": attestation,
    })))
}

async fn persist_cache(
    app: &AppState,
    key: &CacheKey<'_>,
    as_of_block: u64,
    envelope: &Value,
) -> Result<(), ApiError> {
    let data = envelope.get("data").cloned().unwrap_or(Value::Null);
    let attestation = envelope.get("attestation").cloned().unwrap_or(Value::Null);
    app.store
        .cache_put(key.cluster, key.endpoint, as_of_block, data, attestation)
        .await
        .map_err(ApiError::from)
}
