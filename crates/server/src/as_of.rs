//! `as_of` resolver — produces the §7.1 envelope's `as_of` block from
//! the requested safety mode plus an optional `?as_of_block` override.
//!
//! Three flavors:
//!
//! - **Head** (default) — read `chain_state.head_block` and the row in
//!   `blocks` for that block. Reorg-prone reads.
//! - **Finalized** — serve the answer as of `chain_state.finalized_block`,
//!   which the ingest worker advances to `head - FINALITY_DEPTH`. The
//!   handler replays events up to the finalized cursor before signing.
//! - **Historical** (`?as_of_block=N`) — embed `block_number=N`, look
//!   up `block_hash` / `block_timestamp` from `blocks`, and let the
//!   handler replay events up to N through the materializer.
//!
//! `?safety` and `?as_of_block` are mutually exclusive — the route
//! layer rejects the combination with 400.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;

use crate::error::ApiError;
use teesql_chain_indexer_core::store::EventStore;

/// Read-side safety mode. Default `Head`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Safety {
    #[default]
    Head,
    Finalized,
}

impl Safety {
    pub fn parse(s: &str) -> Result<Self, ApiError> {
        match s {
            "head" => Ok(Safety::Head),
            "finalized" => Ok(Safety::Finalized),
            other => Err(ApiError::bad_request(format!(
                "?safety must be 'head' or 'finalized'; got '{other}'"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Safety::Head => "head",
            Safety::Finalized => "finalized",
        }
    }
}

/// The chain commitment baked into every signed response. Mirrors the
/// `as_of` field of the §7.1 envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsOf {
    pub block_number: u64,
    /// 0x-prefixed lowercase hex.
    pub block_hash: String,
    pub block_timestamp: u64,
    /// Whatever the indexer last advanced its finalized cursor to —
    /// typically `head - 12` on Base.
    pub finalized_block: u64,
    pub safety: Safety,
}

impl AsOf {
    pub fn to_json(&self) -> Value {
        json!({
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "block_timestamp": self.block_timestamp,
            "finalized_block": self.finalized_block,
            "safety": self.safety.as_str(),
        })
    }
}

/// Resolve the `as_of` block for a request.
///
/// `requested_block` is the optional `?as_of_block=N`. When `Some`,
/// the request is a historical read — the handler will replay events
/// up to `N`; this function only fills in the block-hash + timestamp
/// for the envelope.
pub async fn resolve(
    store: &EventStore,
    safety: Safety,
    requested_block: Option<u64>,
) -> Result<AsOf, ApiError> {
    let chain_id = store.chain_id();
    let (head, finalized) = read_cursors(store).await?;

    if let Some(requested) = requested_block {
        if requested > head {
            return Err(ApiError::not_found(format!(
                "as_of_block {requested} is past head {head}"
            )));
        }
        let (block_hash, block_ts) = read_block(store, chain_id, requested).await?;
        return Ok(AsOf {
            block_number: requested,
            block_hash,
            block_timestamp: block_ts,
            finalized_block: finalized,
            // Historical reads aren't safety-gated; render as `head`
            // for symmetry with the safety field's default.
            safety: Safety::Head,
        });
    }

    let block_number = match safety {
        Safety::Head => head,
        Safety::Finalized => finalized,
    };
    let (block_hash, block_ts) = read_block(store, chain_id, block_number).await?;
    Ok(AsOf {
        block_number,
        block_hash,
        block_timestamp: block_ts,
        finalized_block: finalized,
        safety,
    })
}

/// Read `chain_state.head_block` + `chain_state.finalized_block` for
/// this store's chain. Returns `(head, finalized)`.
async fn read_cursors(store: &EventStore) -> Result<(u64, u64), ApiError> {
    let chain_id = store.chain_id();
    let row = sqlx::query(
        "SELECT
            COALESCE((SELECT v FROM chain_state WHERE chain_id = $1 AND k = 'head_block'), '0') AS head,
            COALESCE((SELECT v FROM chain_state WHERE chain_id = $1 AND k = 'finalized_block'), '0') AS finalized",
    )
    .bind(chain_id)
    .fetch_one(store.pool())
    .await
    .map_err(ApiError::from)?;
    let head: String = row.try_get("head").map_err(ApiError::from)?;
    let finalized: String = row.try_get("finalized").map_err(ApiError::from)?;
    let head: u64 = head
        .parse()
        .map_err(|_| ApiError::internal("chain_state.head_block is not a u64".to_string()))?;
    let finalized: u64 = finalized
        .parse()
        .map_err(|_| ApiError::internal("chain_state.finalized_block is not a u64".to_string()))?;
    Ok((head, finalized))
}

async fn read_block(
    store: &EventStore,
    chain_id: i32,
    block_number: u64,
) -> Result<(String, u64), ApiError> {
    let row = sqlx::query("SELECT hash, block_ts FROM blocks WHERE chain_id = $1 AND number = $2")
        .bind(chain_id)
        .bind(block_number as i64)
        .fetch_optional(store.pool())
        .await
        .map_err(ApiError::from)?;
    let Some(row) = row else {
        return Err(ApiError::not_found(format!(
            "no blocks row for chain_id={chain_id} number={block_number}"
        )));
    };
    let hash: Vec<u8> = row.try_get("hash").map_err(ApiError::from)?;
    let ts: i64 = row.try_get("block_ts").map_err(ApiError::from)?;
    Ok((format!("0x{}", hex::encode(hash)), ts as u64))
}
