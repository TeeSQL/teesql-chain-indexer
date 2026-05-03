//! Reorg detection + common-ancestor walk. Spec §6.3.
//!
//! Triggered when a freshly-arrived `newHeads` (or log) reports a
//! `parent_hash` that doesn't match what we stored for `number - 1`.
//! `find_common_ancestor` walks backward, comparing each stored hash
//! to the canonical chain's hash at the same height (queried on
//! demand via `eth_getBlockByNumber`), and returns the deepest height
//! where they agree.
//!
//! Two safety properties:
//!
//! 1. **finality_depth bound.** If the walk goes back more than
//!    `finality_depth` blocks without finding a match, we surface
//!    [`ReorgError::DeeperThanFinality`] to the caller, who is expected
//!    to crash (per spec §10) and let the supervisor restart with a
//!    full cold-start backfill. Base finality is ~12 blocks; a deeper
//!    reorg is catastrophic and should be visible in alerts, not
//!    silently absorbed.
//!
//! 2. **No backwards mutation here.** The handler only *reports* the
//!    common ancestor; the caller is responsible for the
//!    `mark_removed_after` + view-replay choreography. Keeps the
//!    walking loop pure and easy to test against an in-memory mock
//!    provider.

use alloy::eips::BlockNumberOrTag;
use alloy::network::{primitives::HeaderResponse, BlockResponse};
use alloy::providers::Provider;

use crate::store::EventStore;

/// Reorg-handling errors. Bubble out to the ingest worker, which
/// either retries (for transient RPC failures) or escalates (for the
/// finality-bound violation).
#[derive(Debug, thiserror::Error)]
pub enum ReorgError {
    #[error(
        "reorg deeper than finality_depth ({finality_depth} blocks); supervisor restart required"
    )]
    DeeperThanFinality { finality_depth: u64, head: u64 },

    #[error("canonical chain returned no block at height {height}")]
    NoCanonicalBlock { height: u64 },

    #[error("local store has no block at height {height}; backfill gap?")]
    NoLocalBlock { height: u64 },

    #[error(transparent)]
    Provider(anyhow::Error),

    #[error(transparent)]
    Store(#[from] anyhow::Error),
}

/// Stateless walker. Carries only the finality bound; everything
/// else comes in as parameters so the same handler can be re-used
/// across chains in a multi-chain process.
#[derive(Debug, Clone, Copy)]
pub struct ReorgHandler {
    finality_depth: u64,
}

impl ReorgHandler {
    pub fn new(finality_depth: u64) -> Self {
        Self { finality_depth }
    }

    pub fn finality_depth(&self) -> u64 {
        self.finality_depth
    }

    /// Walk back from `head` until the local stored hash matches the
    /// canonical chain's hash at that height. Returns the matching
    /// block number — the caller treats it as the common ancestor.
    ///
    /// `head` is the block number of the head where divergence was
    /// first detected. The walk inspects `head, head-1, ...` because
    /// the head itself may be the canonical block (e.g. a reorg
    /// detected by a `parent_hash` mismatch on incoming `head+1`).
    pub async fn find_common_ancestor<P>(
        &self,
        store: &EventStore,
        provider: &P,
        head: u64,
    ) -> Result<u64, ReorgError>
    where
        P: Provider,
    {
        // Bound the search to `finality_depth + 1` heights. A reorg
        // that survives this many comparisons is by definition deeper
        // than the depth we promised consumers we'd protect against.
        for offset in 0..=self.finality_depth {
            let height = match head.checked_sub(offset) {
                Some(h) => h,
                None => return Ok(0), // genesis is always common
            };

            let local = match store.block_hash_at(height).await? {
                Some(h) => h,
                None => {
                    // We have no record for this height — backfill gap
                    // or block prior to indexer start. Treat as
                    // common-ancestor candidate.
                    return Ok(height);
                }
            };

            let canonical = provider
                .get_block_by_number(BlockNumberOrTag::Number(height))
                .await
                .map_err(|e| ReorgError::Provider(anyhow::Error::new(e)))?
                .ok_or(ReorgError::NoCanonicalBlock { height })?;

            let canonical_hash: [u8; 32] = canonical.header().hash().0;

            if canonical_hash == local {
                tracing::info!(
                    height,
                    rewound_blocks = offset,
                    "reorg common ancestor found"
                );
                return Ok(height);
            }

            tracing::debug!(
                height,
                local_hash = %hex::encode(local),
                canonical_hash = %hex::encode(canonical_hash),
                "reorg walk: hash mismatch, continuing back"
            );
        }

        Err(ReorgError::DeeperThanFinality {
            finality_depth: self.finality_depth,
            head,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finality_depth_round_trips() {
        let h = ReorgHandler::new(12);
        assert_eq!(h.finality_depth(), 12);
    }

    #[test]
    fn deeper_than_finality_error_message_includes_depth() {
        let err = ReorgError::DeeperThanFinality {
            finality_depth: 12,
            head: 100,
        };
        let s = err.to_string();
        assert!(
            s.contains("12"),
            "error message must surface the depth: {s}"
        );
    }
}
