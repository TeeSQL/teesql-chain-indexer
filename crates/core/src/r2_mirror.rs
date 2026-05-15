//! R2 mirror hook for `cluster_member_quotes` (unified-network-design
//! §9.2).
//!
//! Storage backend layering:
//!   - Postgres `cluster_member_quotes` is authoritative for the bytes
//!     the REST quote route serves.
//!   - R2 is an availability mirror — quoted in design §9.2 line 491:
//!     "Storage is backed by Postgres plus an R2 mirror. R2 is
//!     availability-only; verify-by-hash means R2 trust is never
//!     extended."
//!
//! This module defines a minimal `R2QuoteMirror` trait the binary
//! crate (or any wrapper) can implement against whatever R2 client it
//! already pulls in (`crates/monitoring-hub/src/r2/` in the parent
//! monorepo, or a future shared `teesql-r2-bearer` crate). Keeping
//! the trait here lets the ingest pipeline gate on a single dependency
//! injection without dragging an S3 client into `core`.
//!
//! Lifecycle: the trait is intentionally fire-and-forget on the call
//! site. A failed upload doesn't fail the DB write; the row stays
//! authoritative and the periodic backfill (see
//! `cluster_member_quotes_pending_r2_idx`) re-runs the upload on the
//! next sweep. Per the design, R2 trust is never extended, so a
//! missing or stale mirror entry has no admission impact — only an
//! availability impact when fabric falls back to R2 because the
//! indexer is offline.

use async_trait::async_trait;

/// One-row R2 mirror upload. Implementations should write the quote
/// bytes to a deterministic key (e.g. content-addressed by
/// `quote_hash`, like
/// `clusters/<cluster_hex>/members/<member_hex>/quotes/<quote_hash_hex>.bin`)
/// and return the canonical URI the row should record.
///
/// Returning `Ok(None)` lets implementations signal "mirror not
/// configured" without an error path — the call site treats `None`
/// as "skip the row update" and moves on.
#[async_trait]
pub trait R2QuoteMirror: Send + Sync {
    /// Upload `quote_bytes` for `(cluster_address, member_id,
    /// quote_hash)`. Returns the URI the indexer should record in
    /// `cluster_member_quotes.r2_uri`, or `None` when the
    /// implementation declined to upload (mirror disabled).
    ///
    /// Implementations MUST be idempotent: a re-upload of the same
    /// `(cluster, member, quote_hash)` triple is a no-op against the
    /// content-addressed key, so the call is safe to retry on the
    /// periodic backfill path.
    async fn put_quote(
        &self,
        cluster_address: [u8; 20],
        member_id: [u8; 32],
        quote_hash: [u8; 32],
        quote_bytes: &[u8],
    ) -> anyhow::Result<Option<String>>;
}

/// No-op mirror used when R2 isn't configured. Always returns
/// `Ok(None)` so the call site's "update row if Some(uri)" branch
/// short-circuits.
pub struct DisabledR2Mirror;

#[async_trait]
impl R2QuoteMirror for DisabledR2Mirror {
    async fn put_quote(
        &self,
        _cluster_address: [u8; 20],
        _member_id: [u8; 32],
        _quote_hash: [u8; 32],
        _quote_bytes: &[u8],
    ) -> anyhow::Result<Option<String>> {
        Ok(None)
    }
}

/// Build the content-addressed R2 key for a quote. Centralised here so
/// every implementation (real or test) uses the same layout and
/// fabric's R2-direct fallback path can derive the URI deterministically
/// from on-chain `(cluster, member, quoteHash)` without round-tripping
/// through the indexer.
///
/// Layout: `clusters/<cluster_hex>/members/<member_hex>/quotes/<quote_hash_hex>.bin`
/// — hex strings are lowercase, no `0x` prefix. Matches the broader
/// `clusters/<uuid>/{base,wal}` layout already in use for R2 backups
/// (CLAUDE.md "Backup storage on R2").
pub fn r2_key_for_quote(
    cluster_address: [u8; 20],
    member_id: [u8; 32],
    quote_hash: [u8; 32],
) -> String {
    format!(
        "clusters/{}/members/{}/quotes/{}.bin",
        hex::encode(cluster_address),
        hex::encode(member_id),
        hex::encode(quote_hash)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_mirror_returns_none() {
        let m = DisabledR2Mirror;
        let result = m
            .put_quote([0u8; 20], [0u8; 32], [0u8; 32], &[1, 2, 3])
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn r2_key_is_content_addressed() {
        let key = r2_key_for_quote([0xabu8; 20], [0xcdu8; 32], [0xefu8; 32]);
        assert_eq!(
            key,
            "clusters/abababababababababababababababababababab\
             /members/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
             /quotes/efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef.bin"
        );
    }

    #[test]
    fn r2_key_is_deterministic() {
        // Two calls with identical inputs MUST produce identical keys.
        // Fabric's R2-direct fallback (§9.2) reaches the same key by
        // deriving from on-chain state, so any drift here would break
        // the indexer-down quote-fetch path silently.
        let a = r2_key_for_quote([0x11u8; 20], [0x22u8; 32], [0x33u8; 32]);
        let b = r2_key_for_quote([0x11u8; 20], [0x22u8; 32], [0x33u8; 32]);
        assert_eq!(a, b);
    }

    #[test]
    fn r2_key_lowercase_hex_only() {
        let key = r2_key_for_quote([0xABu8; 20], [0xCDu8; 32], [0xEFu8; 32]);
        // The hex crate already lowercases by default; this guard
        // protects against a future swap to a different encoder.
        assert!(
            !key.chars()
                .any(|c| c.is_ascii_uppercase() && c.is_alphabetic()),
            "key must be all-lowercase hex: {key}"
        );
    }
}
