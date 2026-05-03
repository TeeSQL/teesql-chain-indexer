//! sqlx PgPool builder over `sqlx-ra-tls`.
//!
//! Indexer authenticates to the monitor cluster's primary as the
//! `chain_indexer_writer` Postgres role (spec §5). The role is created
//! by `provision.sql`; the wire-level password is the cluster's
//! KMS-derived secret (spec §8 — `TEESQL_INDEXER_CLUSTER_SECRET`).
//!
//! We bypass `sqlx_ra_tls::pg_connect_opts_ra_tls` because that helper
//! enforces username ∈ {teesql_read, teesql_readwrite}, and we need
//! `chain_indexer_writer`. The lower-level `RaTlsForwarder::start`
//! gives us the same mutual-RA-TLS bridge without the username
//! validation.

use std::str::FromStr;
use std::sync::Arc;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::PgPool;
use sqlx_ra_tls::{
    dstack::{get_dstack_client_cert, DstackClientCert},
    RaTlsForwarder, RaTlsOptions, RaTlsVerifier,
};

/// Connection parameters for the chain-indexer database. Mirrors the
/// shape the bin crate parses out of `prod.config.toml`'s
/// `[storage]` table; held here so other consumers (tests, the bin
/// crate, etc.) can build the same pool without re-deriving the
/// glue.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Hostname of the monitor cluster's primary, as resolved from
    /// the cluster's signed leader-TXT manifest. The forwarder opens
    /// mutual RA-TLS to this address on every accept.
    pub target_host: String,
    /// Postgres TLS port on the cluster sidecar (typically `5433`).
    pub target_port: u16,
    /// Database name; spec §5 fixes this at `chain_indexer`, kept as
    /// a parameter so dev / test deployments can override.
    pub database: String,
    /// Postgres role the indexer authenticates as
    /// (`chain_indexer_writer` in production).
    pub username: String,
    /// 64-hex cluster-shared secret (`TEESQL_INDEXER_CLUSTER_SECRET`).
    /// Passed through as the wire-level password; the sidecar's
    /// auth-substitution path validates it against the cluster's
    /// KMS-derived secret.
    pub password_secret: String,
    /// sqlx connection-pool sizing.
    pub max_connections: u32,
}

/// Build a sqlx [`PgPool`] that authenticates over mutual RA-TLS to
/// the cluster sidecar.
///
/// `verifier` is the RA-TLS server-side verifier (typically a
/// `DcapVerifier` configured from `[ra_tls]` in `prod.config.toml`).
/// `client_cert_override` is `None` in production — the dstack guest
/// agent issues a fresh client cert per pool — and `Some` only in
/// tests where we want to inject a pre-built cert.
///
/// The forwarder is intentionally `Box::leak`ed: the indexer holds a
/// single pool for its entire process lifetime, so a tighter-lifetime
/// `Drop` would only complicate ownership without releasing real
/// resources before exit.
pub async fn build_pool(
    cfg: &ConnectionConfig,
    verifier: Arc<dyn RaTlsVerifier>,
    ra_tls_opts: RaTlsOptions,
    client_cert_override: Option<DstackClientCert>,
) -> anyhow::Result<PgPool> {
    let client_cert = match client_cert_override {
        Some(c) => c,
        None => get_dstack_client_cert()
            .await
            .map_err(|e| anyhow::anyhow!("dstack client cert: {e}"))?,
    };

    let forwarder = RaTlsForwarder::start(
        cfg.target_host.clone(),
        cfg.target_port,
        client_cert,
        verifier,
        ra_tls_opts,
    )
    .await
    .map_err(|e| anyhow::anyhow!("RA-TLS forwarder start: {e}"))?;
    let local_addr = forwarder.local_addr;
    // Leak — see function docs. This matches what
    // `pg_connect_opts_ra_tls` does for the same reasons.
    let _: &'static RaTlsForwarder = Box::leak(Box::new(forwarder));

    // Build a clean PgConnectOptions pointing at the forwarder, with
    // ssl_mode=disable (TLS already happened upstream of the local
    // bridge — the sqlx ↔ forwarder leg is plain TCP on loopback).
    let opts = PgConnectOptions::from_str("postgres:///")
        .map_err(|e| anyhow::anyhow!("seed PgConnectOptions: {e}"))?
        .host(&local_addr.ip().to_string())
        .port(local_addr.port())
        .username(&cfg.username)
        .password(&cfg.password_secret)
        .database(&cfg.database)
        .ssl_mode(PgSslMode::Disable);

    let pool = PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .connect_with(opts)
        .await
        .map_err(|e| anyhow::anyhow!("sqlx pool connect: {e}"))?;

    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_config_can_be_cloned() {
        // Sanity: ConnectionConfig is held inside builder structs and
        // shared between threads. Clone keeps it cheap to hand out.
        let cfg = ConnectionConfig {
            target_host: "host".into(),
            target_port: 5433,
            database: "chain_indexer".into(),
            username: "chain_indexer_writer".into(),
            password_secret: "0".repeat(64),
            max_connections: 16,
        };
        let _ = cfg.clone();
    }
}
