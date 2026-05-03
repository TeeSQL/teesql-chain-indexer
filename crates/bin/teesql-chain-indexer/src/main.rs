//! `teesql-chain-indexer` — TEE CVM binary that subscribes to one EVM
//! chain's logs, persists every event from every watched contract into
//! Postgres on the monitor cluster (over sqlx-ra-tls), and serves
//! TDX-attested signed responses from a small axum HTTP API.
//!
//! See `docs/specs/chain-indexer.md` (parent monorepo) for the full
//! design — §3.3 for the process layout this `main` realizes, §6.1 for
//! the cold-start order, §8 for the config TOML, §10 for failure modes.

mod config;
mod main_impl;
mod manifest_resolver;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    main_impl::run().await
}
