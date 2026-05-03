//! Generic factory + child-contract event indexer. Implements
//! WS subscribe + cold backfill, reorg detection, the `Decoder` and
//! `View` traits, and the sqlx-Postgres event sink. Holds no
//! TeeSQL-specific knowledge; downstream crates layer ABI bindings
//! and materializers on top.

pub mod connection;
pub mod decode;
pub mod ingest;
pub mod reorg;
pub mod store;
pub mod views;

// Top-level re-exports — the surface the bin crate (Agent 7) and the
// teesql-views / teesql-abi crates wire against. Re-exported here so
// downstream code uses `teesql_chain_indexer_core::EventStore`
// instead of fishing through nested modules.
pub use connection::{build_pool, ConnectionConfig};
pub use decode::{DecodedEvent, Decoder};
pub use ingest::{Ingestor, IngestorBuilder, NotifyEvent};
pub use reorg::{ReorgError, ReorgHandler};
pub use store::{as_addr, as_hash, EventStore, WatchedContract};
pub use views::View;
