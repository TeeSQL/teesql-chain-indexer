//! Generic factory + child-contract event indexer. Implements
//! WS subscribe + cold backfill, reorg detection, the `Decoder` and
//! `View` traits, and the sqlx-Postgres event sink. Holds no
//! TeeSQL-specific knowledge; downstream crates layer ABI bindings
//! and materializers on top.

pub mod connection;
pub mod control_dispatch;
pub mod decode;
pub mod ingest;
pub mod quote_recovery;
pub mod r2_mirror;
pub mod reorg;
pub mod schema_preflight;
pub mod store;
pub mod views;

// Top-level re-exports — the surface the bin crate (Agent 7) and the
// teesql-views / teesql-abi crates wire against. Re-exported here so
// downstream code uses `teesql_chain_indexer_core::EventStore`
// instead of fishing through nested modules.
pub use connection::{build_pool, ConnectionConfig};
pub use control_dispatch::{
    BufferedInstr, ControlDispatchOutcome, ControlOrderer, HoleReason, OrdererConfig,
    DEFAULT_CONFIRMATIONS_REQUIRED, DEFAULT_MAX_BUFFER, DEFAULT_MAX_BUFFER_AGE,
};
pub use decode::{DecodedEvent, Decoder};
pub use ingest::{ControlNotifyEvent, Ingestor, IngestorBuilder, NotifyEvent};
pub use quote_recovery::{
    extract_attested_quote_bytes, set_member_wg_pubkey_attested_selector,
    verify_quote_hash_commitment,
};
pub use r2_mirror::{r2_key_for_quote, DisabledR2Mirror, R2QuoteMirror};
pub use reorg::{ReorgError, ReorgHandler};
pub use schema_preflight::verify_required_schema;
pub use store::{
    as_addr, as_hash, ControlHoleRow, ControlInstructionRow, EventStore, MemberQuoteRow,
    WatchedContract,
};
pub use views::View;
