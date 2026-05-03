//! Signing-key derivation via dstack-sdk and TDX quote binding for
//! the response-envelope `attestation` field. Owns the cached
//! boot-time quote plus the per-request fresh-quote path used when
//! callers pass `?attest=full&nonce=<hex>`.
//!
//! See `docs/specs/chain-indexer.md` §4 (trust model), §4.1 (cross-check
//! protocol), §4.2 (per-request fresh quote), and §7.1 (signed-envelope
//! shape) for the contract this crate implements.
//!
//! The split:
//! - `kms` — env-override + dstack `get_key` resolution.
//! - `address` — secp256k1 verifying key → 20-byte Ethereum address.
//! - `attestation` — `Attestation` envelope, RFC-8785 canonical JSON,
//!   and `payload_hash`.
//! - `signer` — `Signer` struct that ties them together at boot, plus
//!   the per-request fresh-quote path.

pub mod address;
pub mod attestation;
pub mod kms;
pub mod signer;

pub use address::verifying_key_to_address;
pub use attestation::{canonical_json, payload_hash, Attestation};
pub use signer::{AttestConfig, Signer};
