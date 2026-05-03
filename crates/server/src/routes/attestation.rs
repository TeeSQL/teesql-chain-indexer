//! `GET /v1/attestation` — TDX quote + signing pubkey for the
//! indexer process. The quote IS the signature; no envelope needed
//! (consumers verify the quote's `report_data` commits to the
//! signing pubkey, then ECDSA-recover that pubkey on every signed
//! response). Spec §4.
//!
//! The boot-time quote is cached for the process lifetime; consumers
//! that want a per-request nonced quote pass `?attest=full&nonce=...`
//! to any signed read endpoint.

use axum::extract::State;
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use crate::state::MultiChainState;

#[derive(Serialize)]
pub struct AttestationResponse {
    pub signer_address: String,
    pub quote_b64: String,
}

pub async fn attestation(State(state): State<Arc<MultiChainState>>) -> Json<AttestationResponse> {
    Json(AttestationResponse {
        signer_address: format!("0x{}", hex::encode(state.signer.signer_address())),
        quote_b64: state.signer.boot_quote_b64().to_string(),
    })
}
