//! Boot-time-derived signer + TDX-quote producer.
//!
//! `Signer::from_dstack` runs once at startup: derive a long-lived
//! secp256k1 key from `dstack get_key`, derive the corresponding
//! Ethereum address, and request a boot-time TDX quote whose
//! `report_data` commits to that address. The quote is cached for the
//! process lifetime and served from `GET /v1/attestation`.
//!
//! Per-response signing (`sign`) is in-process and synchronous — no
//! quote round-trip per call. The boot-time quote already binds the
//! signer pubkey to the attested CVM, so any consumer that has verified
//! the boot quote against an MRTD they trust can verify subsequent
//! signed responses by ECDSA-recovering the signer address and
//! comparing it to the address committed to in the boot quote.
//!
//! The per-request fresh-quote path (`fresh_quote`) is the §4.2
//! affordance for one-shot attestation flows: a caller passes a nonce,
//! the server includes the response's `payload_hash` plus the nonce in
//! the new quote's `report_data`, costing ~50ms per call.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::Address;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use dstack_sdk::dstack_client::DstackClient;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use sha3::{Digest, Keccak256};
use tracing::{info, warn};

use crate::address::verifying_key_to_address;
use crate::attestation::{payload_hash, Attestation};
use crate::kms::{load_signing_key, override_active};

/// Configuration for signer initialization. Wired up by the bin crate
/// from the indexer's `[attestation]` config table; defaults are sane
/// for a CVM deploy.
#[derive(Debug, Clone)]
pub struct AttestConfig {
    /// dstack `purpose` string. Stable across releases — changing it
    /// rotates the signer.
    pub kms_purpose: String,
    /// dstack `path` string. Typically empty.
    pub kms_path: String,
    /// Env-var name whose presence (set to 32-byte hex) short-circuits
    /// the dstack call for dev/test. Quote generation is also skipped
    /// in that mode.
    pub override_key_env: String,
    /// Seconds added to `signed_at` to compute `expires_at`. Spec
    /// default is 300 (5 minutes).
    pub response_lifetime_s: u64,
}

pub struct Signer {
    dstack: DstackClient,
    signing_key: SigningKey,
    signer_address: Address,
    boot_quote_b64: String,
    response_lifetime_s: u64,
    /// True iff the env-var override was used to derive the signing key.
    /// Quote generation is skipped in this mode and `boot_quote_b64`
    /// is empty.
    attestation_disabled: bool,
}

impl Signer {
    /// Boot-time init: derive the signing key (via dstack or override),
    /// then in production mode request a TDX quote committing to
    /// `report_data[0..20] = signer_address`. Returns a ready-to-use
    /// signer.
    pub async fn from_dstack(cfg: &AttestConfig) -> Result<Self> {
        let dstack = DstackClient::new(None);
        let signing_key = load_signing_key(cfg, &dstack)
            .await
            .context("derive signing key")?;
        let addr_bytes = verifying_key_to_address(signing_key.verifying_key());
        let signer_address = Address::from(addr_bytes);

        let attestation_disabled = override_active(cfg);
        let boot_quote_b64 = if attestation_disabled {
            warn!(
                signer_address = %format!("0x{}", hex::encode(addr_bytes)),
                "attestation disabled (env override active); boot quote will be empty"
            );
            String::new()
        } else {
            let mut report_data = [0u8; 64];
            report_data[..20].copy_from_slice(&addr_bytes);
            let resp = dstack
                .get_quote(report_data.to_vec())
                .await
                .context("dstack GetQuote at boot")?;
            quote_response_to_b64(&resp.quote)?
        };

        info!(
            signer_address = %format!("0x{}", hex::encode(addr_bytes)),
            boot_quote_present = !boot_quote_b64.is_empty(),
            "indexer signer ready"
        );

        Ok(Self {
            dstack,
            signing_key,
            signer_address,
            boot_quote_b64,
            response_lifetime_s: cfg.response_lifetime_s,
            attestation_disabled,
        })
    }

    pub fn signer_address(&self) -> Address {
        self.signer_address
    }

    pub fn boot_quote_b64(&self) -> &str {
        &self.boot_quote_b64
    }

    /// True iff env-override mode is active. Server code can use this
    /// to refuse `?attest=full` requests in dev mode rather than
    /// returning empty quotes that look real.
    pub fn attestation_disabled(&self) -> bool {
        self.attestation_disabled
    }

    /// Compute the §7.1 envelope for `(data, as_of)`. Pure + sync —
    /// the heavy lifting (KMS, quote) all happened at boot.
    pub fn sign(&self, data: &serde_json::Value, as_of: &serde_json::Value) -> Attestation {
        let hash = payload_hash(data, as_of);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let signature_hex = sign_prehash_recoverable(&self.signing_key, &hash);

        Attestation {
            signer_address: format!("0x{}", hex::encode(self.signer_address.as_slice())),
            signature: format!("0x{}", signature_hex),
            payload_hash: format!("0x{}", hex::encode(hash)),
            signed_at: now,
            expires_at: now.saturating_add(self.response_lifetime_s),
        }
    }

    /// Request a fresh TDX quote whose `report_data[0..32]` commits to
    /// `keccak256(payload_hash || nonce)`. Spec §4.2; ~50ms per call.
    /// Returns the quote base64-encoded.
    ///
    /// In env-override mode this returns an empty string and emits a
    /// warning rather than calling dstack — callers that want strict
    /// behavior should consult `attestation_disabled()` first.
    pub async fn fresh_quote(&self, payload_hash: [u8; 32], nonce: [u8; 32]) -> Result<String> {
        if self.attestation_disabled {
            warn!("fresh_quote called with attestation disabled; returning empty");
            return Ok(String::new());
        }

        let inner: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(payload_hash);
            h.update(nonce);
            h.finalize().into()
        };
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&inner);

        let resp = self
            .dstack
            .get_quote(report_data.to_vec())
            .await
            .context("dstack GetQuote per-request")?;
        quote_response_to_b64(&resp.quote)
    }
}

/// `dstack-sdk` returns the quote as a hex string. Convert to base64
/// for the wire (matches the §7.1 envelope's `quote_b64` field).
fn quote_response_to_b64(quote_hex: &str) -> Result<String> {
    let raw = quote_hex.strip_prefix("0x").unwrap_or(quote_hex);
    let bytes = hex::decode(raw).context("dstack quote is not hex")?;
    Ok(BASE64_STANDARD.encode(bytes))
}

/// Sign a 32-byte prehash and return a 65-byte recoverable signature
/// hex-encoded *without* the `0x` prefix. Layout: `r(32) || s(32) || v(1)`
/// where `v = 27 + recovery_id` (Ethereum convention; matches what
/// `ecrecover(payload_hash, sig)` expects).
fn sign_prehash_recoverable(sk: &SigningKey, prehash: &[u8; 32]) -> String {
    let (sig, recid): (Signature, RecoveryId) = sk
        .sign_prehash(prehash)
        .expect("k256 sign_prehash on 32-byte input cannot fail");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = 27 + recid.to_byte();
    hex::encode(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::VerifyingKey;
    use serde_json::json;

    fn fixture_signer_with_override(env: &str) -> Signer {
        std::env::set_var(
            env,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        let cfg = AttestConfig {
            kms_purpose: "test".into(),
            kms_path: String::new(),
            override_key_env: env.into(),
            response_lifetime_s: 300,
        };
        let signer = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(Signer::from_dstack(&cfg))
            .unwrap();
        std::env::remove_var(env);
        signer
    }

    #[test]
    fn signer_round_trip_recovers_address() {
        let signer = fixture_signer_with_override("TEESQL_INDEXER_SIGNER_TEST_RT");
        let data = json!({"foo": 1, "bar": "baz"});
        let as_of = json!({"block_number": 100u64});
        let att = signer.sign(&data, &as_of);

        // signer_address field is lowercase hex
        let expected_addr = format!("0x{}", hex::encode(signer.signer_address.as_slice()));
        assert_eq!(att.signer_address, expected_addr);

        // signature is 0x + 130 hex chars (65 bytes)
        let sig_hex = att.signature.strip_prefix("0x").unwrap();
        assert_eq!(sig_hex.len(), 130);
        let sig_bytes = hex::decode(sig_hex).unwrap();
        let recid_byte = sig_bytes[64];
        assert!(recid_byte == 27 || recid_byte == 28, "v must be 27 or 28");

        // payload_hash matches the helper
        let hash = payload_hash(&data, &as_of);
        assert_eq!(att.payload_hash, format!("0x{}", hex::encode(hash)));

        // recover the signer address from the signature and confirm match
        let signature = Signature::try_from(&sig_bytes[..64]).unwrap();
        let recovery = RecoveryId::try_from(recid_byte - 27).unwrap();
        let vk = VerifyingKey::recover_from_prehash(&hash, &signature, recovery).unwrap();
        let recovered = verifying_key_to_address(&vk);
        assert_eq!(format!("0x{}", hex::encode(recovered)), att.signer_address);
    }

    #[test]
    fn override_mode_emits_empty_boot_quote() {
        let signer = fixture_signer_with_override("TEESQL_INDEXER_SIGNER_TEST_BOOT");
        assert!(signer.attestation_disabled());
        assert_eq!(signer.boot_quote_b64(), "");
    }

    #[test]
    fn override_mode_fresh_quote_returns_empty() {
        let signer = fixture_signer_with_override("TEESQL_INDEXER_SIGNER_TEST_FRESH");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let q = rt
            .block_on(signer.fresh_quote([7u8; 32], [9u8; 32]))
            .unwrap();
        assert_eq!(q, "");
    }

    #[test]
    fn quote_response_to_b64_handles_hex_with_and_without_prefix() {
        assert_eq!(quote_response_to_b64("deadbeef").unwrap(), "3q2+7w==");
        assert_eq!(quote_response_to_b64("0xdeadbeef").unwrap(), "3q2+7w==");
    }

    #[test]
    fn quote_response_to_b64_rejects_non_hex() {
        assert!(quote_response_to_b64("not hex").is_err());
    }
}
