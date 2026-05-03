//! Signing-key resolution.
//!
//! Production: call the dstack guest agent `/GetKey` with a stable
//! `(path, purpose)`. The same `app_id` + same purpose yields the same
//! secp256k1 key for the lifetime of that app, so a CVM redeploy that
//! preserves `app_id` keeps the signer; a redeploy that allocates a new
//! `app_id` rotates it (consumers update their pin).
//!
//! Dev/test: an env-var override of 32-byte hex short-circuits the KMS
//! call. The same shape `dns-controller/src/kms.rs` uses, so any harness
//! that already drives one path drives the other.

use anyhow::{anyhow, Context, Result};
use dstack_sdk::dstack_client::DstackClient;
use k256::ecdsa::SigningKey;

use crate::AttestConfig;

pub async fn load_signing_key(cfg: &AttestConfig, dstack: &DstackClient) -> Result<SigningKey> {
    if let Ok(hex_key) = std::env::var(&cfg.override_key_env) {
        let raw = hex_key.strip_prefix("0x").unwrap_or(&hex_key);
        let bytes = hex::decode(raw).context("override key is not hex")?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "{} must be 32 bytes, got {}",
                cfg.override_key_env,
                bytes.len()
            );
        }
        tracing::warn!(
            env = %cfg.override_key_env,
            "using indexer signing key from env override (dev/test only)"
        );
        let arr: [u8; 32] = bytes.try_into().expect("len checked");
        return SigningKey::from_bytes(&arr.into()).map_err(|e| anyhow!("invalid key: {e}"));
    }

    let resp = dstack
        .get_key(Some(cfg.kms_path.clone()), Some(cfg.kms_purpose.clone()))
        .await
        .context("dstack GetKey failed")?;

    let raw = resp.key.strip_prefix("0x").unwrap_or(&resp.key);
    let bytes = hex::decode(raw).context("KMS key is not hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("KMS returned key of {} bytes, expected 32", bytes.len());
    }
    let arr: [u8; 32] = bytes.try_into().expect("len checked");
    SigningKey::from_bytes(&arr.into()).map_err(|e| anyhow!("invalid KMS key: {e}"))
}

/// Returns true iff the override env var is set. Caller uses this to skip
/// the boot-time `get_quote` round-trip — outside a CVM there's no quote
/// to fetch, and we'd rather warn loudly than 503 in tests.
pub fn override_active(cfg: &AttestConfig) -> bool {
    std::env::var(&cfg.override_key_env).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::verifying_key_to_address;

    fn cfg(env_name: &str) -> AttestConfig {
        AttestConfig {
            kms_purpose: "ignored".into(),
            kms_path: String::new(),
            override_key_env: env_name.into(),
            response_lifetime_s: 300,
        }
    }

    #[tokio::test]
    async fn env_override_short_circuits_kms() {
        let var = "TEESQL_INDEXER_TEST_KEY_OK";
        let cfg = cfg(var);
        let raw_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        std::env::set_var(var, raw_hex);
        let client = DstackClient::new(None);
        let sk = load_signing_key(&cfg, &client).await.unwrap();
        std::env::remove_var(var);
        let addr = verifying_key_to_address(sk.verifying_key());
        assert_ne!(addr, [0u8; 20]);
    }

    #[tokio::test]
    async fn rejects_wrong_length_override() {
        let var = "TEESQL_INDEXER_TEST_KEY_SHORT";
        let cfg = cfg(var);
        std::env::set_var(var, "0xdeadbeef");
        let client = DstackClient::new(None);
        let err = load_signing_key(&cfg, &client).await.unwrap_err();
        std::env::remove_var(var);
        assert!(err.to_string().contains("must be 32 bytes"));
    }

    #[tokio::test]
    async fn rejects_non_hex_override() {
        let var = "TEESQL_INDEXER_TEST_KEY_BAD";
        let cfg = cfg(var);
        std::env::set_var(var, "not hex at all");
        let client = DstackClient::new(None);
        let err = load_signing_key(&cfg, &client).await.unwrap_err();
        std::env::remove_var(var);
        assert!(err.to_string().contains("not hex"));
    }
}
