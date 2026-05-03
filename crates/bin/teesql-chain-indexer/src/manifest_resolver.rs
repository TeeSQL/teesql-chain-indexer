//! Signed leader-TXT discovery for the storage-side connection.
//!
//! When `TEESQL_INDEXER_TARGET_HOST` is unset, the bin crate falls
//! back to reading `_teesql-leader.<cluster_uuid>.teesql.com` from
//! DNS, verifying the dns-controller's signature against the
//! operator-pinned signer address, and using the manifest's
//! `leader_url` field as the storage target. This means the indexer
//! follows leader rotations without an operator-driven env-var
//! override on every primary bounce — the workaround J1 used during
//! the platform-cluster bring-up.
//!
//! The manifest format mirrors `crates/common/src/manifest.rs` in
//! the parent monorepo (the dns-controller's signer); we re-implement
//! the parse + EIP-191 verifier here rather than dragging the parent
//! crate in as a path dep because the standalone repo is meant to
//! build without the parent monorepo present.
//!
//! Failure mode: if the TXT record is missing, expired, or the
//! signature doesn't recover to the pinned address, we surface the
//! error up to the caller; the bin's `open_storage_pool` then refuses
//! to start. There is no "best-effort" fallback to an unpinned host —
//! that would defeat the trust anchor.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

const MANIFEST_VERSION: &str = "1";

/// One signed-manifest TXT body, post-verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderManifest {
    pub cluster: String,
    pub leader_instance: String,
    pub leader_url: String,
    pub epoch: u64,
    pub valid_until: u64,
}

impl LeaderManifest {
    /// Parse a TXT body of the form
    /// `key=value;key=value;...;sig=0x<...>`, recover the signer,
    /// and return the manifest if and only if the signer matches
    /// `expected_signer` AND `valid_until > now`.
    pub fn parse_and_verify(txt: &str, expected_signer: &[u8; 20]) -> Result<Self> {
        let mut parts: Vec<(&str, &str)> = txt
            .split(';')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p
                    .split_once('=')
                    .ok_or_else(|| anyhow!("malformed field: {p}"))?;
                Ok((k.trim(), v.trim()))
            })
            .collect::<Result<Vec<_>>>()?;

        let sig_hex = parts
            .iter()
            .find(|(k, _)| *k == "sig")
            .map(|(_, v)| (*v).to_string())
            .ok_or_else(|| anyhow!("missing sig field"))?;
        parts.retain(|(k, _)| *k != "sig");

        let field = |k: &str| -> Result<String> {
            parts
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| (*v).to_string())
                .ok_or_else(|| anyhow!("missing {k} field"))
        };
        let v = field("v")?;
        if v != MANIFEST_VERSION {
            return Err(anyhow!("manifest version `{v}` not supported"));
        }
        let cluster = field("cluster")?;
        let leader_instance = field("leader_instance")?;
        let leader_url = field("leader_url")?;
        let epoch: u64 = field("epoch")?.parse().context("epoch parse")?;
        let valid_until: u64 = field("valid_until")?.parse().context("valid_until parse")?;

        let manifest = LeaderManifest {
            cluster: cluster.to_lowercase(),
            leader_instance: leader_instance.to_lowercase(),
            leader_url,
            epoch,
            valid_until,
        };

        // Reconstruct the canonical pre-signing body — sorted key
        // order, joined with `;` — and verify the signature against
        // the EIP-191-prefixed digest. Mirrors the producer's
        // `Manifest::canonical_body` in the parent monorepo.
        let body = manifest.canonical_body();
        let prefix = format!("\x19Ethereum Signed Message:\n{}", body.len());
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(body.as_bytes());
        let digest: [u8; 32] = h.finalize().into();

        let raw_sig = sig_hex.strip_prefix("0x").unwrap_or(&sig_hex);
        let sig_bytes = hex::decode(raw_sig).context("sig hex decode")?;
        if sig_bytes.len() != 65 {
            return Err(anyhow!(
                "sig length {} != 65 bytes (r||s||v)",
                sig_bytes.len()
            ));
        }
        let signature = Signature::from_slice(&sig_bytes[..64]).context("Signature::from_slice")?;
        let recid = RecoveryId::try_from(sig_bytes[64].wrapping_sub(27))
            .map_err(|e| anyhow!("invalid recovery id: {e}"))?;
        let recovered = VerifyingKey::recover_from_prehash(&digest, &signature, recid)
            .context("recover signer")?;
        let recovered_addr = verifying_key_to_address(&recovered);
        if &recovered_addr != expected_signer {
            return Err(anyhow!(
                "manifest signer mismatch: recovered 0x{} but expected 0x{}",
                hex::encode(recovered_addr),
                hex::encode(expected_signer)
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if manifest.valid_until <= now {
            return Err(anyhow!(
                "manifest expired: valid_until={} now={now}",
                manifest.valid_until
            ));
        }

        Ok(manifest)
    }

    fn canonical_body(&self) -> String {
        let parts = [
            ("cluster", self.cluster.to_lowercase()),
            ("epoch", self.epoch.to_string()),
            ("leader_instance", self.leader_instance.to_lowercase()),
            ("leader_url", self.leader_url.clone()),
            ("v", MANIFEST_VERSION.to_string()),
            ("valid_until", self.valid_until.to_string()),
        ];
        parts
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(";")
    }
}

fn verifying_key_to_address(vk: &VerifyingKey) -> [u8; 20] {
    let encoded = vk.to_encoded_point(/*compress=*/ false);
    // Drop the 0x04 prefix; hash the X||Y bytes; take the last 20.
    let xy = &encoded.as_bytes()[1..];
    let mut h = Keccak256::new();
    h.update(xy);
    let digest = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    out
}

/// Resolve `_teesql-leader.<cluster_uuid>.teesql.com`, verify the
/// signature, and return the manifest. Joins multi-chunk TXT bodies
/// (Cloudflare splits at 255 bytes) before parsing.
pub async fn resolve_leader_manifest(
    record_name: &str,
    expected_signer: &[u8; 20],
) -> Result<LeaderManifest> {
    let (cfg, opts) = match hickory_resolver::system_conf::read_system_conf() {
        Ok(pair) => pair,
        Err(_) => (ResolverConfig::cloudflare(), ResolverOpts::default()),
    };
    let resolver = TokioAsyncResolver::tokio(cfg, opts);
    let response = resolver
        .txt_lookup(record_name)
        .await
        .with_context(|| format!("TXT lookup for {record_name}"))?;

    let mut last_err: Option<anyhow::Error> = None;
    for record in response.iter() {
        let body: String = record
            .iter()
            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
            .collect();
        match LeaderManifest::parse_and_verify(&body, expected_signer) {
            Ok(m) => return Ok(m),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no TXT records found at {record_name}")))
}

/// Pull `host[:port]` out of `https://host:port/...` (or `http://`).
/// Returns `(host, Some(port))` when an explicit port was present in
/// the URL, otherwise `(host, None)` so callers can apply their own
/// default. Used to convert the manifest's `leader_url` into the
/// `target_host` + `target_port` `ConnectionConfig` expects.
pub fn host_port_from_leader_url(url: &str) -> Result<(String, Option<u16>)> {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // Cut at the first `/` so a path doesn't leak into the host.
    let authority = stripped.split('/').next().unwrap_or(stripped);
    if let Some((host, port)) = authority.rsplit_once(':') {
        // IPv6 forms (`[::1]:5433`) — keep the bracket.
        if host.starts_with('[') && !host.ends_with(']') {
            // Not a port separator; treat the whole authority as host.
            return Ok((authority.to_string(), None));
        }
        let port: u16 = port.parse().context("port parse")?;
        Ok((host.to_string(), Some(port)))
    } else {
        Ok((authority.to_string(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;

    fn signer() -> (SigningKey, [u8; 20]) {
        let sk = SigningKey::from_bytes(&[0x33u8; 32].into()).unwrap();
        let addr = verifying_key_to_address(sk.verifying_key());
        (sk, addr)
    }

    fn signed_body(m: &LeaderManifest, sk: &SigningKey) -> String {
        let body = m.canonical_body();
        let prefix = format!("\x19Ethereum Signed Message:\n{}", body.len());
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(body.as_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let (sig, recovery): (Signature, RecoveryId) = sk.sign_prehash(&digest).unwrap();
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig.to_bytes());
        sig_bytes[64] = 27 + recovery.to_byte();
        format!("{body};sig=0x{}", hex::encode(sig_bytes))
    }

    #[test]
    fn parse_and_verify_round_trip() {
        let (sk, addr) = signer();
        let m = LeaderManifest {
            cluster: "0x8ada7e9d5d207038c61e8f3ac2916c4a9aabc37e".into(),
            leader_instance: "c7499cdcef3404fddcb46b9acf53cbc64a865473".into(),
            leader_url:
                "https://c7499cdcef3404fddcb46b9acf53cbc64a865473-5432.dstack-base-prod4.phala.network"
                    .into(),
            epoch: 2,
            valid_until: u64::MAX, // not expired
        };
        let body = signed_body(&m, &sk);
        let back = LeaderManifest::parse_and_verify(&body, &addr).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn rejects_wrong_signer() {
        let (sk, _) = signer();
        let m = LeaderManifest {
            cluster: "0x8ada7e9d5d207038c61e8f3ac2916c4a9aabc37e".into(),
            leader_instance: "c7499cdcef3404fddcb46b9acf53cbc64a865473".into(),
            leader_url: "https://x".into(),
            epoch: 1,
            valid_until: u64::MAX,
        };
        let body = signed_body(&m, &sk);
        let bad_addr = [0xffu8; 20];
        let err = LeaderManifest::parse_and_verify(&body, &bad_addr).unwrap_err();
        assert!(format!("{err}").contains("manifest signer mismatch"));
    }

    #[test]
    fn rejects_expired() {
        let (sk, addr) = signer();
        let m = LeaderManifest {
            cluster: "0x8ada7e9d5d207038c61e8f3ac2916c4a9aabc37e".into(),
            leader_instance: "c7499cdcef3404fddcb46b9acf53cbc64a865473".into(),
            leader_url: "https://x".into(),
            epoch: 1,
            valid_until: 0,
        };
        let body = signed_body(&m, &sk);
        let err = LeaderManifest::parse_and_verify(&body, &addr).unwrap_err();
        assert!(format!("{err}").contains("manifest expired"));
    }

    #[test]
    fn host_port_from_phala_gateway_url() {
        let (h, p) = host_port_from_leader_url(
            "https://c7499cdcef3404fddcb46b9acf53cbc64a865473-5432.dstack-base-prod4.phala.network",
        )
        .unwrap();
        assert_eq!(
            h,
            "c7499cdcef3404fddcb46b9acf53cbc64a865473-5432.dstack-base-prod4.phala.network"
        );
        assert_eq!(p, None);

        let (h, p) = host_port_from_leader_url("https://example.com:8443/path/here").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, Some(8443));
    }
}
