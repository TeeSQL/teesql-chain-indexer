//! TOML config for the chain indexer process. Mirrors spec §8 exactly.
//!
//! Hot-reload is out of scope; the indexer restarts to pick up config
//! changes. Secrets never live in the TOML — they arrive via Phala-
//! encrypted env at deploy time and are read by the server / storage
//! layers directly (see `TEESQL_INDEXER_CLUSTER_SECRET` in the deploy
//! compose template).
//!
//! `dead_code` is allowed crate-wide here because under the default
//! (Phase-1) build the trivial `main()` only reads a handful of
//! fields; the rest are consumed by `main_impl.rs` which is feature-
//! gated behind `phase2`. The full struct is intentionally
//! over-specified so a Phase-2 flip needs zero config-shape changes.

#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Top-level config. Loaded once at startup from
/// `--config /etc/teesql-chain-indexer/config.toml`. Field order matches
/// spec §8 so a side-by-side review against the spec is trivial.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Each entry defines one chain this binary serves. The default
    /// deployment runs one process per chain; a single process can
    /// carry multiple `[[chains]]` entries when the operator is
    /// confident the RPC providers are independent enough that one's
    /// outage won't block the others.
    pub chains: Vec<ChainConfig>,

    /// Postgres storage on the monitor cluster, reached over
    /// sqlx-ra-tls.
    pub storage: StorageConfig,

    /// HTTP / SSE listener.
    pub server: ServerConfig,

    /// gRPC listener — typically alongside the REST surface on a
    /// sibling port. Default `enabled = true` so existing deploys
    /// pick it up automatically; default `listen_addr` puts it on
    /// `0.0.0.0:8081` next to the REST `:8080`.
    #[serde(default)]
    pub grpc: GrpcConfig,

    /// dstack-KMS-derived signing key + per-response envelope tunables.
    pub attestation: AttestationConfig,

    /// RA-TLS verifier policy applied to the monitor cluster's
    /// server-side cert when the indexer's sqlx pool dials it.
    pub ra_tls: RaTlsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    /// Path segment in the public REST routes — `/v1/<shortname>/...`.
    /// Lowercase, no slashes; matches the dns-controller's friendly
    /// chain naming (`base`, `base-sepolia`).
    pub shortname: String,

    /// EIP-155 chain id. Written into every `events` / `blocks` /
    /// `cluster_*` row and used as the discriminator in every primary
    /// key, so multi-chain processes can share the same database
    /// without row-level collisions.
    pub chain_id: u64,

    pub rpc_http_url: String,
    pub rpc_ws_url: String,

    /// Factories whose `ClusterDeployed` events expand into watched
    /// child diamonds. Empty is invalid — there has to be at least one
    /// trust pin per chain.
    pub factories: Vec<FactoryConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryConfig {
    /// `0x` + 40 hex. The ERC1967 proxy address; UUPS rotation of the
    /// implementation behind it is transparent to the indexer (the
    /// address is what feeds `eth_getLogs` filters and the `events`
    /// `contract` column).
    pub address: String,

    /// Block number where the factory itself was deployed (or any
    /// block before its first `deployCluster` call). Cold-start
    /// backfill scans `ClusterDeployed` events forward from here;
    /// each child diamond inherits this lower bound the first time
    /// it shows up.
    pub from_block: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// On-chain UUID of the monitor cluster, e.g. `6dee00f10e`. The
    /// signed leader-TXT manifest at
    /// `_teesql-leader.<cluster_uuid>.teesql.com` is what the
    /// sqlx-ra-tls dialer follows to reach the current primary.
    pub cluster_uuid: String,

    /// Postgres database name; provisioned by `deploy/provision.sql`.
    pub database: String,

    /// Login role; see `deploy/provision.sql` for the role + grants.
    pub username: String,

    /// sqlx pool size cap. Spec §8 default is 16.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// `host:port` form; bound by axum at boot.
    pub listen_addr: String,

    /// Per-source-IP RPS cap. 50 is the spec §8 default.
    #[serde(default = "default_rate_limit_rps")]
    pub rate_limit_rps: u32,

    /// Cap on simultaneous open SSE connections process-wide. Past
    /// this the SSE handler returns 503 with `Retry-After`; consumers
    /// fall back to polling.
    #[serde(default = "default_sse_max_connections")]
    pub sse_max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcConfig {
    /// `host:port` form bound by tonic. Default keeps gRPC on the
    /// sibling port to REST so a single Phala-gateway hostname can
    /// front both transports.
    #[serde(default = "default_grpc_listen_addr")]
    pub listen_addr: String,

    /// Operator escape hatch — set to `false` to skip the gRPC
    /// listener entirely. Default `true` so the gRPC surface ships
    /// to existing deploys without an explicit opt-in.
    #[serde(default = "default_grpc_enabled")]
    pub enabled: bool,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_grpc_listen_addr(),
            enabled: default_grpc_enabled(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationConfig {
    /// Purpose handed to `dstack get_key` — the indexer's signing key
    /// is bound to `(app_id, kms_purpose)`. Default is the spec §4
    /// constant; the override is here for dev / testing where two
    /// distinct indexers share an `app_id`.
    #[serde(default = "default_kms_purpose")]
    pub kms_purpose: String,

    /// Signed-envelope `expires_at` lifetime in seconds. Matches the
    /// dns-controller manifest convention (5 min default).
    #[serde(default = "default_response_lifetime_s")]
    pub response_lifetime_s: u64,

    /// Number of blocks behind head to consider "finalized". Drives
    /// the `?safety=finalized` long-poll cursor and the reorg-depth
    /// guard. Spec §6.3 default is 12 for Base.
    #[serde(default = "default_finality_depth")]
    pub finality_depth: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RaTlsConfig {
    /// `dcap` — local DCAP via dcap-qvl, the post-2026-04-24 default
    /// shared with the hub. The only verifier wired in v1; anything
    /// else is a config error. `intel` (Intel Trust Authority round-
    /// trip) is reserved for a future wiring of `IntelApiVerifier`
    /// and must be added back to this allowlist alongside that change.
    #[serde(default = "default_ra_tls_verifier")]
    pub verifier: String,

    /// Optional MRTD allowlist for the monitor cluster's server cert.
    /// Empty = accept any TDX-attested counterparty (defense in depth
    /// the schema allows but production deployments should populate).
    #[serde(default)]
    pub allowed_mrtds: Vec<String>,

    /// Hard fail on TDX debug-mode counterparties when false. Production
    /// must keep this false; dev simulator deploys may flip it.
    #[serde(default)]
    pub allow_debug_mode: bool,

    /// Hard fail on dstack simulator (no real quote) counterparties when
    /// false. Production must keep this false.
    #[serde(default)]
    pub allow_simulator: bool,
}

fn default_max_connections() -> u32 {
    16
}
fn default_rate_limit_rps() -> u32 {
    50
}
fn default_sse_max_connections() -> u32 {
    1000
}
fn default_kms_purpose() -> String {
    "teesql-chain-indexer-sign".into()
}
fn default_response_lifetime_s() -> u64 {
    300
}
fn default_finality_depth() -> u64 {
    12
}
fn default_ra_tls_verifier() -> String {
    "dcap".into()
}
fn default_grpc_listen_addr() -> String {
    "0.0.0.0:8081".into()
}
fn default_grpc_enabled() -> bool {
    true
}

impl Config {
    /// Read + parse a TOML config from disk. Errors include the file
    /// path so a config typo doesn't get reported with a bare TOML
    /// line number.
    pub fn load_from(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let cfg: Self =
            toml::from_str(&s).with_context(|| format!("parse TOML {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.chains.is_empty() {
            anyhow::bail!("config must declare at least one [[chains]] entry");
        }
        for c in &self.chains {
            if c.shortname.is_empty() {
                anyhow::bail!("chains.shortname must not be empty");
            }
            if c.shortname.contains('/') || c.shortname.contains(' ') {
                anyhow::bail!(
                    "chains.shortname `{}` must not contain `/` or spaces (used as a URL path segment)",
                    c.shortname
                );
            }
            if c.factories.is_empty() {
                anyhow::bail!(
                    "chains.factories on `{}` must not be empty (need at least one trust pin)",
                    c.shortname
                );
            }
            for f in &c.factories {
                if f.address.len() != 42 || !f.address.starts_with("0x") {
                    anyhow::bail!(
                        "chains.factories.address `{}` on chain `{}` is not 0x + 40 hex",
                        f.address,
                        c.shortname
                    );
                }
            }
        }
        if self.storage.cluster_uuid.is_empty() {
            anyhow::bail!("storage.cluster_uuid must not be empty");
        }
        if self.storage.database.is_empty() {
            anyhow::bail!("storage.database must not be empty");
        }
        if self.storage.username.is_empty() {
            anyhow::bail!("storage.username must not be empty");
        }
        if self.server.listen_addr.is_empty() {
            anyhow::bail!("server.listen_addr must not be empty");
        }
        if self.grpc.enabled && self.grpc.listen_addr.is_empty() {
            anyhow::bail!("grpc.listen_addr must not be empty when grpc.enabled = true");
        }
        if self.grpc.enabled && self.grpc.listen_addr == self.server.listen_addr {
            anyhow::bail!(
                "grpc.listen_addr `{}` collides with server.listen_addr; the two transports must bind distinct ports",
                self.grpc.listen_addr
            );
        }
        match self.ra_tls.verifier.as_str() {
            "dcap" => {}
            other => anyhow::bail!(
                "ra_tls.verifier `{}` is not supported; the only valid value is `dcap` \
                 (intel is reserved for a future wiring of IntelApiVerifier)",
                other
            ),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference config straight from spec §8 — if this stops parsing,
    /// either the spec or the struct drifted.
    #[test]
    fn parses_spec_section_8_config() {
        let toml = r#"
[[chains]]
shortname    = "base"
chain_id     = 8453
rpc_http_url = "https://base-mainnet.g.alchemy.com/v2/k"
rpc_ws_url   = "wss://base-mainnet.g.alchemy.com/v2/k"

[[chains.factories]]
address    = "0xfbd65e6b30f40db87159a5d3a390fc9c2bd87e11"
from_block = 45481400

[storage]
cluster_uuid    = "6dee00f10e"
database        = "chain_indexer"
username        = "chain_indexer_writer"
max_connections = 16

[server]
listen_addr         = "0.0.0.0:8080"
rate_limit_rps      = 50
sse_max_connections = 1000

[attestation]
kms_purpose         = "teesql-chain-indexer-sign"
response_lifetime_s = 300
finality_depth      = 12

[ra_tls]
verifier         = "dcap"
allowed_mrtds    = []
allow_debug_mode = false
allow_simulator  = false
"#;
        let dir = tempdir();
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(cfg.chains.len(), 1);
        assert_eq!(cfg.chains[0].shortname, "base");
        assert_eq!(cfg.chains[0].chain_id, 8453);
        assert_eq!(cfg.chains[0].factories[0].from_block, 45481400);
        assert_eq!(cfg.storage.cluster_uuid, "6dee00f10e");
        assert_eq!(cfg.server.rate_limit_rps, 50);
        assert_eq!(cfg.attestation.finality_depth, 12);
        assert_eq!(cfg.ra_tls.verifier, "dcap");
    }

    #[test]
    fn grpc_defaults_to_8081_alongside_rest_8080() {
        let toml = r#"
[[chains]]
shortname    = "base"
chain_id     = 8453
rpc_http_url = "x"
rpc_ws_url   = "x"
[[chains.factories]]
address    = "0xfbd65e6b30f40db87159a5d3a390fc9c2bd87e11"
from_block = 1
[storage]
cluster_uuid = "u"
database     = "d"
username     = "u"
[server]
listen_addr = "0.0.0.0:8080"
[attestation]
[ra_tls]
"#;
        let dir = tempdir();
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(cfg.grpc.listen_addr, "0.0.0.0:8081");
        assert!(cfg.grpc.enabled);
    }

    #[test]
    fn grpc_listen_addr_must_differ_from_rest() {
        let toml = r#"
[[chains]]
shortname    = "base"
chain_id     = 8453
rpc_http_url = "x"
rpc_ws_url   = "x"
[[chains.factories]]
address    = "0xfbd65e6b30f40db87159a5d3a390fc9c2bd87e11"
from_block = 1
[storage]
cluster_uuid = "u"
database     = "d"
username     = "u"
[server]
listen_addr = "0.0.0.0:8080"
[grpc]
listen_addr = "0.0.0.0:8080"
enabled     = true
[attestation]
[ra_tls]
"#;
        let dir = tempdir();
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        let err = Config::load_from(&path).unwrap_err();
        assert!(format!("{err:#}").contains("collides with server.listen_addr"));
    }

    #[test]
    fn defaults_apply_when_optional_fields_omitted() {
        let toml = r#"
[[chains]]
shortname    = "base"
chain_id     = 8453
rpc_http_url = "https://x"
rpc_ws_url   = "wss://x"

[[chains.factories]]
address    = "0xfbd65e6b30f40db87159a5d3a390fc9c2bd87e11"
from_block = 1

[storage]
cluster_uuid = "u"
database     = "d"
username     = "u"

[server]
listen_addr = "0.0.0.0:8080"

[attestation]

[ra_tls]
"#;
        let dir = tempdir();
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = Config::load_from(&path).unwrap();
        assert_eq!(cfg.storage.max_connections, 16);
        assert_eq!(cfg.server.rate_limit_rps, 50);
        assert_eq!(cfg.server.sse_max_connections, 1000);
        assert_eq!(cfg.attestation.kms_purpose, "teesql-chain-indexer-sign");
        assert_eq!(cfg.attestation.response_lifetime_s, 300);
        assert_eq!(cfg.attestation.finality_depth, 12);
        assert_eq!(cfg.ra_tls.verifier, "dcap");
        assert!(!cfg.ra_tls.allow_debug_mode);
        assert!(!cfg.ra_tls.allow_simulator);
    }

    #[test]
    fn rejects_short_factory_address() {
        let toml = r#"
[[chains]]
shortname    = "base"
chain_id     = 8453
rpc_http_url = "x"
rpc_ws_url   = "x"
[[chains.factories]]
address    = "0xabc"
from_block = 1
[storage]
cluster_uuid = "u"
database     = "d"
username     = "u"
[server]
listen_addr = "0.0.0.0:8080"
[attestation]
[ra_tls]
"#;
        let dir = tempdir();
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        let err = Config::load_from(&path).unwrap_err();
        assert!(format!("{err:#}").contains("not 0x + 40 hex"));
    }

    #[test]
    fn rejects_bad_verifier() {
        let toml = r#"
[[chains]]
shortname    = "base"
chain_id     = 8453
rpc_http_url = "x"
rpc_ws_url   = "x"
[[chains.factories]]
address    = "0xfbd65e6b30f40db87159a5d3a390fc9c2bd87e11"
from_block = 1
[storage]
cluster_uuid = "u"
database     = "d"
username     = "u"
[server]
listen_addr = "0.0.0.0:8080"
[attestation]
[ra_tls]
verifier = "rolled-our-own"
"#;
        let dir = tempdir();
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        let err = Config::load_from(&path).unwrap_err();
        assert!(format!("{err:#}").contains("is not supported; the only valid value is `dcap`"));
    }

    #[test]
    fn rejects_empty_chains() {
        let toml = r#"
chains = []
[storage]
cluster_uuid = "u"
database     = "d"
username     = "u"
[server]
listen_addr = "0.0.0.0:8080"
[attestation]
[ra_tls]
"#;
        let dir = tempdir();
        let path = dir.join("c.toml");
        std::fs::write(&path, toml).unwrap();
        let err = Config::load_from(&path).unwrap_err();
        assert!(format!("{err:#}").contains("at least one [[chains]] entry"));
    }

    /// `tempfile` is a heavy dep for what these tests need; roll a tiny
    /// scratch dir under the system temp root that the test writes
    /// configs into. Per-call uniqueness comes from a global atomic
    /// counter — `cargo test` runs cases in parallel so a fixed name
    /// (just `pid`) collides between cases that both write `c.toml`
    /// and one tramples the other's input.
    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "teesql-chain-indexer-cfg-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::create_dir_all(&p);
        p
    }
}
