//! Phase-2 wiring against the real upstream APIs:
//!
//! * `teesql_chain_indexer_attest::Signer::from_dstack(&AttestConfig)` —
//!   derives the response-signing key via dstack KMS and caches a
//!   boot-time TDX quote that commits to it.
//! * `teesql_chain_indexer_core::connection::build_pool(...)` plus
//!   `EventStore::new(pool, chain_id)` — opens the sqlx-ra-tls pool to
//!   the monitor cluster's primary and wraps it in a per-chain
//!   `EventStore`.
//! * `teesql_chain_indexer_abi::all_decoders()` /
//!   `teesql_chain_indexer_views::all_views()` — registers the
//!   factory + cluster-diamond decoders and the leader / members /
//!   lifecycle materializers per chain.
//! * `teesql_chain_indexer_core::Ingestor::builder()...build().run()` —
//!   one ingest loop per chain.
//! * `teesql_chain_indexer_server::{build_router, build_grpc_service,
//!   spawn_listen_worker}` plus `state::{AppState, MultiChainState,
//!   ServerConfig}` — the axum + tonic surface with per-chain state
//!   and the LISTEN→broadcast bridge.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::{broadcast, mpsc};

use teesql_chain_indexer_attest::{AttestConfig, Signer};
use teesql_chain_indexer_core::connection::{build_pool, ConnectionConfig};
use teesql_chain_indexer_core::ingest::{ControlNotifyEvent, NotifyEvent};
use teesql_chain_indexer_core::store::EventStore;
use teesql_chain_indexer_core::Ingestor;
use teesql_chain_indexer_server::metrics::Metrics;
use teesql_chain_indexer_server::state::{AppState, MultiChainState, ServerConfig};
use teesql_chain_indexer_server::{
    build_grpc_service, build_router, spawn_control_listen_worker, spawn_listen_worker,
};

use crate::config::{ChainConfig, Config};
use crate::manifest_resolver::{host_port_from_leader_url, resolve_leader_manifest};

#[derive(Parser, Debug)]
#[command(
    name = "teesql-chain-indexer",
    about = "Attested Postgres-backed event log over an EVM RPC"
)]
struct Args {
    /// Path to the TOML config file.
    #[arg(long, default_value = "/etc/teesql-chain-indexer/config.toml")]
    config: PathBuf,
}

/// Env var supplying the wire-level password the indexer presents as
/// `chain_indexer_writer` to the monitor cluster's RA-TLS sidecar.
/// Mirrors `TEESQL_INDEXER_CLUSTER_SECRET` from spec §8.
const ENV_CLUSTER_SECRET: &str = "TEESQL_INDEXER_CLUSTER_SECRET";

/// Resolved hostname of the monitor cluster's primary. The signed
/// leader-TXT manifest at `_teesql-leader.<cluster_uuid>.teesql.com`
/// is the system of record; the operator (or a future on-host helper)
/// resolves it once and feeds the answer in via this env var so this
/// process can be hermetic w.r.t. DNS resolver configuration. Spec §3.1.
const ENV_TARGET_HOST: &str = "TEESQL_INDEXER_TARGET_HOST";

/// Postgres TLS port served by the monitor cluster's sidecar
/// (`5433` is the platform-wide default).
const ENV_TARGET_PORT: &str = "TEESQL_INDEXER_TARGET_PORT";
const DEFAULT_TARGET_PORT: u16 = 5433;

/// dstack `path` argument fed into the KMS derivation. Always empty
/// for the indexer's signing key; spec §4 fixes the binding to
/// `(app_id, kms_purpose)` only.
const KMS_PATH: &str = "";

/// Env-var name an operator can set with a 64-char hex string to
/// short-circuit the dstack call (dev / simulator only). Production
/// CVMs leave this unset so `Signer::from_dstack` always goes through
/// the real KMS.
const KMS_OVERRIDE_ENV: &str = "TEESQL_INDEXER_SIGNING_KEY_OVERRIDE";

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,teesql_chain_indexer=debug".into()),
        )
        .init();

    let args = Args::parse();
    let cfg = Config::load_from(&args.config)
        .with_context(|| format!("load {}", args.config.display()))?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        chains = cfg.chains.len(),
        cluster_uuid = %cfg.storage.cluster_uuid,
        listen = %cfg.server.listen_addr,
        "starting teesql-chain-indexer"
    );

    let attest_cfg = AttestConfig {
        kms_purpose: cfg.attestation.kms_purpose.clone(),
        kms_path: KMS_PATH.to_string(),
        override_key_env: KMS_OVERRIDE_ENV.to_string(),
        response_lifetime_s: cfg.attestation.response_lifetime_s,
    };
    let signer = Arc::new(
        Signer::from_dstack(&attest_cfg)
            .await
            .context("derive signing key from dstack KMS")?,
    );
    tracing::info!(
        signer_address = %format!("0x{}", hex::encode(signer.signer_address().as_slice())),
        "signing key ready"
    );

    let pool = open_storage_pool(&cfg).await?;

    let metrics = Arc::new(Metrics::default());
    let mut by_shortname: HashMap<String, AppState> = HashMap::new();
    let mut ingestor_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    for chain_cfg in cfg.chains.iter() {
        let chain_id = i32::try_from(chain_cfg.chain_id).with_context(|| {
            format!(
                "chain_id {} on `{}` overflows i32",
                chain_cfg.chain_id, chain_cfg.shortname
            )
        })?;

        let store = EventStore::new(pool.clone(), chain_id)
            .await
            .with_context(|| format!("EventStore::new for chain `{}`", chain_cfg.shortname))?;
        seed_watched_factories(&store, chain_cfg).await?;

        // Per-chain views map keyed on `View::name()` for the route
        // layer's endpoint dispatch ("leader" / "members" /
        // "lifecycle"). The Vec from `all_views()` carries trait
        // objects that aren't `Clone`, so we materialise it twice —
        // once into the route map, once into the ingestor builder.
        let view_for_routes = teesql_chain_indexer_views::all_views();
        let mut views_map: HashMap<&'static str, Arc<dyn teesql_chain_indexer_core::views::View>> =
            HashMap::new();
        for v in view_for_routes {
            views_map.insert(v.name(), Arc::from(v));
        }
        let views_arc = Arc::new(views_map);

        // SSE broadcast — one channel per chain. The route layer's
        // per-handler subscription is filtered server-side; capacity
        // covers the 1k SSE connection cap with headroom.
        let (sse_tx, _sse_rx) = broadcast::channel::<NotifyEvent>(2048);

        // Track D3: separate control-plane bus. Sized smaller than
        // the generic events bus because each cluster has at most a
        // handful of control SSE subscribers (one per member sidecar
        // + one for the hub UI), and the per-cluster ControlOrderer
        // strictly serializes by `nonce` so backed-up frames are not
        // a real failure mode the way they would be on the generic
        // events bus. 512 covers a worst-case lag spike without
        // forcing reconnects.
        let (control_tx, _control_rx) = broadcast::channel::<ControlNotifyEvent>(512);

        // Postgres LISTEN→broadcast bridge for the route layer's SSE
        // path. Keeps SSE alive when the in-process notify path is
        // bypassed (e.g. a future multi-instance HA topology where
        // the writer + reader live in different processes).
        let _listen_handle = spawn_listen_worker(pool.clone(), sse_tx.clone());
        // Twin bridge for the dedicated `chain_indexer_control`
        // channel. Track D3.
        let _control_listen_handle = spawn_control_listen_worker(pool.clone(), control_tx.clone());

        // In-process Ingestor → broadcast bridge. The Ingestor sends a
        // `NotifyEvent` on this mpsc after every event apply alongside
        // the standard `pg_notify`; this forwarder lifts each one
        // onto the same broadcast bus the LISTEN worker feeds, so
        // SSE consumers in the same process see the event in
        // sub-millisecond rather than the ~5-50ms it takes to round-
        // trip through Postgres LISTEN/NOTIFY. Both producers fire
        // for every event by design — the SSE handler dedupes by
        // `event_id` so consumers see one frame per id regardless of
        // which path arrives first. Buffer 1024 leaves slack for a
        // brief broadcast-fan-out stall without back-pressuring the
        // ingest loop (the Ingestor drops on full and relies on
        // pg_notify as the durable fallback).
        let (notify_tx, mut notify_rx) = mpsc::channel::<NotifyEvent>(1024);
        {
            let sse_tx_for_bridge = sse_tx.clone();
            tokio::spawn(async move {
                while let Some(ev) = notify_rx.recv().await {
                    // No subscribers → drop on the floor; matches the
                    // LISTEN worker's behavior. Errors here only
                    // surface when every receiver has dropped.
                    let _ = sse_tx_for_bridge.send(ev);
                }
            });
        }

        let app_state = AppState {
            store: Arc::new(store.clone()),
            signer: signer.clone(),
            views: views_arc.clone(),
            sse_tx: sse_tx.clone(),
            control_tx: control_tx.clone(),
            config: ServerConfig {
                sse_max_connections: cfg.server.sse_max_connections as usize,
                rate_limit_rps: cfg.server.rate_limit_rps,
                response_lifetime_s: cfg.attestation.response_lifetime_s,
                default_chain: cfg
                    .chains
                    .first()
                    .map(|c| c.shortname.clone())
                    .unwrap_or_else(|| "base".to_string()),
            },
            started_at: Instant::now(),
        };
        by_shortname.insert(chain_cfg.shortname.clone(), app_state);

        let mut ingestor_builder = Ingestor::builder()
            .chain_id(chain_id)
            .rpc_http_url(chain_cfg.rpc_http_url.clone())
            .rpc_ws_url(chain_cfg.rpc_ws_url.clone())
            .store(store)
            .finality_depth(cfg.attestation.finality_depth)
            .notify_channel(notify_tx);
        for d in teesql_chain_indexer_abi::all_decoders() {
            ingestor_builder = ingestor_builder.decoder(d);
        }
        for v in teesql_chain_indexer_views::all_views() {
            ingestor_builder = ingestor_builder.view(v);
        }
        let ingestor = ingestor_builder
            .build()
            .with_context(|| format!("Ingestor::build for chain `{}`", chain_cfg.shortname))?;

        let shortname = chain_cfg.shortname.clone();
        ingestor_tasks.push(tokio::spawn(async move {
            if let Err(e) = ingestor.run().await {
                tracing::error!(chain = %shortname, error = %e, "ingestor exited with error");
            }
        }));
    }

    let multi = Arc::new(MultiChainState {
        by_shortname: Arc::new(by_shortname),
        signer: signer.clone(),
        started_at: Instant::now(),
    });

    let router = build_router(multi.clone(), metrics.clone());
    let listener = tokio::net::TcpListener::bind(&cfg.server.listen_addr)
        .await
        .with_context(|| format!("bind {}", cfg.server.listen_addr))?;
    tracing::info!(addr = %cfg.server.listen_addr, "HTTP server listening");

    let server_task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!(error = %e, "HTTP server exited");
        }
    });

    let mut tasks = ingestor_tasks;
    tasks.push(server_task);

    // gRPC mirror — same handler pipeline as REST, served on its own
    // listen_addr alongside the REST :8080. Operators front both
    // through a single Phala-gateway hostname per spec §7.2. Skipping
    // the listener entirely is the `grpc.enabled = false` escape
    // hatch — useful in dev when port :8081 is taken by another
    // service.
    if cfg.grpc.enabled {
        let grpc_service = build_grpc_service(multi.clone());
        let grpc_addr: SocketAddr = cfg
            .grpc
            .listen_addr
            .parse()
            .with_context(|| format!("parse grpc.listen_addr `{}`", cfg.grpc.listen_addr))?;
        tracing::info!(addr = %grpc_addr, "gRPC server listening");
        let grpc_task = tokio::spawn(async move {
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(grpc_service)
                .serve(grpc_addr)
                .await
            {
                tracing::error!(error = %e, "gRPC server exited");
            }
        });
        tasks.push(grpc_task);
    } else {
        tracing::info!("gRPC server disabled by config (grpc.enabled = false)");
    }

    let (res, _idx, rest) = futures::future::select_all(tasks).await;
    for t in rest {
        t.abort();
    }
    res.context("indexer task exited")
}

/// Build the sqlx-ra-tls pool against the cluster's current primary.
///
/// Two paths to a `target_host`:
///
/// 1. **Operator override.** `TEESQL_INDEXER_TARGET_HOST` set in the
///    encrypted env. Used for first-time bring-up when the
///    dns-controller hasn't yet published the cluster's leader-TXT
///    manifest, or for testing against a pinned host. The
///    accompanying `TEESQL_INDEXER_TARGET_PORT` defaults to 5433.
///
/// 2. **Manifest-TXT discovery (default).** When the env var is
///    unset, resolve `_teesql-leader.<cluster_uuid>.teesql.com`,
///    verify the dns-controller's signature against
///    `[storage] manifest_signer_address`, and use the manifest's
///    `leader_url` as the target. This is the normal steady-state
///    path — leader rotations propagate automatically without an
///    operator-driven env-var update.
async fn open_storage_pool(cfg: &Config) -> Result<sqlx::PgPool> {
    let env_target_host = std::env::var(ENV_TARGET_HOST)
        .ok()
        .filter(|s| !s.is_empty());
    let env_target_port = std::env::var(ENV_TARGET_PORT)
        .ok()
        .filter(|s| !s.is_empty());

    let (target_host, target_port) = match env_target_host {
        Some(host) => {
            let port = env_target_port
                .map(|s| s.parse::<u16>())
                .transpose()
                .context("TEESQL_INDEXER_TARGET_PORT not a valid u16")?
                .unwrap_or(DEFAULT_TARGET_PORT);
            tracing::info!(
                target_host = %host,
                target_port = port,
                "storage target via TEESQL_INDEXER_TARGET_HOST override"
            );
            (host, port)
        }
        None => {
            let signer_str = cfg
                .storage
                .manifest_signer_address
                .as_deref()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "neither {} is set nor [storage] manifest_signer_address is \
                         configured; one of the two is required to discover the \
                         cluster's primary",
                        ENV_TARGET_HOST
                    )
                })?;
            let signer_bytes = parse_signer_address(signer_str)?;
            let record_name = format!("_teesql-leader.{}.teesql.com", cfg.storage.cluster_uuid);
            tracing::info!(
                record = %record_name,
                signer = %signer_str,
                "resolving signed leader manifest"
            );
            let manifest = resolve_leader_manifest(&record_name, &signer_bytes)
                .await
                .with_context(|| format!("resolve manifest TXT at {record_name}"))?;
            let addr = host_port_from_leader_url(&manifest.leader_url).with_context(|| {
                format!("parse host/port from leader_url `{}`", manifest.leader_url)
            })?;
            // Scheme-aware default: `https://` lands at the Phala
            // gateway's TCP 443, which routes to the cluster's
            // internal port via the `-<port>s` suffix encoded in
            // the hostname (`<instance_id>-5433s.<node>.phala.network`).
            // Anything else (`http://localhost:5433`, an internal
            // tailnet hostname, etc.) falls through to the cluster's
            // postgres-side default 5433.
            let scheme_default_port = if addr.https { 443 } else { DEFAULT_TARGET_PORT };
            let port = env_target_port
                .map(|s| s.parse::<u16>())
                .transpose()
                .context("TEESQL_INDEXER_TARGET_PORT not a valid u16")?
                .or(addr.explicit_port)
                .unwrap_or(scheme_default_port);
            tracing::info!(
                target_host = %addr.host,
                target_port = port,
                leader_instance = %manifest.leader_instance,
                epoch = manifest.epoch,
                "storage target resolved via manifest TXT"
            );
            (addr.host, port)
        }
    };

    let password_secret = std::env::var(ENV_CLUSTER_SECRET)
        .with_context(|| format!("env {} not set", ENV_CLUSTER_SECRET))?;

    let conn_cfg = ConnectionConfig {
        target_host,
        target_port,
        database: cfg.storage.database.clone(),
        username: cfg.storage.username.clone(),
        password_secret,
        max_connections: cfg.storage.max_connections,
    };

    // Config-load validation already restricts this to `dcap`; the
    // catch-all is here for defense-in-depth against a future code
    // path that bypasses Config::validate.
    let verifier: Arc<dyn sqlx_ra_tls::RaTlsVerifier> = match cfg.ra_tls.verifier.as_str() {
        "dcap" => Arc::new(sqlx_ra_tls::DcapVerifier::new()),
        other => anyhow::bail!(
            "ra_tls.verifier `{}` is not supported; the only valid value is `dcap`",
            other
        ),
    };
    let ra_tls_opts = sqlx_ra_tls::RaTlsOptions {
        allowed_mrtds: cfg.ra_tls.allowed_mrtds.clone(),
        allow_debug_mode: cfg.ra_tls.allow_debug_mode,
        allow_simulator: cfg.ra_tls.allow_simulator,
        client_cert_override: None,
    };

    build_pool(&conn_cfg, verifier, ra_tls_opts, None)
        .await
        .context("open monitor-cluster Postgres pool over sqlx-ra-tls")
}

/// Insert the configured `[[chains.factories]]` rows into
/// `watched_contracts` so the cold-start backfill loop sees them on
/// first iteration. Idempotent under
/// `EventStore::add_watched_contract` (re-registering keeps the
/// earliest from_block).
async fn seed_watched_factories(store: &EventStore, chain_cfg: &ChainConfig) -> Result<()> {
    for f in &chain_cfg.factories {
        let bytes = decode_address(&f.address).with_context(|| {
            format!(
                "factory address `{}` on chain `{}`",
                f.address, chain_cfg.shortname
            )
        })?;
        store
            .add_watched_contract(bytes, "factory", None, f.from_block)
            .await
            .with_context(|| format!("seed factory {} on `{}`", f.address, chain_cfg.shortname))?;
    }
    Ok(())
}

fn decode_address(s: &str) -> Result<[u8; 20]> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    let v = hex::decode(raw).context("hex decode")?;
    let arr: [u8; 20] = v
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 20 bytes after hex decode"))?;
    Ok(arr)
}

/// Parse `[storage] manifest_signer_address`. Same shape as
/// `decode_address` but with a friendlier error message that points
/// the operator at the config field they probably typo'd.
fn parse_signer_address(s: &str) -> Result<[u8; 20]> {
    decode_address(s)
        .with_context(|| format!("storage.manifest_signer_address `{s}` is not 0x + 40 hex"))
}
