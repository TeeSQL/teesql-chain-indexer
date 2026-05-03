# teesql-chain-indexer — TEE CVM binary that subscribes to one EVM
# chain's logs, persists every event into Postgres on the monitor
# cluster (over sqlx-ra-tls), and serves TDX-attested signed responses
# from a small axum HTTP API.
#
# # Build context
#
# This Dockerfile assumes the build context root contains the
# chain-indexer workspace AND the path-dep'd `sqlx-ra-tls` and
# `ra-tls-parse` trees side by side (these are referenced by relative
# `../sqlx-ra-tls` paths in the workspace `Cargo.toml`). The published
# images are baked from a temp tarball context the publish script
# assembles — see `scripts/publish-chain-indexer.sh` for the layout.
# Building from this directory directly will fail at the `COPY
# sqlx-ra-tls` step until that tarball is staged.
#
# # Phase 2
#
# The binary is currently published with the trivial `fn main()` entry
# point (no `--features phase2`); upgrading the published image to the
# real wiring is a single `--features phase2` flip in the
# `cargo build --release` line below, plus a workspace-version bump.

# syntax=docker/dockerfile:1.6
FROM rust:1.92-slim AS builder
WORKDIR /build

# System deps:
#   * pkg-config + libssl-dev — sqlx + reqwest TLS link path
#   * protobuf-compiler — tonic-build emits Rust from the proto schema
#     in `proto/chain_indexer.proto`
#   * ca-certificates — runtime HTTPS to RPC providers from inside the
#     build (cargo's git index in particular)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev protobuf-compiler ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Workspace + path-deps. The sqlx-ra-tls / ra-tls-parse trees come from
# the parent monorepo's `open-source/` (or its sibling submodules in
# the canonical github.com/teesql layout). The publish script stages
# them so these paths resolve relative to the build context root.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY sqlx-ra-tls /sqlx-ra-tls
COPY ra-tls-parse /ra-tls-parse

# Default feature set keeps `main` trivial — see the comment block at
# the top of `crates/bin/teesql-chain-indexer/src/main.rs`. Bump to
# `--features phase2` once the upstream sibling crates ship their real
# APIs (see `Cargo.toml [features]`).
RUN cargo build --release -p teesql-chain-indexer

FROM debian:bookworm-slim

# `curl` for the compose HEALTHCHECK; `ca-certificates` so HTTPS RPC
# calls from the running binary verify Alchemy's cert.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/teesql-chain-indexer /usr/local/bin/teesql-chain-indexer

# Bake a copy of the prod template into the image so a smoke-test deploy
# without an encrypted-env config can still boot for sanity checks. The
# real deploy path always overrides this via INDEXER_CONFIG_B64 + the
# entrypoint decode in `deploy/compose.template.yml`.
COPY deploy/prod.config.toml /etc/teesql-chain-indexer/config.toml

EXPOSE 8080

# Mirrors the compose HEALTHCHECK so `docker run --health-cmd` users
# get the same probe. /v1/health is unsigned per spec §7.1.
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s \
    CMD curl -fsS http://127.0.0.1:8080/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/teesql-chain-indexer"]
CMD ["--config", "/etc/teesql-chain-indexer/config.toml"]
