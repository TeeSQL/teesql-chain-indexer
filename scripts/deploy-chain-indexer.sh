#!/usr/bin/env bash
# Prepare a teesql-chain-indexer deploy bundle.
#
# Emits, into deploy/out/:
#   - config.toml             copy of the source TOML (for audit)
#   - compose.yml             rendered compose file with INDEXER_IMAGE_TAG
#                             substituted (this is what Phala hashes)
#   - .env                    encrypted-env payload (cluster secret +
#                             config b64; the operator runs `phala join
#                             encrypt` against this before deploy)
#   - phala-deploy-cmd.sh     runnable `phala deploy` invocation
#
# The script NEVER invokes `phala` itself. The operator runs the
# emitted command interactively so deploys land under their Phala Cloud
# account + global deployer key. This matches the dns-controller and
# monitoring-hub deploy-script convention.
#
# Usage:
#   TEESQL_INDEXER_CLUSTER_SECRET=$(openssl rand -hex 32) \
#       ./scripts/deploy-chain-indexer.sh [--config <path>] [--tag vX.Y.Z] \
#                                         [--node-id N] [--cvm-id <id>] \
#                                         [--dry-run]
#
# Args / flags:
#   --config <path>     defaults to deploy/prod.config.toml
#   --tag vX.Y.Z        defaults to `v` + workspace package version
#   --node-id N         Phala node id. Default 26 (prod5)
#   --cvm-id <id>       upgrade an existing CVM rather than first-time
#                       deploy. Switches `phala deploy` to its
#                       --cvm-id mode (canonical upgrade path per
#                       CLAUDE.md memory `reference_hub_upgrade_procedure`
#                       — `phala cvms upgrade` is broken for our shape).
#   --dry-run           render bundle but skip the compose-hash probe
#
# Required env:
#   TEESQL_INDEXER_CLUSTER_SECRET   64 hex chars (32 bytes). The
#       cluster-shared secret that authenticates `chain_indexer_writer`
#       to the monitor cluster's RA-TLS Postgres. Generated once and
#       allowlisted in the monitor cluster's sidecar wire-protocol
#       auth map.
#
# Optional env:
#   TEESQL_INDEXER_OVERRIDE_KEY  dev-only. 32 hex bytes that override
#       the dstack-derived signing key. Leave unset in production.
#   RUST_LOG                     default `info,teesql_chain_indexer=debug`
#   DEPLOY_NAME                  default `teesql-chain-indexer-base`
#
# # First deploy vs upgrade
#
# First deploy: omit --cvm-id. Phala auto-allocates a DstackApp and
# accepts the new compose hash automatically (no pre-seeded
# allowlist required for v1 single-instance — same as the hub's first
# deploy). Capture the allocated app_id from the output for any future
# `--cvm-id` upgrade.
#
# Upgrade: pass --cvm-id <id>. Re-uses the existing DstackApp + KMS
# keys; the new compose hash needs to be allowlisted on-chain (the
# script prints the hash + the operator-side `addComposeHash` command
# rather than running it itself, since allowlist mutations are
# Safe-gated).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMPLATE="${REPO_ROOT}/deploy/compose.template.yml"
OUT_DIR="${REPO_ROOT}/deploy/out"

# --- arg parse ---------------------------------------------------------------

CONFIG_SRC="${REPO_ROOT}/deploy/prod.config.toml"
TAG=""
NODE_ID="26"
CVM_ID=""
DRY_RUN="false"
RUST_LOG_VAL="${RUST_LOG:-info,teesql_chain_indexer=debug}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)   CONFIG_SRC="$2"; shift 2 ;;
        --tag)      TAG="$2"; shift 2 ;;
        --node-id)  NODE_ID="$2"; shift 2 ;;
        --cvm-id)   CVM_ID="$2"; shift 2 ;;
        --dry-run)  DRY_RUN="true"; shift ;;
        -h|--help)
            sed -n '1,/^set -euo/p' "$0" | sed -n '/^# /p'
            exit 0
            ;;
        *) echo "ERROR: unknown arg \`$1\`" >&2; exit 2 ;;
    esac
done

if [[ ! -f "${CONFIG_SRC}" ]]; then
    echo "ERROR: config not found: ${CONFIG_SRC}" >&2
    exit 2
fi

if [[ -z "${TEESQL_INDEXER_CLUSTER_SECRET:-}" ]]; then
    echo "ERROR: TEESQL_INDEXER_CLUSTER_SECRET must be set (64 hex chars)" >&2
    exit 2
fi
if [[ ! "${TEESQL_INDEXER_CLUSTER_SECRET}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "ERROR: TEESQL_INDEXER_CLUSTER_SECRET must be exactly 64 hex chars" >&2
    exit 2
fi

if [[ -z "${TAG}" ]]; then
    # Workspace `package.version` is the source of truth — every crate
    # uses `version.workspace = true`, so the tag, the Cargo version,
    # and the compose-template `image:` line all key off the same value.
    VER=$(awk '
        /^\[workspace\.package\]/ { in_wp = 1; next }
        in_wp && /^\[/            { in_wp = 0 }
        in_wp && /^version[[:space:]]*=/ {
            sub(/^version[[:space:]]*=[[:space:]]*"/, "")
            sub(/".*/, "")
            print
            exit
        }
    ' "${REPO_ROOT}/Cargo.toml")
    if [[ -z "${VER}" ]]; then
        echo "ERROR: failed to extract workspace version from ${REPO_ROOT}/Cargo.toml" >&2
        exit 1
    fi
    TAG="v${VER}"
fi

CONFIG_STEM="$(basename "${CONFIG_SRC}" .config.toml)"
CONFIG_STEM="${CONFIG_STEM%.toml}"
DEPLOY_NAME="${DEPLOY_NAME:-teesql-chain-indexer-${CONFIG_STEM}}"

mkdir -p "${OUT_DIR}"
cp "${CONFIG_SRC}" "${OUT_DIR}/config.toml"

# --- render compose ----------------------------------------------------------

# Phala hashes the compose file as-rendered (see CLAUDE.md memory
# `reference_phala_compose_hash_relocking`). Substituting the image
# tag here, before hash derivation, locks the on-chain compose-hash
# allowlist entry to a specific image. The template uses
# ${INDEXER_IMAGE_TAG} as the substitution token.
INDEXER_IMAGE_TAG="${TAG}" \
    envsubst '${INDEXER_IMAGE_TAG}' < "${TEMPLATE}" > "${OUT_DIR}/compose.yml"

# --- encrypted .env payload --------------------------------------------------

# Base64-encode the config (no-newline) so it survives Phala's env
# substitution intact — same trick the dns-controller + hub use.
CONFIG_B64="$(base64 -w 0 "${OUT_DIR}/config.toml")"

# Optional GHCR pull creds. The chain-indexer image is currently public,
# so blank values are acceptable; listing the env keys keeps the
# encrypted-env allowlist forward-compatible with a future flip to a
# private package without a fresh compose-hash round-trip.
GHCR_REGISTRY=""
GHCR_USERNAME=""
GHCR_TOKEN=""
GHCR_CREDS="${HOME}/.teesql/ghcr-pull.toml"
if [[ -f "${GHCR_CREDS}" ]]; then
    GHCR_REGISTRY=$(awk -F'"' '/^[[:space:]]*registry[[:space:]]*=/{print $2}' "${GHCR_CREDS}" | head -1)
    GHCR_USERNAME=$(awk -F'"' '/^[[:space:]]*username[[:space:]]*=/{print $2}' "${GHCR_CREDS}" | head -1)
    GHCR_TOKEN=$(awk -F'"' '/^[[:space:]]*token[[:space:]]*=/{print $2}' "${GHCR_CREDS}" | head -1)
fi

cat > "${OUT_DIR}/.env" <<EOF
TEESQL_INDEXER_CLUSTER_SECRET=${TEESQL_INDEXER_CLUSTER_SECRET}
INDEXER_CONFIG_B64=${CONFIG_B64}
RUST_LOG=${RUST_LOG_VAL}
TEESQL_INDEXER_OVERRIDE_KEY=${TEESQL_INDEXER_OVERRIDE_KEY:-}
TEESQL_INDEXER_TARGET_HOST=${TEESQL_INDEXER_TARGET_HOST:-}
TEESQL_INDEXER_TARGET_PORT=${TEESQL_INDEXER_TARGET_PORT:-}
DSTACK_DOCKER_REGISTRY=${GHCR_REGISTRY}
DSTACK_DOCKER_USERNAME=${GHCR_USERNAME}
DSTACK_DOCKER_PASSWORD=${GHCR_TOKEN}
EOF
chmod 600 "${OUT_DIR}/.env"

# --- compose-hash dry-run probe ---------------------------------------------

# Phala's `POST /cvms/provision` returns the `compose_hash` it would
# derive without actually creating a CVM. Operators allowlist this hash
# on-chain (Safe-gated `addComposeHash` for the monitor cluster) before
# the deploy can succeed under `--cvm-id`. The probe is byte-for-byte
# off by ~1 from the actual deploy hash (see CLAUDE.md memory
# `project_compose_hash_dryrun_drift` — trailing newline difference);
# allowlist the deploy's hash, not the probe's. We still emit the probe
# value so an operator can sanity-check the rendered compose before
# spending the gas to allowlist.
if [[ "${DRY_RUN}" != "true" ]]; then
    echo "==> compose hash probe (informational only — see CLAUDE.md memory project_compose_hash_dryrun_drift):"
    if command -v phala >/dev/null 2>&1; then
        # Best-effort. If phala CLI isn't installed we just skip; the
        # operator can run the probe themselves later.
        phala cvms provision \
            --compose "${OUT_DIR}/compose.yml" \
            -e "${OUT_DIR}/.env" \
            --node-id "${NODE_ID}" \
            --disk-size 20G \
            --kms base \
            --dry-run 2>/dev/null \
          | grep -i 'compose_hash' || echo "    (phala CLI returned no compose_hash field — run the deploy directly)"
    else
        echo "    (phala CLI not installed; skipping probe)"
    fi
fi

# --- generated phala deploy command -----------------------------------------

# `--private-key` is REQUIRED. The PRIVATE_KEY env var alternative
# documented in the CLI help is unreliable when invoked via wrapper
# scripts (env doesn't always make it through `exec`), so always pass
# the flag explicitly per CLAUDE.md memory
# `feedback_phala_deploy_private_key_required` — hit twice in a single
# session. `tr -d '\n'` strips a trailing newline that some editors
# tack onto the key file (truncates the key in place otherwise).
DEPLOYER_KEY_FILE="${HOME}/.teesql/global-deployer.key"

if [[ -n "${CVM_ID}" ]]; then
    # Upgrade path. `phala deploy --cvm-id <id>` is the canonical
    # upgrade per CLAUDE.md memory `reference_hub_upgrade_procedure`
    # — `phala cvms upgrade` is broken for our deploy shape and silently
    # discards the encrypted env on every call.
    DEPLOY_VERB="upgrade existing CVM ${CVM_ID}"
    DEPLOY_FLAGS="    --cvm-id ${CVM_ID} \\"
else
    # First-time deploy. Phala allocates a fresh DstackApp + auto-
    # allowlists the compose hash (single-instance v1 — see deploy
    # script header).
    DEPLOY_VERB="first-time deploy (Phala auto-allocates app_id)"
    DEPLOY_FLAGS=""
fi

cat > "${OUT_DIR}/phala-deploy-cmd.sh" <<EOF
#!/usr/bin/env bash
# Generated by scripts/deploy-chain-indexer.sh — re-run the generator
# to refresh.
#
# Mode: ${DEPLOY_VERB}.
# Image tag baked into compose.yml: ${TAG}

set -euo pipefail
cd "\$(dirname "\$0")"

if [[ ! -f "${DEPLOYER_KEY_FILE}" ]]; then
    echo "ERROR: deployer key not found at ${DEPLOYER_KEY_FILE}" >&2
    exit 1
fi

exec phala deploy \\
    --name "${DEPLOY_NAME}" \\
    --compose compose.yml \\
    -e .env \\
${DEPLOY_FLAGS}    --node-id ${NODE_ID} \\
    --disk-size 20G \\
    --kms base \\
    --private-key "\$(tr -d '\\n' < ${DEPLOYER_KEY_FILE})" \\
    --wait
EOF
chmod +x "${OUT_DIR}/phala-deploy-cmd.sh"

# --- summary ----------------------------------------------------------------

echo
echo "==> Deploy bundle written to ${OUT_DIR}/"
echo
echo "    config.toml         — source config (audit)"
echo "    compose.yml         — what Phala hashes + deploys (image tag ${TAG})"
echo "    .env                — encrypted-env payload (mode 600)"
echo "    phala-deploy-cmd.sh — runnable phala deploy"
echo
echo "==> Mode: ${DEPLOY_VERB}"
echo
if [[ -n "${CVM_ID}" ]]; then
    echo "==> Before running the deploy: capture the rendered compose's"
    echo "    on-chain compose_hash and have the Safe owner add it to the"
    echo "    DstackApp's allowed_envs/composes via addComposeHash."
    echo "    See docs/deployment.md for the exact Safe TX shape."
    echo
fi
echo "==> Prerequisite for first deploy: monitor cluster's primary must"
echo "    have run deploy/provision.sql. Re-run after every primary"
echo "    redeploy (pgdata is per-CVM — see CLAUDE.md memory"
echo "    project_primary_pgdata_per_cvm)."
echo
echo "==> Next:"
echo "    cd ${OUT_DIR} && ./phala-deploy-cmd.sh"
