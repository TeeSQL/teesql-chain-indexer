#!/usr/bin/env bash
# Build and publish `ghcr.io/teesql/teesql-chain-indexer:vX.Y.Z` to GHCR.
#
# Usage:
#   ./scripts/publish-chain-indexer.sh [TAG] [--dry-run]
#
# The tag defaults to `v` + the workspace `package.version` from the
# top-level `Cargo.toml` (every crate uses `version.workspace = true`,
# so one bump moves the whole bake in lockstep — same convention the
# monitoring-hub publish script follows). Pass an explicit tag to
# republish a specific release; the manifest-inspect step at the end
# guards against a silent `docker push` no-op (CLAUDE.md memory:
# `feedback_verify_image_pushed`).
#
# # Build context
#
# The chain-indexer workspace path-deps `sqlx-ra-tls` and `ra-tls-parse`
# from sibling directories under the parent monorepo's `open-source/`
# tree. Docker can't COPY across context boundaries so we materialize a
# tarball context that places these trees alongside the workspace and
# feed that to `docker build` on stdin. Same trick the parent monorepo's
# own Dockerfile.dns-controller uses (it operates from the monorepo root
# directly, where `open-source/sqlx-ra-tls` is already a sibling); the
# standalone open-source repo doesn't have that luxury, so we stage.

set -euo pipefail

# Resolve the chain-indexer repo root from the script's own location so
# this works equally well whether invoked from the open-source/teesql-
# chain-indexer/ subdir of the parent monorepo or from a standalone
# clone of github.com/teesql/teesql-chain-indexer.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DRY_RUN="false"
TAG=""
for arg in "$@"; do
    case "${arg}" in
        --dry-run) DRY_RUN="true" ;;
        v[0-9]*) TAG="${arg}" ;;
        *) echo "ERROR: unrecognized arg \`${arg}\` (expected --dry-run or vX.Y.Z)" >&2; exit 2 ;;
    esac
done

if [[ -z "${TAG}" ]]; then
    # Workspace version is the source of truth — every crate inherits it
    # via `version.workspace = true`. The crate `version = "0.1.0"`
    # line under [workspace.package] is a top-of-file convention.
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

IMAGE="ghcr.io/teesql/teesql-chain-indexer:${TAG}"

# Working tree must be clean so the publish is reproducible from the
# sha. `git diff --quiet` returns nonzero on dirty tree; we run it
# inside the chain-indexer repo (which may be a submodule of the
# parent monorepo OR the standalone github.com/teesql clone — git
# auto-discovers either way).
if ! (cd "${REPO_ROOT}" && git diff --quiet HEAD -- . 2>/dev/null); then
    echo "ERROR: ${REPO_ROOT} working tree is dirty — commit or stash before publishing" >&2
    exit 1
fi

# Locate the path-deps. Two layouts work:
#   1. Inside the parent monorepo:
#        open-source/teesql-chain-indexer/   (REPO_ROOT)
#        open-source/sqlx-ra-tls/             (sibling)
#        open-source/ra-tls-parse/            (sibling)
#   2. Standalone github.com/teesql clone with sibling submodule
#      checkouts at ../sqlx-ra-tls and ../ra-tls-parse.
SQLX_RA_TLS="${SQLX_RA_TLS:-${REPO_ROOT}/../sqlx-ra-tls}"
RA_TLS_PARSE="${RA_TLS_PARSE:-${REPO_ROOT}/../ra-tls-parse}"

if [[ ! -d "${SQLX_RA_TLS}" ]]; then
    echo "ERROR: sqlx-ra-tls path dep not found at ${SQLX_RA_TLS}" >&2
    echo "       Override with SQLX_RA_TLS=<path>." >&2
    exit 1
fi
if [[ ! -d "${RA_TLS_PARSE}" ]]; then
    echo "ERROR: ra-tls-parse path dep not found at ${RA_TLS_PARSE}" >&2
    echo "       Override with RA_TLS_PARSE=<path>." >&2
    exit 1
fi

# Stage a tarball build context. `mktemp -d` then trap-cleanup so the
# context disappears even on a failed build. We hardlink-copy with `cp
# -al` where supported to keep the staging step O(1) on disk.
STAGE="$(mktemp -d -t teesql-chain-indexer-ctx.XXXXXX)"
trap 'rm -rf "${STAGE}"' EXIT

echo "==> Staging build context at ${STAGE}"
# Copy workspace contents (resolving symlinks where necessary). We
# explicitly enumerate so we don't drag in `target/` or `Cargo.lock`
# editor backups.
for entry in Cargo.toml Cargo.lock crates proto deploy LICENSE README.md Dockerfile; do
    if [[ -e "${REPO_ROOT}/${entry}" ]]; then
        cp -aL "${REPO_ROOT}/${entry}" "${STAGE}/"
    fi
done

# Sibling path-deps land at the context root so the Dockerfile's
# `COPY sqlx-ra-tls /sqlx-ra-tls` line resolves. The double-slash
# Docker quirk (image path needing a leading `/`) is handled inside
# the Dockerfile itself.
cp -aL "${SQLX_RA_TLS}" "${STAGE}/sqlx-ra-tls"
cp -aL "${RA_TLS_PARSE}" "${STAGE}/ra-tls-parse"

if [[ "${DRY_RUN}" == "true" ]]; then
    echo
    echo "==> DRY RUN — context staged at ${STAGE}; not removing trap"
    trap - EXIT
    echo "    inspect with: ls -la ${STAGE}"
    echo "    image would be: ${IMAGE}"
    exit 0
fi

echo "==> Building ${IMAGE}"
# `--platform linux/amd64` because Phala TDX nodes are x86_64. Building
# on an arm64 dev box without this flag silently produces an arm image
# that fails to start on the cluster.
docker buildx build \
    --platform linux/amd64 \
    --load \
    -t "${IMAGE}" \
    "${STAGE}"

echo
echo "==> Authenticating to GHCR as $(gh api user --jq '.login')"
gh auth token | docker login ghcr.io -u "$(gh api user --jq '.login')" --password-stdin

echo
echo "==> Pushing ${IMAGE}"
docker push "${IMAGE}"

echo
echo "==> Verifying ${IMAGE} is reachable on GHCR"
# `docker manifest inspect` against the registry catches a silent push
# no-op (auth-scope mismatch, network blip). Without this the next
# deploy attempt fails far away from the publish step with a confusing
# `manifest unknown` boot loop. See CLAUDE.md memory
# `feedback_verify_image_pushed`.
if ! docker manifest inspect "${IMAGE}" >/dev/null; then
    echo "ERROR: ${IMAGE} manifest not reachable after push" >&2
    exit 1
fi

echo
echo "Done. Image published: ${IMAGE}"
echo
echo "Next: ./scripts/deploy-chain-indexer.sh ${TAG}"
echo "      (or pass deploy/prod.config.toml + node id explicitly — see"
echo "       deploy script header for usage)"
