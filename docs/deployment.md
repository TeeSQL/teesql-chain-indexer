# Deployment

`teesql-chain-indexer` deploys as a single CVM via dstack on Phala
Cloud. The lifecycle has two distinct paths — first deploy and
upgrade — that share the same publish step and bundle generator.

This document covers what to do; the *why* lives in the spec
(`docs/specs/chain-indexer.md` in the parent monorepo, especially
§3.3, §6.1, §8, and §9).

## Preconditions

- `phala` CLI authenticated.
- `~/.teesql/global-deployer.key` (the long-lived deployer EOA used
  for every TeeSQL cluster + app deploy, mode 600). The Phala deploy
  always passes this via `--private-key` explicitly — never via the
  `PRIVATE_KEY` env var, which is unreliable through wrapper scripts.
- A 32-byte `TEESQL_INDEXER_CLUSTER_SECRET` allowlisted on the
  monitor cluster's sidecar wire-protocol auth map for the
  `chain_indexer_writer` Postgres role. Generate with
  `openssl rand -hex 32` once and persist in
  `~/.teesql/chain-indexer.env`.
- Monitor cluster's primary has run `deploy/provision.sql`. pgdata is
  per-CVM, so this must be re-run after every primary redeploy
  (CLAUDE.md memory `project_primary_pgdata_per_cvm`). A missing
  `chain_indexer_writer` role surfaces as a sidecar
  `pg_auth_inject failed: early eof` followed by Postgres
  `FATAL: role "chain_indexer_writer" does not exist`.
- Alchemy API key in `deploy/prod.config.toml` — never use the public
  `mainnet.base.org` RPC for production (CLAUDE.md memory
  `feedback_no_public_rpc_for_production`); a single CVM saturates a
  public endpoint within minutes.

## First deploy

Run once per fresh DstackApp; Phala auto-allocates the app_id and
auto-allowlists the compose hash (single-instance v1; the HA
multi-instance variant is a follow-up spec — see chain-indexer §9).

1. **Bump the version + add a changelog entry**

   Every deploy gets a fresh version. No exceptions, even for tiny
   fixes (CLAUDE.md memory
   `feedback_hub_version_bump_per_deploy`). Three files committed
   together:

   - `Cargo.toml` workspace `package.version`
   - `deploy/compose.template.yml` (the template's `image:` line
     references `${INDEXER_IMAGE_TAG}` which the deploy script
     substitutes from the workspace version, so this is implicit
     today; once the chain-indexer grows a separate changelog file
     bump it here too)
   - any user-facing release notes in `README.md` if applicable

2. **Publish the image**

   ```bash
   ./scripts/publish-chain-indexer.sh
   docker manifest inspect ghcr.io/teesql/teesql-chain-indexer:vX.Y.Z
   ```

   The publish script verifies the manifest itself; the explicit
   manifest-inspect is here as an extra confirmation when working
   from a CI shell that hides the script's tail (CLAUDE.md memory
   `feedback_verify_image_pushed`).

3. **Generate the deploy bundle**

   ```bash
   set -a; source ~/.teesql/chain-indexer.env; set +a
   ./scripts/deploy-chain-indexer.sh
   ```

   Emits `deploy/out/{config.toml, compose.yml, .env,
   phala-deploy-cmd.sh}`. The `.env` is mode-600; don't `cat` it —
   it has the cluster secret. The compose's image tag is locked to
   the workspace version at render time so Phala's compose-hash
   derivation captures the exact image.

4. **Run the deploy**

   ```bash
   cd deploy/out && ./phala-deploy-cmd.sh
   ```

   Capture the allocated `app_id` + `vm_uuid` from the output:

   ```bash
   phala cvms list -j | jq '.items[] | select(.cvmName=="teesql-chain-indexer-prod")'
   ```

5. **Verify the indexer is reachable**

   ```bash
   curl -fsS https://chain-indexer.teesql.com/v1/health
   curl -fsS https://chain-indexer.teesql.com/v1/attestation | jq
   curl -fsS "https://chain-indexer.teesql.com/v1/base/factories/0xfbd65e6b30f40db87159a5d3a390fc9c2bd87e11/contains?address=0x848c17bdbf42d0067727d74955074d36b9c2ba3e" | jq
   ```

   The third call exercises the gas-webhook integration path (see
   spec §11). The second returns the boot-time TDX quote whose
   `report_data` commits to the long-lived signing pubkey — pin
   that pubkey in any consumer that wants strong attestation.

## Upgrade an existing CVM

`phala deploy --cvm-id <id>` is the canonical upgrade — `phala cvms
upgrade` is broken for our deploy shape and silently discards the
encrypted env on every call (CLAUDE.md memory
`reference_hub_upgrade_procedure`).

1. Bump the version + publish (steps 1-2 above).
2. **Re-apply `deploy/provision.sql` against the monitor cluster's
   primary** before deploying the new image. The script's `ADD COLUMN
   IF NOT EXISTS` statements are idempotent and back-fill any new
   columns onto the existing roster without dropping data. The
   indexer's startup preflight check (`schema_preflight.rs` —
   `REQUIRED_COLUMNS` registry) refuses to start when columns added
   in newer materializer code are missing from the database, so
   skipping this step turns into an at-boot "migration required"
   error after the deploy lands. Diff `REQUIRED_COLUMNS` against the
   previously-deployed tag to see exactly which columns are new in
   this build.
3. Find the existing CVM:

   ```bash
   phala cvms list -j | jq '.items[] | select(.cvmName=="teesql-chain-indexer-prod") | {cvmName, vmUuid, appId}'
   ```

4. Generate the deploy bundle in `--cvm-id` mode:

   ```bash
   set -a; source ~/.teesql/chain-indexer.env; set +a
   ./scripts/deploy-chain-indexer.sh --cvm-id <vmUuid>
   ```

   The bundle generator switches the emitted `phala-deploy-cmd.sh`
   to upgrade mode. The new compose hash needs to be allowlisted
   on-chain via `addComposeHash` on the DstackApp before the deploy
   succeeds — the script prints the rendered compose so the operator
   can extract the hash via `phala cvms provision --dry-run` and
   hand it to the Safe TX builder.

5. Apply the upgrade:

   ```bash
   cd deploy/out && ./phala-deploy-cmd.sh
   ```

6. Verify (same checks as step 5 above). Cold-start backfill takes
   a few minutes; `as_of.block_number` should advance from the last
   pre-upgrade `chain_state.head_block` cursor in the database.

## Cluster moves

If the monitor cluster's UUID changes (full redeploy):

1. Update `storage.cluster_uuid` in `deploy/prod.config.toml`.
2. Re-run `deploy/provision.sql` against the new primary.
3. Allocate a fresh `TEESQL_INDEXER_CLUSTER_SECRET` and have the new
   monitor cluster's sidecar allowlist it for `chain_indexer_writer`.
4. Run an upgrade against the existing chain-indexer CVM (the
   indexer's `app_id` does not change — only its storage target does).

The indexer's `events` history does NOT survive a monitor-cluster
move. Cold-start backfill from `chains.factories.from_block` rebuilds
the full event log from chain. This typically takes 5-15 minutes for
the current TeeSQL fleet's event volume.

## Rollback

Single-instance v1: rollback is "deploy the previous version's tag
via `--cvm-id`." Storage state is forward-only (Postgres
migrations don't auto-revert), so a major schema change requires
either a forward-only fix or a full redeploy + provision-sql + cold-
start backfill.

For minor patch rollbacks, the materialized views can always be
truncated + rebuilt from the `events` table — see spec §5.

## See also

- Spec: `docs/specs/chain-indexer.md` (parent monorepo)
- Pattern source: `docs/runbooks/monitoring-hub-upgrade.md` (parent
  monorepo) — same overall lifecycle, different image
- Pattern source: `docs/runbooks/dns-controller-deploy.md` (parent
  monorepo) — equivalent first-deploy walkthrough for the
  dns-controller
