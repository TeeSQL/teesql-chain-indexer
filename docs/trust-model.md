# Trust model

The chain indexer is a **performance shortcut, not a trust dependency**.
Every consumer can independently verify three things:

1. **The indexer's identity** — `GET /v1/attestation` returns a TDX
   quote whose `report_data` field commits to the indexer's signing
   pubkey. Consumers verify the quote locally via `dcap-qvl` (no
   Intel Trust Authority round-trip; same default as the hub since
   2026-04-24) and pin against an MRTD they trust for that image
   hash.

2. **Every signed response** — every API response carries an
   `attestation` envelope `(signer_address, signature, payload_hash,
   signed_at, expires_at)`. The signature is ECDSA over
   `keccak256(canonical_json(data) || canonical_json(as_of))`.
   Consumers ECDSA-recover the signer and check it equals the address
   they pulled from the quote.

3. **The chain commitment** — every response includes `as_of_block`,
   `as_of_block_hash`, `block_timestamp`, and `finalized_block`. A
   skeptical consumer can periodically (1 in N requests, randomly
   sampled) re-issue the same query directly against an RPC and
   compare. Compromised-indexer detection without giving back the
   cost win.

The signing key is derived via
`dstack get_key("teesql-chain-indexer-sign", "")`. The key is bound
to the indexer's `app_id`, so a redeploy that allocates a new
app_id rotates the signer; consumers update their pin.

The indexer's Postgres connection runs over `sqlx-ra-tls` to the
monitor cluster's primary, so the storage layer's transport is
itself attested. Postgres at-rest encryption uses the monitor
cluster's KMS-derived key. The indexer holds no long-lived secrets
outside the dstack KMS.

## Cross-check protocol

For every signed response, the indexer publishes a companion
`/proof` endpoint that returns the underlying chain events the
answer was derived from. Example:

```
GET /v1/base/clusters/0x848c.../leader
  → {data:{member_id, epoch}, as_of:{block_number, ...}, attestation:{...}}

GET /v1/base/clusters/0x848c.../leader/proof?as_of_block=45491234
  → {events: [{block_number, log_index, tx_hash, topic0, topics_rest, data, decoded_kind: "LeaderClaimed", decoded: {...}}, ...]}
```

A skeptical consumer with chain access can request the proof,
replay the events through their own copy of the materializer logic,
and verify they get the same `(member_id, epoch)`. The materializer
logic is open source in `crates/teesql-views/`, so re-derivation is
a few hundred lines, not a re-implementation of the indexer.

The indexer does not require consumers to use the proof endpoint —
it's there so a 1%-sampled cross-check is cheap (one extra HTTP
call plus a tiny `eth_getLogs` against chain to confirm the events
themselves were emitted). Consumers that want stronger guarantees
can sample at higher rates; consumers that trust the attested
signer pin can skip the proof entirely.

## Per-request fresh quote

The default `/v1/attestation` returns a quote generated at indexer
boot, cached for the process lifetime. The `report_data` commits
to the long-lived signing pubkey, so the boot-time quote is
sufficient for verifying any subsequent signed response.

Consumers that want a freshly-generated quote with a per-request
nonce (e.g. for one-shot attestation flows or audit captures) pass
`?attest=full&nonce=<hex>` to any read endpoint. The response
includes an inline `quote_b64` field whose `report_data` commits to
`keccak256(payload_hash || nonce)`. This costs ~50ms per call (TDX
quote generation latency) and is opt-in for that reason.

## What is NOT trust-critical

- **The indexer's availability**. Consumers degrade to direct chain
  reads when the indexer is unreachable (or to long-poll against
  `?safety=finalized` when freshness slips). The single-instance v1
  posture (spec §9) is acceptable precisely because consumers don't
  hard-fail on indexer outages.
- **The indexer's data layer**. The Postgres on the monitor cluster
  is a cache of chain. If it's lost or corrupted, the indexer
  re-bootstraps from `chains.factories.from_block` on cold start.
  Materialized views can always be truncated + rebuilt from the
  `events` table.
- **The indexer's cross-chain consistency**. Each chain runs its own
  process per spec §6. The HTTP server is shared, but the ingestion
  pipelines are isolated; one chain's RPC outage stalls only its own
  reads.

## See also

- Full spec: `docs/specs/chain-indexer.md` §4 (parent monorepo) — this
  document tracks the spec verbatim
- API: `docs/api.md` (this repo)
- Operator-side trust pinning: `docs/deployment.md` (this repo) — the
  step-5 verification pulls the boot-time quote and is what a
  consumer should automate as part of their pin-update workflow
