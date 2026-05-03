# API

`teesql-chain-indexer` exposes one REST + SSE surface and one gRPC
surface, both backed by the same service trait so the response
shapes can't drift between transports. Every read endpoint returns a
TDX-attested signed envelope (spec §7).

The full table + the signed-envelope spec live in
`docs/specs/chain-indexer.md` §7. This page is the one-line index +
common curl examples; the spec is canonical when in doubt.

## Conventions

- Base URL: `https://chain-indexer.teesql.com` (production). Local
  dev: `http://127.0.0.1:8080`.
- All chain-scoped routes carry a `:chain` path segment matching the
  shortname in `deploy/prod.config.toml` (`base` for Base mainnet).
- Every read endpoint accepts these query params:
  - `?safety=head|finalized` (default `head`).
    `finalized` long-polls until `chain_state.finalized_block >=
    as_of_block`.
  - `?as_of_block=<N>` — return state at block N, replayed from the
    event log. Mutually exclusive with `?safety`.
  - `?attest=full&nonce=<hex>` — opt in to a freshly-generated TDX
    quote whose `report_data` commits to
    `keccak256(payload_hash || nonce)`. ~50ms latency cost; use
    only for one-shot attestation flows.
- Responses are JSON. `payload_hash =
  keccak256(canonical_json(data) || canonical_json(as_of))` per
  RFC-8785 canonicalization. ECDSA-recover `signer_address` from
  `signature` over `payload_hash` to verify; pin against
  `/v1/attestation`.

## REST endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/health` | Liveness. Unsigned. |
| `GET` | `/v1/attestation` | Boot-time TDX quote whose `report_data` commits to the long-lived signer pubkey. Cache the pubkey per-image. |
| `GET` | `/v1/chains` | Every chain this indexer serves (head + finalized per chain). |
| `GET` | `/v1/:chain/chain` | This chain's head, finalized, last-ingested-event id. |
| `GET` | `/v1/:chain/factories/:addr/clusters` | Every cluster diamond minted by this factory. |
| `GET` | `/v1/:chain/factories/:addr/contains?address=<x>` | `{contains: bool}`. The gas-webhook's per-UserOp call. |
| `GET` | `/v1/:chain/clusters/:addr` | Cluster overview (leader, member count, lifecycle). |
| `GET` | `/v1/:chain/clusters/:addr/leader` | `(member_id, epoch)` — what `leaderLease()` would return. |
| `GET` | `/v1/:chain/clusters/:addr/leader/proof` | Underlying chain events (cross-check; spec §4.1). |
| `GET` | `/v1/:chain/clusters/:addr/members?include_retired=false` | Full member set. |
| `GET` | `/v1/:chain/clusters/:addr/members/proof` | Underlying chain events. |
| `GET` | `/v1/:chain/clusters/:addr/members/:member_id` | Single-member detail. |
| `GET` | `/v1/:chain/clusters/:addr/lifecycle` | `destroyed_at` timestamp (or null). |
| `GET` | `/v1/:chain/clusters/:addr/lifecycle/proof` | Underlying events. |
| `GET` | `/v1/:chain/clusters/:addr/events?since=<id>&kind=<csv>&limit=N` | Paginated raw event stream, ordered by `events.id`. Skips `removed=true`. |
| `GET` | `/v1/:chain/clusters/:addr/events/sse?since=<id>&kind=<csv>` | Long-lived SSE stream. Bare frames for sub-ms fan-out; reconnects pick up via `Last-Event-ID`. Pair with `GET /v1/:chain/events/:id` for per-event signed proof. |
| `GET` | `/v1/:chain/events/:id` | Single event detail in the standard signed envelope. The verification companion to bare SSE frames — fetch when you need cryptographic proof of a specific event id. Returns 404 when no row matches; reorged events resolve and surface `removed: true`. |
| `GET` | `/v1/metrics` | Prometheus metrics (CU saved, events/sec, lag). |

> **Endpoint taxonomy.** `/clusters/:addr/events*` accepts ANY
> contract address, including factory addresses — events are keyed
> on the emitting contract, not on a factory-vs-diamond split. To
> stream a factory's `ClusterDeployed` events, query
> `/v1/:chain/clusters/:factory_addr/events/sse?kind=ClusterDeployed`.
> `/factories/:addr/...` stays restricted to factory-specific
> operations (`clusters`, `contains`); there is no separate
> `/factories/:addr/events*` surface.

## Common call

The single most-frequent request is the gas-webhook's per-UserOp
factory-membership probe (spec §11). On Base mainnet against the v4
`ClusterDiamondFactory`:

```bash
curl -fsS \
    "https://chain-indexer.teesql.com/v1/base/clusters/0x848c17bdbf42d0067727d74955074d36b9c2ba3e/leader" \
  | jq
```

Output shape:

```json
{
  "data": {
    "member_id": "0x...",
    "epoch": 7
  },
  "as_of": {
    "block_number": 45491234,
    "block_hash": "0x...",
    "block_timestamp": 1777771500,
    "finalized_block": 45491222,
    "safety": "head"
  },
  "attestation": {
    "signer_address": "0xa4021ec2...",
    "signature": "0x...",
    "payload_hash": "0x...",
    "signed_at": 1777771502,
    "expires_at": 1777771802
  }
}
```

## SSE example

Long-lived consumer pattern (replaces the polling loops described in
spec §7.3):

```bash
curl -N -H "Accept: text/event-stream" \
    "https://chain-indexer.teesql.com/v1/base/clusters/0x848c.../events/sse?kind=LeaderClaimed,MemberRegistered"
```

Reconnects pass `Last-Event-ID: <last_id>` so the indexer replays
the gap from the `events` table before resuming the live stream.

SSE frames are bare (no per-frame signed envelope) so fan-out stays
in the single-millisecond range. When you need cryptographic proof
of a specific event id — e.g. for an audit log or a sample-
verification flow — fetch the signed envelope by id:

```bash
curl -fsS \
    "https://chain-indexer.teesql.com/v1/base/events/12345" \
  | jq
```

Output is the standard `{data, as_of, attestation}` envelope per
spec §7.1, with `data` carrying the full event row including the
emitting `contract` and the `removed` flag.

## gRPC

Every REST method has a mirror under the `teesql.chain_indexer.v1`
package. Proto definitions live at `proto/chain_indexer.proto`;
Rust consumers generate via `tonic-build`. Adding a third transport
later (e.g. NATS) repeats the pattern: bind to the same service
trait the REST + gRPC layers already implement.

The gRPC listener defaults to `0.0.0.0:8081` (REST/SSE on `:8080`,
gRPC on `:8081` — the Phala gateway maps both ports onto one
hostname). Operators can flip `[grpc] enabled = false` in
`deploy/prod.config.toml` to skip the listener entirely (dev
escape hatch when the port is taken). Production: `chain-
indexer.teesql.com:8081` for the gRPC surface.

## See also

- Full spec: `docs/specs/chain-indexer.md` §7 (parent monorepo)
- Trust model: `docs/trust-model.md` (this repo)
- Deploy / lifecycle: `docs/deployment.md` (this repo)
