# teesql-chain-indexer

Attested Postgres-backed event log over an EVM RPC. Replaces O(N)
consumer polling with an O(1) push subscription: every TeeSQL
component that needs on-chain truth (sidecar leader monitor, hub
member registry, dns-controller per-cluster watcher, gas-sponsorship
webhook) reads from this service instead of opening its own Alchemy
connection. One WS subscription fans out to every consumer over
HTTPS + SSE + gRPC, with TDX-attested signed responses so consumers
can verify the indexer's identity and re-derive any answer
independently. See the spec at
`docs/specs/chain-indexer.md` (relative to the parent monorepo) for
the full design.

## Crates

- `teesql-chain-indexer-core` — generic factory + child-contract
  ingest pipeline (WS subscribe, cold backfill, reorg detection,
  `Decoder` and `View` traits, sqlx-Postgres event sink). No TeeSQL
  types.
- `teesql-chain-indexer-abi` — `alloy::sol!` bindings for the cluster
  diamond factory + cluster diamond, plus `Decoder` implementations.
- `teesql-chain-indexer-views` — materializers that turn decoded
  events into `cluster_leader` / `cluster_members` /
  `cluster_lifecycle` summary rows.
- `teesql-chain-indexer-attest` — KMS-derived signing key plus TDX
  quote binding for the response-envelope `attestation` field.
- `teesql-chain-indexer-server` — axum HTTP + SSE routes (and the
  gRPC mirror under `teesql.chain_indexer.v1`) wrapped in the signed
  response envelope.
- `teesql-chain-indexer` — binary that wires everything together.

## Building

This crate has unpublished sibling dependencies (`sqlx-ra-tls` and
`ra-tls-parse`, neither on crates.io yet) wired as path deps to
`../sqlx-ra-tls` and `../ra-tls-parse`. To build, check it out under
a parent directory that holds those siblings — either:

```
mkdir tee && cd tee
git clone https://github.com/TeeSQL/teesql-chain-indexer
git clone https://github.com/TeeSQL/sqlx-ra-tls
git clone https://github.com/TeeSQL/ra-tls-parse
cd teesql-chain-indexer && cargo build --workspace
```

Or check out the `dstackgres` parent monorepo (private) where this
crate lives as a submodule under `open-source/teesql-chain-indexer/`
alongside the others. Once `sqlx-ra-tls` and `ra-tls-parse` publish
to crates.io, this layout requirement goes away.

## License

Apache-2.0. The canonical mirror lives at
`github.com/TeeSQL/teesql-chain-indexer`.
