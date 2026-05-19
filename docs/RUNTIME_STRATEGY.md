# Runtime Strategy

Tovbase ID starts in Python intentionally, but Python is not treated as a
religion or an irreversible production bet.

Tracking issue: <https://github.com/robosys-labs/tovbase-id/issues/19>

## Current decision

The v1 pilot registry core remains Python/FastAPI because it matches the
current Tovbase engineering stack and lets us stabilize the bank-facing
contracts quickly:

- DID method and document shape.
- No-PII request schemas.
- Receipt signing and verification envelopes.
- Bank and provider attestation signatures.
- PostgreSQL logical replication tables.
- Batch migration semantics.
- Action challenge and submission policy.

The current hot path is mostly validation, indexed PostgreSQL lookup, receipt
signing, Ed25519 verification through native crypto libraries, and JSON
serialization. That makes Python acceptable for pilot delivery while the
protocol is still changing.

## Production stance

The likely long-term production-core candidate is Go, not Python, if measured
load shows Python is too heavy for bank-operated nodes.

Why Go is the first migration candidate:

- Single static-ish binary is easy for bank infrastructure teams to operate.
- Lower idle memory than typical Python app workers.
- Strong concurrency for high lookup volume.
- Excellent PostgreSQL, HTTP, gRPC, and mTLS support.
- Faster delivery and broader bank ops familiarity than Rust for this service
  class.

Rust remains an option for narrow crypto-critical components, but a full Rust
registry service is not the default unless we need stronger memory-safety or
performance guarantees than Go provides.

## Migration gates

Do not rewrite during the pilot only because another runtime looks cleaner.
Revisit the registry-core runtime when one or more of these become true:

- API worker RSS is consistently above `API_MEMORY_TARGET_MB` under realistic
  registry traffic.
- `POST /v1/did/register` p95 exceeds 75 ms excluding bank network.
- DID/hash resolve p95 exceeds 20 ms inside a local bank node.
- CPU cost per verification makes bank-operated mirrors materially more
  expensive than the target deployment envelope.
- A bank requires a single-binary node distribution for production approval.
- API contracts, schemas, receipt envelopes, and replication tables are stable
  enough to avoid rewriting moving targets.

## Current guardrail

`GET /v1/did/health` exposes a `runtime` object with:

- implementation name,
- process id,
- Python version,
- platform,
- RSS bytes/MB when available,
- configured memory target,
- whether memory is within target,
- migration candidate.

This keeps the Python-vs-Go decision measurable during pilots.
