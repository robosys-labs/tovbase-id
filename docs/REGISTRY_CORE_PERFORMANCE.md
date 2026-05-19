# Registry Core Performance

Use `scripts/benchmark_registry_core.py` to measure the lightweight registry
hot paths without Redis, Qdrant, NATS, GPU, blockchain, or external bank
infrastructure.

```bash
python scripts/benchmark_registry_core.py --iterations 10
```

The benchmark runs against an isolated SQLite database through FastAPI
`TestClient` and configures temporary bank API and attestation keys in memory.
It measures:

- `POST /v1/did/register`
- `GET /v1/did/{did}`
- `GET /v1/did/hash/{hash_id}`
- `POST /v1/did/receipt/verify`
- `POST /v1/did/attest`

Pilot local targets:

| Path | Target |
| --- | --- |
| Register p95 | < 75 ms |
| Resolve by DID p95 | < 20 ms |
| Resolve by hash p95 | < 20 ms |
| Receipt verify p95 | < 20 ms through API |
| Attestation upsert p95 | < 75 ms |

These numbers are not a substitute for PostgreSQL/load testing, but they keep
the deterministic registry core honest in CI and catch accidental slowdowns in
the no-network, no-provider path.
