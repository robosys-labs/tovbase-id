# Event Chain Audit

Every registry mutation writes an append-only `registry_events` row. Each event
stores:

- canonical payload hash,
- previous event hash for the same aggregate,
- monotonic sequence number for the aggregate,
- event hash over the canonical payload and previous hash.

This gives operators and bank auditors a lightweight tamper-detection spine
without introducing blockchain or consensus into the v1 hot path.

## Admin API

```text
GET /v1/did/events/audit
X-Tovbase-Admin-Key: <admin API key>
```

Optional scope:

```text
GET /v1/did/events/audit?aggregate_id=<hash-or-action-id>
```

The response reports global validity, aggregate counts, event counts, and any
problems such as:

- `sequence_mismatch`
- `previous_hash_mismatch`
- `payload_hash_mismatch`
- `event_hash_mismatch`

## CLI

```bash
python scripts/verify_event_chain.py
python scripts/verify_event_chain.py --aggregate-id <hash-or-action-id>
```

The command exits non-zero if any chain problem is detected.
