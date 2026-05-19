# Merkle Anchoring Workflow

Anchoring is an optional Phase 3 integrity aid. It is not required for registry
correctness or normal lookup. The registry remains useful when public-chain or
external anchoring is unavailable.

Tovbase anchors receipt payload hashes inside a closed time window:

```text
leaf = registration_receipts.payload_hash
root = MerkleRoot(sorted(leaves))
```

If a level has an odd number of leaves, the final leaf is duplicated for that
level. Pair hashes are computed as:

```text
SHA-256(left_bytes || right_bytes)
```

## Create an anchor

```text
POST /v1/did/anchors
```

Request:

```json
{
  "window_start": "2026-05-19T00:00:00Z",
  "window_end": "2026-05-20T00:00:00Z",
  "anchor_network": "internal",
  "anchor_txid": "optional-external-reference"
}
```

The response contains `anchor_id`, `merkle_root`, `hash_count`, and the window.
The anchor row also stores the exact leaf hash list used for future proof
generation.

Empty windows are rejected.

## Fetch an anchor

```text
GET /v1/did/anchors/{anchor_id}
```

## Generate a receipt inclusion proof

```text
GET /v1/did/anchors/{anchor_id}/proof/{receipt_id}
```

The proof response contains:

- `payload_hash`
- `merkle_root`
- `leaf_index`
- ordered sibling proof steps
- `verified`

Auditors can recompute the proof from the receipt payload hash and the returned
proof steps without trusting the database row.

## Operational notes

- Create anchors only for closed windows to avoid late-arriving receipts inside
  an already-anchored window.
- External publication of `merkle_root` is optional and can be added later by
  writing `anchor_network` and `anchor_txid`.
- Anchoring proves inclusion in a batch. It does not reveal PII and does not
  replace signed receipts.
