# Bank Attestation Workflow

Bank attestations are signed claims that a bank has seen or verified a registry
hash under its own KYC controls. They do not expose customer IDs, raw PII, salts,
documents, or biometric media.

## 1. Generate a bank attestation key

```bash
python scripts/generate_bank_key.py \
  --bank-id bank-a \
  --key-id bank-a-signing-2026-01
```

The bank keeps `bank_private_key_b64` in its own secret store. Tovbase receives
only the `trusted_key_record` through `TRUSTED_BANK_KEYS_JSON`.

Example registry config:

```json
[
  {
    "bank_id": "bank-a",
    "key_id": "bank-a-signing-2026-01",
    "signature_algorithm": "ed25519",
    "public_key_jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "base64url public key"
    },
    "status": "active"
  }
]
```

## 2. Sign an attestation

The bank signs this canonical envelope:

```json
{
  "purpose": "tovbase-id:bank-attestation:v1",
  "hash_id": "<sha256 hex>",
  "bank_id": "bank-a",
  "attestation_type": "kyc_hash_seen",
  "attestation_hash": "<sha256 hex evidence digest>",
  "issued_at": "2026-05-19T21:45:00Z",
  "expires_at": null,
  "key_id": "bank-a-signing-2026-01",
  "payload": {}
}
```

Rules:

- Serialize canonical JSON with sorted keys and no insignificant whitespace.
- Sign the UTF-8 canonical JSON bytes with Ed25519.
- Send the base64url signature in `bank_attestation.signature`.
- Keep the raw KYC evidence inside the bank boundary.

Tovbase rejects attestations when the bank key is unknown, inactive, uses an
unsupported algorithm, or the signature does not verify.

## 3. Submit or update

```text
POST /v1/did/attest
```

Upsert key:

```text
(hash_id, bank_id, attestation_type)
```

The response includes `signature_verified`.

## 4. Revoke

Revocations are signed too. The bank signs:

```json
{
  "purpose": "tovbase-id:bank-attestation-revocation:v1",
  "hash_id": "<sha256 hex>",
  "bank_id": "bank-a",
  "attestation_type": "kyc_hash_seen",
  "revoked_at": "2026-05-19T22:00:00Z",
  "reason_code": "bank_revoked",
  "key_id": "bank-a-signing-2026-01",
  "payload": {}
}
```

Submit:

```text
POST /v1/did/attest/revoke
```

Revoked attestations disappear from normal DID resolution but remain in audit
exports.

## 5. Audit export

```text
GET /v1/did/attest/{hash_id}/audit
```

The audit export returns all attestations for the hash, including revoked
records, signatures, verification status, payload metadata, and timestamps.
It still does not return raw PII or bank customer mappings.
