# API Authentication

Tovbase ID uses request-level API keys for mutating bank and operator
endpoints. This is transport authorization only; bank attestations, action
attestations, user signatures, and registration receipts are still
cryptographically signed and verified independently.

## Key storage

Runtime config stores only SHA-256 hashes of API keys:

```text
BANK_API_KEYS_JSON=[{"bank_id":"bank-a","key_id":"bank-a-api-1","api_key_hash":"...","status":"active"}]
ADMIN_API_KEYS_JSON=[{"key_id":"admin-api-1","api_key_hash":"...","status":"active"}]
```

Generate records with:

```bash
python scripts/generate_api_key.py --bank-id bank-a --key-id bank-a-api-1
python scripts/generate_api_key.py --admin --key-id admin-api-1
```

The script prints the plaintext `api_key` once and an `env_value` that can be
stored in the deployment secret store. Keep the plaintext key only in the bank
or operator secret manager.

## Bank endpoint headers

Bank write endpoints require:

```text
X-Tovbase-Bank-Id: bank-a
X-Tovbase-Api-Key: <bank API key>
```

The request body `bank_id`, when present, must match `X-Tovbase-Bank-Id`.

Bank-authenticated endpoints:

- `POST /v1/did/register`
- `POST /v1/did/register/batch`
- `POST /v1/did/attest`
- `POST /v1/did/attest/revoke`
- `POST /v1/did/actions/challenge`

## Admin endpoint headers

Operator-only endpoints require:

```text
X-Tovbase-Admin-Key: <admin API key>
```

Admin-authenticated endpoints:

- `GET /v1/did/attest/{hash_id}/audit`
- `GET /v1/did/events/audit`
- `POST /v1/did/anchors`

Public read/verification endpoints remain unauthenticated so relying parties
and bank mirrors can resolve DIDs, verify receipts, inspect registry keys, and
fetch anchor proofs without holding mutation credentials.
