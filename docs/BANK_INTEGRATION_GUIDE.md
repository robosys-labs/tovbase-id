# Bank Integration Guide

This guide describes the first pilot workflow for a bank integrating Tovbase ID.
It assumes the bank owns KYC collection, per-user salt custody, customer mapping,
and any liveness provider relationship.

## 1. Initialize the registry database

For local development:

```bash
cp .env.example .env
pip install -e ".[dev]"
python scripts/migrate.py
uvicorn app.main:app --reload --port 8001
```

`scripts/migrate.py` is intentionally idempotent. It creates the portable
registry tables used by SQLite development and PostgreSQL production.

## 2. Configure a persistent receipt-signing key

Generate an Ed25519 key:

```bash
python scripts/generate_signing_key.py \
  --node-id tovbase-primary-ng-1 \
  --key-id tovbase-registry-2026-01
```

Copy the `env` values into the runtime secret store. The private key signs
registration receipts only. It is not a user key, and it cannot sign user
actions.

Banks can fetch the active public key at:

```text
GET /v1/did/keys/current
```

Use that public key to verify registration receipts offline.

For rotation, deploy the new private key as the active signing key and keep old
public keys in `DID_VERIFYING_KEYS_JSON`. The API exposes all active and
verify-only public keys at:

```text
GET /v1/did/keys
```

This lets old receipts keep verifying by `key_id` after the signing key changes.

## 3. Configure bank API authentication

Generate a bank API key record:

```bash
python scripts/generate_api_key.py --bank-id bank-a --key-id bank-a-api-1
```

Copy the printed `env_value` into `BANK_API_KEYS_JSON` in the deployment secret
store. The plaintext `api_key` is shown once and should be stored only in the
bank or operator secret manager.

Bank write requests include:

```text
X-Tovbase-Bank-Id: bank-a
X-Tovbase-Api-Key: <bank API key>
```

Audit export and anchor creation use an operator key generated with:

```bash
python scripts/generate_api_key.py --admin --key-id admin-api-1
```

See `docs/API_AUTHENTICATION.md` for the endpoint matrix.

## 4. Hash identity data inside the bank boundary

Use the browser reference in `sdk/browser/tovbase-id-sdk.mjs` as the audit
baseline for web and mobile SDK work.

The first canonicalization contract is documented in
`docs/KYC_CANONICALIZATION_V1.md` and represented as
`schemas/kyc_ng_v1.schema.json`.

```js
import { createRegistrationRequest } from "./sdk/browser/tovbase-id-sdk.mjs";

const request = await createRegistrationRequest({
  identity: {
    nin: "12345678901",
    bvn: "22233344455",
    passport_number: "A1234567",
  },
  saltBase64Url: bankHeldUserSalt,
  webauthnCredentialId: credentialId,
  webauthnPublicKeyJwk: publicKeyJwk,
  bankId: "bank-a",
});
```

The returned request contains:

- `hash_id`
- `did` derivable as `did:tov:<hash_id>`
- WebAuthn public metadata
- device public-key fingerprint
- SDK/schema metadata

It does not contain:

- NIN
- BVN
- passport number
- raw document/media
- salt
- bank customer id
- user private key

## 5. Register the DID

```text
POST /v1/did/register
X-Tovbase-Bank-Id: bank-a
X-Tovbase-Api-Key: <bank API key>
```

The registry stores the hash, DID document, append-only event, signed receipt,
and optional bank attestation in one transaction.

If a bank attestation is supplied, it must be signed by a trusted bank key from
`TRUSTED_BANK_KEYS_JSON`. The complete signed attestation and revocation flow is
documented in `docs/BANK_ATTESTATION_WORKFLOW.md`.

Duplicate exact registrations are idempotent. A duplicate `hash_id` with a
different public-key fingerprint returns `409 Conflict`.

## 6. Recover or rekey a DID

When a user replaces a phone, rotates a passkey, or completes a bank-controlled
recovery handshake, the bank can update the DID verification key without moving
raw PII or salts into Tovbase.

```text
POST /v1/did/rekey
X-Tovbase-Bank-Id: bank-a
X-Tovbase-Api-Key: <bank API key>
```

The request must be signed by a trusted bank key over the canonical
`tovbase-id:did-rekey:v1` envelope. The signed envelope includes:

- `hash_id`
- `bank_id`
- new `webauthn_credential_id`
- new `webauthn_public_key`
- new `device_pubkey_fingerprint`
- `rekeyed_at`
- `reason_code`
- optional `bank_credential_id`
- no-PII `payload`

The registry verifies the bank signature, updates the DID document to version
`N+1`, records an `identity_rekeyed` event in the per-identity hash chain, and
returns the updated DID document. If the same key material is submitted again,
the endpoint returns `unchanged` for safe retry.

The `hash_id` and DID remain stable during rekey so relying parties keep one
cryptographic identity. Banks that want a new identity hash after recovery can
perform a normal new registration instead and manage any customer merge policy
inside bank systems.

## 7. Batch migration format

Existing bank customers can be migrated with precomputed registration entries
using:

```text
schemas/batch_registration.schema.json
examples/batch_registration.json
```

Each batch entry is the same no-PII request body accepted by
`POST /v1/did/register`, wrapped in a bank-scoped batch envelope.

Submit a batch with:

```text
POST /v1/did/register/batch
X-Tovbase-Bank-Id: bank-a
X-Tovbase-Api-Key: <bank API key>
```

The endpoint applies the authenticated envelope `bank_id` to every entry and
processes entries independently through the normal registration path. Results
include `registered`, `exists`, or `failed` per entry, so a migration can safely
retry the same batch without duplicating identities.

## 8. Signed official actions

Create a timestamped action challenge:

```text
POST /v1/did/actions/challenge
X-Tovbase-Bank-Id: bank-a
X-Tovbase-Api-Key: <bank API key>
```

The user signs the returned `challenge_hash`. The challenge envelope includes
the DID, bank id, action type, document/media hash, nonce, policy version,
`issued_at`, and `expires_at`.

Submit the signature and any step-up attestation:

```text
POST /v1/did/actions/submit
```

Policy examples:

- `instant`: passkey signature only.
- `aal2`: passkey plus bank handshake credential reference.
- `aal3`: passkey plus bank handshake credential plus camera/liveness result.

Camera/liveness media remains with the bank or liveness provider. Tovbase stores
only evidence hashes and signed result metadata. Provider signature requirements
are documented in `docs/ACTION_ATTESTATION_PROVIDER_WORKFLOW.md`.

Backend timing can be checked with `scripts/benchmark_action_flow.py`; see
`docs/SIGNED_ACTION_PERFORMANCE.md`.

## 9. Mirror readiness

The pilot read mirror uses PostgreSQL logical replication over the registry
tables. The operational runbook is `docs/BANK_MIRROR_RUNBOOK.md`.

Banks can validate the application-level contract with:

```text
GET /v1/did/health
GET /v1/did/{did}
GET /v1/did/hash/{hash_id}
POST /v1/did/receipt/verify
```
