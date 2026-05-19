# Tovbase DID Registry Architecture

## Executive summary

Tovbase can support bank-grade decentralized identity as a federated hash
registry: SDKs hash identity inputs on the user's device, Tovbase stores only
derived hashes, WebAuthn credential metadata, DID records, signed receipts, and
bank attestations, and partner banks operate mirror nodes so lookup continues
even if the Tovbase primary is offline.

The first delivery is registry-core only. It does not introduce ML, GPUs,
blockchain dependency, raw PII storage, centrally stored user private keys, or
server-side WebAuthn challenge verification. It is deliberately small
infrastructure: deterministic hashing, PostgreSQL durability, signed receipts,
append-only registry events, and mirrorable records.

## Research-backed technology choices

This architecture is optimized for low memory, low CPU, and operational
flexibility. It avoids heavyweight consensus on day one and chooses components
that already fit Tovbase's current Python/FastAPI/PostgreSQL deployment.

| Capability | Chosen technology | Why this is the lightweight choice | Source |
| --- | --- | --- | --- |
| DID data model | W3C DID Core-compatible `did:tov` method | DID Core supports verifiable data registries and cryptographic verification methods without requiring a blockchain. | [W3C DID Core](https://www.w3.org/TR/did/) |
| User key control | WebAuthn/passkeys | WebAuthn creates public-key credentials in authenticators; the public key is returned to the relying party while the private key remains with the authenticator. | [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) |
| User UX | FIDO passkeys | Passkeys let users approve with the same biometric/PIN unlock flow they already use on devices. | [FIDO Passkeys](https://fidoalliance.org/passkeys/) |
| L2 mirroring | PostgreSQL logical replication | Native table-level replication with transactional ordering; no new data store for read mirrors. | [PostgreSQL logical replication](https://www.postgresql.org/docs/16/logical-replication.html) |
| L3 audit stream | NATS JetStream | NATS is a single binary with low memory/CPU goals; JetStream adds persistence and optimized Raft clustering when a quorum log is needed. | [NATS](https://nats.io/about/), [JetStream clustering](https://docs.nats.io/running-a-nats-service/configuration/clustering/jetstream_clustering) |
| Bank-to-node RPC | REST first, gRPC optional for bank mirrors | REST keeps v1 integration simple. gRPC/protobuf is reserved for high-throughput mirror streams and strongly typed bank SDKs. | [gRPC introduction](https://grpc.io/docs/what-is-grpc/introduction/) |
| Landing/edge delivery | Static Next page or Cloudflare Worker custom domain | `id.tovbase.com` can run as a static product surface with API calls proxied to the core backend. | [Cloudflare custom domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/) |

Decision: v1 ships as a small FastAPI backend in this dedicated `tovbase-id`
repository. A separate Rust/Go registry microservice is only justified after
measured Python CPU or memory pressure, because the registry's hot path is
mostly validation, hash normalization, indexed PostgreSQL lookup, and signature
verification.

## Efficient target architecture

The production shape is intentionally split into a tiny control plane and a
mirrorable data plane.

```text
Browser/mobile SDK
  - WebAuthn/passkey creation
  - PII normalization and salted SHA-256 hashing
  - no raw PII sent to Tovbase
        |
        v
Tovbase DID API, FastAPI /v1/did/*
  - schema validation
  - DID derivation
  - receipt signing
  - bank attestation ingestion
        |
        v
PostgreSQL registry tables
  - identity_hashes
  - did_documents
  - registry_events
  - registration_receipts
  - bank_attestations
        |
        +--> Logical replication publication --> Bank read mirrors
        |
        +--> Optional JetStream append log --> L3 write quorum/audit plane
```

The v1 read path is a single indexed lookup by `hash_id` or DID. The v1 write
path is one transaction that inserts or idempotently returns:

1. `identity_hashes`
2. `did_documents`
3. `registry_events`
4. `registration_receipts`
5. optional `bank_attestations`

Recommended low-resource targets for the pilot:

| Component | Pilot target |
| --- | --- |
| Backend memory | < 256 MB RSS per API worker under normal registry load |
| Registry write latency | p95 < 75 ms excluding bank network |
| Registry read latency | p95 < 20 ms local DB, < 75 ms remote API |
| Mirror lookup latency | p95 < 20 ms inside bank VPC/LAN |
| Registry CPU | Mostly idle at < 100 writes/sec on 2 vCPU |
| Storage | < 2 KB per identity hash before receipt/attestation growth |

The expensive parts of identity proofing remain outside Tovbase: bank KYC,
customer mapping, user key custody, and optional VC issuance.

## Design goals

- Store no raw PII, NIN, BVN, date of birth, address, phone number, email, or
  per-user salt in Tovbase.
- Store no user private keys in Tovbase. User signing keys remain in WebAuthn
  authenticators, passkeys, secure enclaves, hardware keys, or bank-controlled
  device flows.
- Make the registry useful if Tovbase disappears. Banks keep full registry
  mirrors and can continue lookup against their local nodes.
- Keep steady-state CPU and memory low enough to run on ordinary 1-2 vCPU
  instances and bank-operated commodity nodes.
- Keep the workflow ubiquitous: browser SDK, mobile SDK, server-to-server bank
  API, read mirror, and future offline receipt verification all use the same
  `hash_id`, DID, and receipt envelope.
- Keep the system compatible with the current repo: FastAPI routes under
  `/v1`, SQLAlchemy models in `app/models.py`, Pydantic schemas in
  `app/schemas.py`, and portable `JSON` columns for SQLite development
  compatibility.
- Preserve the project identity: deterministic math and cryptographic proofs,
  not learned weights, model inference, GPUs, or expensive managed consensus.

Non-goals for v1:

- Full server-side WebAuthn registration/assertion ceremony verification.
- JWT-VC issuance by Tovbase. Banks may issue credentials from their own
  systems after reading the registry.
- Public blockchain anchoring as a requirement for correctness.
- Write-capable bank mirrors or Raft consensus in the first phase.

## Ubiquitous workflow model

Every integration mode should share the same primitives and differ only in
transport.

| Workflow | Primary user | Transport | Required primitives |
| --- | --- | --- | --- |
| Bank mobile onboarding | Retail customer | Native SDK + HTTPS | WebAuthn/passkey, SDK hash, receipt |
| Browser onboarding | Web customer | Web SDK + HTTPS | WebAuthn/passkey, SDK hash, receipt |
| Bank batch migration | Bank ops | server-to-server HTTPS | precomputed hashes, receipt batch |
| Bank local verification | Bank risk engine | local mirror SQL/REST | DID lookup, receipt verification |
| Third-party verification | Merchant/fintech | public HTTPS | DID lookup, receipt verification |
| Offline audit | Regulator/bank audit | exported JSON | receipt payload, node public key, Merkle proof when available |

This keeps the system flexible without multiplying the trust model. The only
thing that changes across workflows is the adapter.

## Core architecture

### Roles

| Role | Responsibility | Stores raw PII? |
| --- | --- | --- |
| User device | Generates/uses WebAuthn credential, signs future challenges, runs SDK hashing flow | No long-term central copy |
| Bank app or SDK | Collects identity input, obtains per-user salt, computes registry hash locally | Temporarily in local trusted flow |
| Bank internal system | Maintains customer mapping and salt escrow under bank controls | Yes, bank-local only |
| Tovbase primary | Stores hash registry, DID document, WebAuthn public metadata, receipts, attestations | No |
| Bank mirror node | Subscribes to registry stream and serves local lookup | No |

### Registration flow

1. The user creates or selects a WebAuthn credential on mobile, browser,
   Windows Hello, hardware key, or a bank app backed by secure hardware.
2. The bank app or SDK collects the identity inputs required by the bank's KYC
   process. These inputs never leave the bank/SDK boundary as raw fields.
3. The SDK computes:

   ```text
   hash_id = SHA-256(canonical_identity_payload || per_user_salt || device_public_key_fingerprint)
   did = did:tov:<hash_id>
   ```

   `canonical_identity_payload` is a deterministic, bank-approved
   normalization of the required fields. The exact field order and
   normalization rules must be versioned by SDK release.
4. The SDK sends only `hash_id`, `did`, WebAuthn credential metadata, device
   public-key material, and bank metadata to Tovbase.
5. Tovbase stores the registry record and returns a signed receipt containing
   the hash, DID, timestamp, node id, and receipt signature.
6. Tovbase publishes the inserted record to bank mirrors through PostgreSQL
   logical replication in phase 1.
7. The bank checks its own mirror, then may issue a Verifiable Credential from
   its own infrastructure. The VC remains bank/user controlled and is not
   required for Tovbase registry lookup.

### Unified identity inputs

The registry can unify passport number, BVN, NIN, bank account evidence, phone,
email, or other bank-approved KYC fields into one cryptographic identity only
when those inputs are normalized and hashed before they reach Tovbase.

```text
canonical_identity_payload = canonicalize({
  passport_hash_component,
  bvn_hash_component,
  nin_hash_component,
  bank_customer_binding,
  device_public_key_fingerprint,
  schema_version
})

hash_id = SHA-256(canonical_identity_payload || per_user_salt)
did = did:tov:<hash_id>
```

Rules:

- Raw passport, BVN, NIN, names, birth dates, addresses, and salts remain
  bank-local or SDK-local.
- The bank controls which fields are required for its policy. Tovbase sees the
  resulting hash and public verification metadata, not the underlying KYC data.
- The field canonicalization schema is versioned. A bank can rotate from
  `kyc-ng-v1` to `kyc-ng-v2` without silently changing the meaning of existing
  hashes.
- Multiple bank attestations may point to the same `hash_id`, but no bank needs
  to expose its internal customer mapping.

The first canonicalization contract is `docs/KYC_CANONICALIZATION_V1.md`, with
machine-readable shape in `schemas/kyc_ng_v1.schema.json`.

### Lookup and proof flow

1. A relying party receives a DID, hash id, or signed user assertion.
2. The relying party resolves `did:tov:<hash_id>` against any available node:
   Tovbase primary or bank mirror.
3. The node returns the DID document, registration receipt, and current bank
   attestations.
4. The relying party verifies the receipt signature with the Tovbase registry
   node public key and verifies user assertions against the public key in the
   DID document.

Tovbase proves that a hash was registered at a time. It does not prove the
person's real-world identity by itself. Real-world binding remains with the
bank's internal KYC system and any bank-issued VC.

### Signed action and document flow

Tovbase ID should support bank-approved official actions such as signing a PDF,
approving a mandate, authorizing a transfer instruction, signing a media file,
or consenting to data sharing.

Important cryptographic wording: a bank does not "decode" a signature. It
verifies a signature against the registered public key and the bank-issued
handshake credential. If a document or media payload must remain confidential,
that payload is encrypted separately to a bank public key; the signature proves
authorship and intent.

Recommended action envelope:

```json
{
  "action_id": "act_...",
  "did": "did:tov:<hash_id>",
  "bank_id": "bank-a",
  "action_type": "document_signature",
  "document_hash": "64 lowercase hex chars",
  "media_hash": null,
  "challenge": "base64url random challenge",
  "requested_attestation": {
    "level": "aal2",
    "methods": ["passkey"],
    "max_age_seconds": 300
  },
  "issued_at": "2026-05-19T12:00:00Z",
  "expires_at": "2026-05-19T12:05:00Z",
  "nonce": "base64url nonce",
  "policy_version": "bank-a-actions-v1"
}
```

The user signs a canonical challenge that includes:

```text
SHA-256(canonical_json(action_envelope))
```

The signed result contains:

- WebAuthn/passkey assertion signature over the action challenge.
- Bank-issued handshake credential reference, such as `bank_credential_id`,
  `bank_key_id`, or a bank-issued VC identifier.
- Timestamp fields from the action envelope plus the authenticator/client
  assertion time recorded by the server.
- Optional liveness or step-up attestation result when policy requires it.

This supports the requested "two-key" model:

1. The user signs with their device/passkey private key.
2. The bank verifies that the signature is bound to a credential created during
   the initial bank handshake.
3. If the bank issued an additional credential or key reference at handshake,
   the signed action includes that reference so the bank can verify policy
   compliance at any later time.

Do not store a bank-issued user private key in Tovbase. If the bank gives the
user an additional credential, store only public metadata, a credential id, or a
signed bank attestation in the registry.

### Requested attestation policies

Banks should be able to request attestations by level and method.

| Level | Example methods | Expected use |
| --- | --- | --- |
| `instant` | passkey only | Low-risk login, low-risk document acknowledgement |
| `aal2` | passkey + bank handshake credential | Account changes, mandate approval, medium-risk official actions |
| `aal3` | passkey + camera liveness + bank credential | High-risk transfer approval, identity recovery, new device binding |
| `manual_review` | passkey + liveness + human review reference | Exceptional recovery or regulatory intervention |

Camera/liveness proof should be represented as an attestation result, not as
raw biometric media in Tovbase. The liveness provider or bank stores the raw
capture under its own compliance boundary and sends Tovbase only:

- `attestation_type`, for example `camera_liveness`.
- `attestation_result`, for example `passed`.
- `evidence_hash`, a digest of bank/provider-held evidence.
- `issued_at`, `expires_at`, `provider_id`, `key_id`, and provider signature.

This lets a bank require "camera-based attestation" while keeping biometric
payloads out of the Tovbase registry.

### Timestamping and speed targets

Digital signatures and receipts carry timestamps by design:

- `issued_at`: when the bank or Tovbase issued the challenge/receipt.
- `expires_at`: when the action challenge becomes invalid.
- `signed_at`: server-observed time when the signed assertion was received.
- `authenticator_sign_count` or equivalent authenticator metadata when
  available.
- `receipt.issued_at`: Tovbase receipt time.
- `registry_events.occurred_at`: append-only registry event time.

Performance target:

- Instant, no step-up attestation: under 3 seconds from challenge display to
  signed action submission on a normal device and network.
- Passkey + bank credential check: under 10 seconds for normal approval.
- Camera/liveness step-up: under 30 seconds end to end, assuming the liveness
  provider response is under 20 seconds.
- Backend verification only: p95 under 200 ms for action envelope verification,
  excluding human interaction and external liveness provider latency.

## Data model

Implementation should use SQLAlchemy models in `app/models.py` and portable
`JSON` column types, even where production PostgreSQL could render `JSONB`.
The SQL below is conceptual and uses portable shapes.

### `identity_hashes`

One row per registered identity hash.

```sql
CREATE TABLE identity_hashes (
    hash_id VARCHAR(64) PRIMARY KEY,
    did TEXT NOT NULL UNIQUE,
    hash_algorithm VARCHAR(32) NOT NULL DEFAULT 'sha256',
    hash_encoding VARCHAR(16) NOT NULL DEFAULT 'hex',
    sdk_version VARCHAR(32),
    device_pubkey_fingerprint VARCHAR(64) NOT NULL,
    webauthn_credential_id TEXT NOT NULL,
    webauthn_public_key JSON NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    metadata JSON
);
```

Rules:

- `hash_id` is normalized internally to lowercase SHA-256 hex, exactly 64
  characters. If base64url input is supported later, the API must decode and
  normalize before persistence.
- `webauthn_public_key` stores public material only, preferably COSE key data
  plus a stable JWK representation when available.
- `metadata` cannot contain raw PII, salts, bank customer IDs, or access tokens.

### `registry_events`

Append-only event envelope used by mirrors, audits, and the future L3 stream.

```sql
CREATE TABLE registry_events (
    event_id TEXT PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    aggregate_id TEXT NOT NULL,
    aggregate_type VARCHAR(32) NOT NULL,
    sequence_number INTEGER NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    payload JSON NOT NULL,
    payload_hash VARCHAR(64) NOT NULL,
    previous_event_hash VARCHAR(64),
    event_hash VARCHAR(64) NOT NULL UNIQUE
);
```

Rules:

- Every mutation of the registry emits exactly one event inside the same
  database transaction.
- `event_hash = SHA-256(canonical_json(payload) || previous_event_hash)`.
- The event table is the replication/audit spine. Read models can be rebuilt
  from it if later consensus or anchoring changes the serving layer.

### `did_documents`

Current DID document for each registry hash.

```sql
CREATE TABLE did_documents (
    did TEXT PRIMARY KEY,
    hash_id VARCHAR(64) NOT NULL REFERENCES identity_hashes(hash_id),
    document JSON NOT NULL,
    document_hash VARCHAR(64) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
```

The v1 DID method is:

```text
did:tov:<sha256-hex-hash-id>
```

Minimum DID document shape:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:tov:<hash_id>",
  "verificationMethod": [
    {
      "id": "did:tov:<hash_id>#webauthn-1",
      "type": "JsonWebKey2020",
      "controller": "did:tov:<hash_id>",
      "publicKeyJwk": {}
    }
  ],
  "authentication": ["did:tov:<hash_id>#webauthn-1"],
  "assertionMethod": ["did:tov:<hash_id>#webauthn-1"]
}
```

### `registration_receipts`

Append-only receipts signed by the active registry node key.

```sql
CREATE TABLE registration_receipts (
    receipt_id TEXT PRIMARY KEY,
    hash_id VARCHAR(64) NOT NULL REFERENCES identity_hashes(hash_id),
    did TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    node_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    payload JSON NOT NULL,
    payload_hash VARCHAR(64) NOT NULL,
    signature TEXT NOT NULL,
    signature_algorithm VARCHAR(32) NOT NULL
);
```

The receipt signing key is an infrastructure attestation key, not a user key.
It should live in KMS/HSM-backed storage in production. Compromise of this key
can forge registry receipts after compromise time, but it cannot sign as users
because user private keys never enter Tovbase.

### `bank_attestations`

Claims from bank nodes that a bank has recognized or verified a hash.

```sql
CREATE TABLE bank_attestations (
    attestation_id TEXT PRIMARY KEY,
    hash_id VARCHAR(64) NOT NULL REFERENCES identity_hashes(hash_id),
    bank_id TEXT NOT NULL,
    attestation_hash VARCHAR(64) NOT NULL,
    attestation_type VARCHAR(32) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    payload JSON NOT NULL,
    revoked_at TIMESTAMPTZ,
    UNIQUE (hash_id, bank_id, attestation_type)
);
```

Rules:

- `payload` must not contain customer IDs, PII, or salts.
- `attestation_hash` is a bank-signed digest of bank-local evidence.
- Revocation is represented by `revoked_at`, not hard deletion.

### `signed_actions`

Official user approvals over documents, media, mandates, or consent payloads.

```sql
CREATE TABLE signed_actions (
    action_id TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    hash_id VARCHAR(64) NOT NULL REFERENCES identity_hashes(hash_id),
    bank_id TEXT NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    document_hash VARCHAR(64),
    media_hash VARCHAR(64),
    challenge_hash VARCHAR(64) NOT NULL,
    requested_attestation JSON NOT NULL,
    bank_credential_id TEXT,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    signed_at TIMESTAMPTZ,
    signature TEXT,
    signature_algorithm VARCHAR(32),
    verification_result JSON,
    status VARCHAR(32) NOT NULL DEFAULT 'pending'
);
```

Rules:

- Tovbase stores document/media hashes, not document/media contents.
- `signed_at` is required before an action can become `approved`.
- The signature is over the canonical action envelope hash.
- The action can reference one or more `action_attestations`.

### `action_attestations`

Step-up attestation results for a signed action.

```sql
CREATE TABLE action_attestations (
    action_attestation_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES signed_actions(action_id),
    attestation_type VARCHAR(64) NOT NULL,
    provider_id TEXT NOT NULL,
    evidence_hash VARCHAR(64) NOT NULL,
    result VARCHAR(32) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    payload JSON NOT NULL
);
```

Rules:

- Store only evidence hashes and signed provider/bank results.
- Do not store raw face images, videos, identity documents, or media captures
  unless a bank chooses to do so in its own systems.

### `registry_anchors`

Optional integrity anchors for phase 3.

```sql
CREATE TABLE registry_anchors (
    anchor_id TEXT PRIMARY KEY,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    merkle_root VARCHAR(64) NOT NULL,
    hash_count INTEGER NOT NULL,
    anchor_network VARCHAR(32),
    anchor_txid TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
```

Anchoring is a verification aid, not the source of truth. The registry must
work without public-chain availability.

## API contracts

All endpoints live under the existing `/v1` prefix.

### `POST /v1/did/register`

Registers a precomputed identity hash.

Request:

```json
{
  "hash_id": "64 lowercase hex chars",
  "hash_algorithm": "sha256",
  "hash_encoding": "hex",
  "sdk_version": "tovbase-js/0.1.0",
  "webauthn_credential_id": "base64url credential id",
  "webauthn_public_key": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  },
  "device_pubkey_fingerprint": "64 lowercase hex chars",
  "bank_id": "bank-a",
  "bank_attestation": {
    "attestation_type": "kyc_hash_seen",
    "attestation_hash": "64 lowercase hex chars",
    "issued_at": "2026-05-19T12:00:00Z",
    "key_id": "bank-a-signing-2026-01",
    "signature": "base64url signature",
    "payload": {}
  }
}
```

Response:

```json
{
  "did": "did:tov:<hash_id>",
  "hash_id": "<hash_id>",
  "status": "registered",
  "registered_at": "2026-05-19T12:00:01Z",
  "receipt": {
    "receipt_id": "tgr_...",
    "payload_hash": "64 lowercase hex chars",
    "signature_algorithm": "ed25519",
    "key_id": "tovbase-registry-2026-01",
    "signature": "base64url signature"
  }
}
```

Behavior:

- Reject raw PII field names and unsupported fields at schema validation.
- Return idempotently for duplicate `hash_id` if the public key fingerprint and
  DID match the existing record.
- Return `409 Conflict` if `hash_id` already exists with conflicting WebAuthn
  metadata.

### `GET /v1/did/{did}`

Resolves a DID to its DID document, receipt summary, and active attestations.

Response:

```json
{
  "did": "did:tov:<hash_id>",
  "hash_id": "<hash_id>",
  "did_document": {},
  "registered_at": "2026-05-19T12:00:01Z",
  "status": "active",
  "receipt": {
    "receipt_id": "tgr_...",
    "payload_hash": "...",
    "key_id": "tovbase-registry-2026-01",
    "signature": "..."
  },
  "attestations": [
    {
      "bank_id": "bank-a",
      "attestation_type": "kyc_hash_seen",
      "issued_at": "2026-05-19T12:00:00Z",
      "expires_at": null,
      "revoked_at": null
    }
  ]
}
```

### `GET /v1/did/hash/{hash_id}`

Alias lookup for systems that have the hash but not the DID string.

Behavior is identical to `GET /v1/did/{did}` after deriving
`did:tov:<hash_id>`.

### `POST /v1/did/receipt/verify`

Verifies that a receipt payload and signature match a registry node key.

Request:

```json
{
  "receipt_id": "tgr_...",
  "payload": {},
  "signature": "base64url signature",
  "key_id": "tovbase-registry-2026-01"
}
```

Response:

```json
{
  "valid": true,
  "payload_hash": "64 lowercase hex chars",
  "verified_at": "2026-05-19T12:01:00Z"
}
```

### `GET /v1/did/keys/current`

Returns the active registry receipt-verification public key.

Response:

```json
{
  "node_id": "tovbase-primary-ng-1",
  "key_id": "tovbase-registry-2026-01",
  "signature_algorithm": "ed25519",
  "public_key_jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "base64url public key"
  }
}
```

Banks should cache the public key by `key_id` and keep old public keys for
receipt verification after rotation.

### `GET /v1/did/keys`

Returns active and verify-only registry receipt public keys. Verify-only keys
are used for old receipts after signing-key rotation.

### `POST /v1/did/attest`

Adds or updates a bank attestation for an existing hash.

Behavior:

- Requires bank authentication.
- Verifies the bank attestation signature against `TRUSTED_BANK_KEYS_JSON`.
- Rejects attestations for unknown hashes unless explicitly configured for
  queue-and-retry during mirror outage scenarios.
- Upserts by `(hash_id, bank_id, attestation_type)`.

### `POST /v1/did/attest/revoke`

Revokes an existing bank attestation. The revocation request is itself signed by
the bank key and records `revoked_at` without deleting the original attestation.

### `GET /v1/did/attest/{hash_id}/audit`

Exports all attestations for a hash, including revoked records, signatures,
verification status, payload metadata, and timestamps.

### `POST /v1/did/actions/challenge`

Creates a timestamped action challenge for signing a document, media object,
mandate, or consent envelope.

Request:

```json
{
  "did": "did:tov:<hash_id>",
  "bank_id": "bank-a",
  "action_type": "document_signature",
  "document_hash": "64 lowercase hex chars",
  "media_hash": null,
  "requested_attestation": {
    "level": "aal3",
    "methods": ["passkey", "bank_handshake", "camera_liveness"],
    "max_age_seconds": 300
  },
  "policy_version": "bank-a-actions-v1"
}
```

Response:

```json
{
  "action_id": "act_...",
  "challenge_hash": "64 lowercase hex chars",
  "issued_at": "2026-05-19T12:00:00Z",
  "expires_at": "2026-05-19T12:05:00Z",
  "canonical_envelope": {}
}
```

### `POST /v1/did/actions/submit`

Submits the user's passkey signature and optional step-up attestation results.

Request:

```json
{
  "action_id": "act_...",
  "bank_credential_id": "bankcred_...",
  "webauthn_assertion": {},
  "signature": "base64url signature",
  "signed_at": "2026-05-19T12:00:18Z",
  "attestations": [
    {
      "attestation_type": "camera_liveness",
      "provider_id": "bank-a-liveness",
      "evidence_hash": "64 lowercase hex chars",
      "result": "passed",
      "issued_at": "2026-05-19T12:00:16Z",
      "expires_at": "2026-05-19T12:05:16Z",
      "key_id": "bank-a-liveness-2026-01",
      "signature": "base64url signature",
      "payload": {}
    }
  ]
}
```

Response:

```json
{
  "action_id": "act_...",
  "status": "approved",
  "signed_at": "2026-05-19T12:00:18Z",
  "verification_result": {
    "signature_valid": true,
    "bank_credential_valid": true,
    "attestation_policy_satisfied": true
  }
}
```

### `GET /v1/did/actions/{action_id}`

Returns the action envelope, verification status, timestamps, and attestation
summaries. It must never return raw document/media contents or raw biometric
captures.

### `GET /v1/did/health`

Returns registry and mirror-readiness status.

Response:

```json
{
  "status": "ok",
  "database": true,
  "registry_tables": true,
  "node_id": "tovbase-primary-ng-1",
  "signing_key_id": "tovbase-registry-2026-01",
  "latest_receipt_at": "2026-05-19T12:00:01Z",
  "replication": {
    "publication": "did_registry_publication",
    "last_lsn": "0/16B6A50"
  }
}
```

## Mirror-node topology

### Phase 1: L2 read mirrors

- Tovbase primary writes to PostgreSQL.
- PostgreSQL logical replication publishes only DID registry tables:
  `identity_hashes`, `registry_events`, `did_documents`, `registration_receipts`,
  `bank_attestations`, `signed_actions`, `action_attestations`, and
  `registry_anchors`.
- `scripts/configure_publication.py` renders or applies the primary publication
  SQL.
- `scripts/render_subscription_sql.py` renders bank-side `CREATE SUBSCRIPTION`
  SQL with password placeholders.
- Each bank runs a read-only mirror node in its own environment.
- Bank systems query local mirrors for low-latency verification and operational
  continuity.
- If the primary is offline, mirrors continue serving reads. New registrations
  can queue in bank systems and sync later.

This phase is enough for the first banking pilot.

### Phase 2: L3 permissioned audit log

- Add a write/audit log across 3 or more trusted bank nodes using NATS
  JetStream. Prefer JetStream over etcd for the registry event plane because it
  provides a lightweight single-binary runtime, persistent streams, replayable
  consumers, and optimized Raft clustering.
- The log orders registration events and attestation updates.
- Conflict handling should remain boring:
  - Same `hash_id` and same DID/public-key fingerprint is idempotent.
  - Same `hash_id` and conflicting public-key fingerprint is a conflict.
  - Attestation updates are last-write-wins only for the same
    `(hash_id, bank_id, attestation_type)` tuple and must preserve prior receipt
    history.

### Phase 3: L4 integrity anchoring

- Periodically compute a Merkle root over new receipt payload hashes.
- Store root and proof window in `registry_anchors`.
- Optionally publish the root to Bitcoin, Ethereum, or another low-cost public
  anchor.
- Anchoring proves that a batch existed by a time. It is not required for
  day-to-day registry operation.

## Security guarantees

### What a registry breach exposes

An attacker who obtains the full Tovbase registry sees:

- identity hashes,
- DIDs,
- WebAuthn credential IDs,
- public keys,
- signed receipt payloads,
- bank attestation metadata.

They do not see:

- NIN,
- BVN,
- name,
- date of birth,
- address,
- bank customer ID,
- per-user salt,
- user private key,
- bank internal mapping table.

The registry alone is not enough to reverse identity, impersonate a user, or
link a person to a bank customer record.

### Blast-radius analysis

| Scenario | Result | Bank/customer risk |
| --- | --- | --- |
| Tovbase primary offline | Bank mirrors continue read lookup. New registrations queue and sync later. | No lookup outage for banks with mirrors |
| Tovbase company shuts down | Banks retain registry copies and can continue operating among themselves. | No forced data loss |
| Tovbase database breached | Attacker gets hashes and public metadata only. | No user impersonation, no raw PII |
| Tovbase receipt key compromised | Attacker may forge receipts after compromise time until key revocation. | Detectable by key rotation, anchor windows, and mirror logs |
| Bank internal system breached | Attacker may map that bank's hashes to its customers. | Limited to that bank's customer base |
| User device key compromised | Attacker may sign as that user until revocation/rekey. | Individual account risk, not registry-wide risk |
| Mirror node compromised | Attacker sees registry copy and may serve stale data locally. | Mitigate with signed receipts, replication monitoring, and mirror attestation |

## Repo implementation fit

The backend implementation follows the lightweight Tovbase conventions:

- Models live in `app/models.py`.
- Request/response schemas live in `app/schemas.py`.
- Routes live in `app/api/routes.py` under the `/v1` prefix.
- Config values live in `app/config.py`, including `did_node_id`,
  `did_signing_key_id`, receipt key paths or KMS identifiers, and accepted bank
  IDs.
- Tests sit in a dedicated `tests/test_registry.py`.
- The implementation must use SQLAlchemy `JSON`, not PostgreSQL-only `JSONB`,
  to preserve SQLite development compatibility.

Implementation-readiness note: this code is now isolated from the main Tovbase
trust-scoring backend, so graph/credential schema drift in that repo does not
block DID registry development.

## Future implementation acceptance criteria

- No DID endpoint accepts raw PII, salts, bank customer IDs, OAuth tokens, or
  user private keys.
- Registry hashes are fixed-length SHA-256 values: canonical lowercase hex
  internally, with any accepted base64url input decoded and normalized before
  persistence.
- `POST /v1/did/register` is idempotent for exact duplicate registrations.
- Conflicting duplicate registrations return `409 Conflict`.
- Every successful registration produces a signed, timestamped receipt.
- Receipt verification works independently from the database when given the
  payload, signature, and registry node public key.
- DID lookup works by both DID and hash id.
- Bank attestations are upserted, revocable, signed, and never contain raw PII.
- Passport, BVN, NIN, and other KYC inputs can be unified only through
  bank/SDK-local canonicalization and hashing; raw values never enter Tovbase.
- Signed action challenges include document/media hashes, issued/expiry
  timestamps, policy version, and nonce.
- Signed action submission verifies the user's passkey signature, bank
  handshake credential reference, timestamp validity, and requested attestation
  policy.
- Camera/liveness attestations store provider-signed result metadata and
  evidence hashes only, not raw biometric captures.
- UX/performance tests cover:
  - instant passkey-only action approval under 3 seconds on a warm path,
  - passkey plus bank credential approval under 10 seconds,
  - passkey plus camera liveness approval under 30 seconds when provider
    response is under 20 seconds.
- Unit tests cover:
  - successful registration,
  - duplicate registration,
  - conflicting duplicate registration,
  - invalid hash format,
  - DID lookup,
  - hash lookup,
  - receipt verification success,
  - receipt verification failure,
  - attestation add/update/revoke,
  - signed action challenge creation,
  - signed action submission,
  - action attestation policy enforcement,
  - rejection of forbidden PII-like fields.
- Integration tests should not require Qdrant, Redis, GPU, blockchain access,
  or live bank infrastructure.

## Rollout recommendation

Phase 1 should ship as a backend registry core plus one pilot-bank mirror:

- Add the five registry tables.
- Add the six `/v1/did/*` endpoints.
- Add deterministic receipt signing and verification.
- Add timestamped action challenge/signing endpoints for documents, media,
  mandates, and consent payloads.
- Configure PostgreSQL logical replication publication for registry tables.
- Provide one SDK hashing reference implementation for browser/mobile teams.

Phase 2 should add permissioned audit ordering only after at least two banks
need write continuity.

Phase 3 should add Merkle anchoring only after banks ask for external integrity
proofs. The registry should remain useful without it.
