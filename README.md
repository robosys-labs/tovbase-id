# Tovbase ID

Bank-grade DID and federated hash registry for institutions that need portable
identity verification without a central PII honeypot.

Tovbase ID is the identity infrastructure split from the main Tovbase trust
scoring codebase. It is designed around:

- SDK-side hashing of bank-approved identity inputs such as passport, BVN, NIN,
  and device public key fingerprints.
- User-held WebAuthn/passkey signing keys.
- `did:tov:<hash_id>` decentralized identifiers.
- Signed, timestamped registration receipts.
- Bank attestations and optional step-up action attestations.
- PostgreSQL logical replication to bank-operated read mirrors.
- Optional NATS JetStream event-plane work only after multiple banks need L3
  write continuity.

## Current contents

```text
docs/
  DID_REGISTRY_ARCHITECTURE.md   # technical architecture
  DID_REGISTRY_MASTERPLAN_PRD.md # roadmap and product requirements
  BANK_INTEGRATION_GUIDE.md      # pilot-bank integration guide
  BANK_MIRROR_RUNBOOK.md         # PostgreSQL read-mirror setup
  BANK_ATTESTATION_WORKFLOW.md   # signed bank attestation and revocation flow
  ACTION_ATTESTATION_PROVIDER_WORKFLOW.md # camera/liveness provider signature flow
  KYC_CANONICALIZATION_V1.md     # local KYC hashing rules
  assets/
    tovbase-id-landing.png       # landing-page verification screenshot
sdk/
  browser/                       # dependency-free browser hashing reference
schemas/
  batch_registration.schema.json # server-to-server batch migration format
  kyc_ng_v1.schema.json          # local canonical identity payload schema
examples/
  batch_registration.json        # sample batch payload
web/
  app/
    page.tsx                     # id.tovbase.com landing page
app/
  api/routes.py                  # FastAPI routes under /v1/did
  models.py                      # SQLAlchemy registry tables
  schemas.py                     # Pydantic request/response contracts
  services/                      # crypto and registry workflows
tests/
  test_registry.py               # registry-core acceptance tests
```

## Product surface

The dedicated product domain is:

```text
https://id.tovbase.com
```

For local landing-page development:

```bash
cd web
pnpm install
pnpm dev
```

For local backend development:

```bash
cp .env.example .env
pip install -e ".[dev]"
python scripts/generate_signing_key.py --node-id tovbase-id-dev-1 --key-id tovbase-registry-dev-1
python scripts/generate_bank_key.py --bank-id bank-a --key-id bank-a-signing-1
python scripts/generate_provider_key.py --provider-id bank-a-liveness --key-id bank-a-liveness-1
python scripts/migrate.py
python scripts/configure_publication.py --print-sql
uvicorn app.main:app --reload --port 8001
python -m pytest tests -q
node sdk/browser/test-sdk.mjs
```

For PostgreSQL mirror/publication work, install the optional driver:

```bash
pip install -e ".[dev,postgres]"
```

## Implemented registry surface

- `POST /v1/did/register`
- `GET /v1/did/{did}`
- `GET /v1/did/hash/{hash_id}`
- `POST /v1/did/receipt/verify`
- `GET /v1/did/keys/current`
- `GET /v1/did/keys`
- `POST /v1/did/attest`
- `POST /v1/did/attest/revoke`
- `GET /v1/did/attest/{hash_id}/audit`
- `POST /v1/did/actions/challenge`
- `POST /v1/did/actions/submit`
- `GET /v1/did/actions/{action_id}`
- `GET /v1/did/health`

## Status

This repository has moved from foundation into Milestone 1 implementation. The
first registry-core backend is present with portable SQLite/PostgreSQL models,
strict no-PII request validation, deterministic DID derivation, signed
registration receipts, bank attestations, and signed document/media action
workflows.
