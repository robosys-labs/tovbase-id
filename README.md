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
  assets/
    tovbase-id-landing.png       # landing-page verification screenshot
web/
  app/
    page.tsx                     # id.tovbase.com landing page
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

## Status

This repository is in foundation mode. The architecture, PRD, and product page
are present. Backend registry implementation is tracked through GitHub
milestones and issues in this repository.
