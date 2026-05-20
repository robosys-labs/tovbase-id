# Tovbase ID Masterplan and PRD

## Product summary

Tovbase ID is a bank-grade identity hash registry for institutions that need
portable identity verification without a central PII honeypot. It gives banks,
fintechs, marketplaces, and relying parties a fast way to register, resolve,
mirror, and audit decentralized identifiers backed by user-held passkeys and
bank attestations.

Dedicated product surface: `https://id.tovbase.com`

Core promise:

```text
Register once. Mirror everywhere. Prove without exposing PII.
```

The product is not a replacement for bank KYC. It is a cryptographic registry
and availability layer that lets banks prove a user-controlled identifier was
registered and attested without Tovbase storing the underlying identity data.

## Research basis

- W3C DID Core defines DIDs as identifiers that resolve to DID documents and
  can express cryptographic verification methods and services:
  <https://www.w3.org/TR/did/>
- W3C WebAuthn Level 3 defines public key credentials and passkey-style
  discoverable credentials:
  <https://www.w3.org/TR/webauthn-3/>
- FIDO describes passkeys as cryptographic credentials that use device unlock
  flows such as biometrics, PIN, or pattern:
  <https://fidoalliance.org/passkeys/>
- PostgreSQL logical replication provides transactional table replication from
  publisher to subscriber:
  <https://www.postgresql.org/docs/16/logical-replication.html>
- NATS is a lightweight, high-performance single-binary messaging system, and
  JetStream adds optimized Raft clustering for persistent streams:
  <https://nats.io/about/> and
  <https://docs.nats.io/running-a-nats-service/configuration/clustering/jetstream_clustering>
- gRPC/protobuf is useful for strongly typed high-throughput bank/mirror
  integrations, but should remain optional in v1:
  <https://grpc.io/docs/what-is-grpc/introduction/>
- Cloudflare/edge custom domains can serve the dedicated `id.tovbase.com`
  product surface with low operational overhead:
  <https://developers.cloudflare.com/workers/configuration/routing/custom-domains/>

## Goals and non-goals

### Goals

- Launch a docs-backed product narrative for bank partners.
- Ship a minimal registry core with deterministic hash registration, DID
  resolution, receipt signing, and bank attestations.
- Support a single cryptographic identity derived from bank-approved KYC inputs
  such as passport, BVN, NIN, and other data, while keeping raw values and salts
  outside Tovbase.
- Current status: `kyc-ng-v1` is documented with browser SDK normalization and
  a local canonical payload JSON schema.
- Support official user actions where a user signs a document/media hash,
  mandate, or consent envelope with their passkey and a bank-issued handshake
  credential reference.
- Let banks request attestation policies by level and method, including
  camera/liveness step-up without Tovbase storing raw biometric captures.
- Keep runtime cost low: ordinary CPU, ordinary PostgreSQL, no GPU, no
  mandatory blockchain, no heavyweight consensus before multiple banks need it.
- Support ubiquitous workflows across browser SDK, mobile SDK, bank
  server-to-server API, mirror lookup, and offline audit exports.
- Make the registry survivable: bank mirrors continue serving reads if the
  Tovbase primary is offline.
- Give investors and bank risk teams a crisp answer to "what happens if
  Tovbase disappears?"

### Non-goals for v1

- Tovbase does not store raw PII, salts, bank customer IDs, or user private
  keys.
- Tovbase does not become a credential issuer for the bank in v1.
- Tovbase does not run a public blockchain or require public-chain anchoring.
- Tovbase does not require a new Rust/Go microservice until profiling proves
  Python/FastAPI is the bottleneck.
- Current runtime strategy: Python/FastAPI is the pilot/reference
  implementation; Go is the preferred production-core migration candidate if
  measured CPU, memory, packaging, or bank-node distribution gates justify it.
- Tovbase does not perform full WebAuthn ceremony verification in the first
  registry-core release.

## Personas

| Persona | Need | Success signal |
| --- | --- | --- |
| Bank CTO | Lightweight, explainable infrastructure with a clear failure model | Can run a local mirror and verify receipts without trusting Tovbase uptime |
| Bank CISO | No PII honeypot and no central private keys | Breach analysis shows no user impersonation from registry data alone |
| Bank product lead | Fast onboarding and familiar user approval | Customer registers with passkey/biometric/PIN flow inside existing bank app |
| Fintech/relying party | Fast DID lookup and proof verification | Lookup returns DID document, receipt, and active attestations in milliseconds |
| Regulator/auditor | Exportable, immutable evidence | Can verify receipt signatures and event hashes offline |
| Investor | Resilience, scalability, and cost discipline | Architecture works if Tovbase primary fails and stays inside low-cost infra envelope |

## Product requirements

### P0: Registry core

- Accept only pre-hashed identity registrations from SDKs or bank systems.
- Allow bank-defined canonicalization schemas that combine passport, BVN, NIN,
  device public key, and other approved fields into one hash without sending
  raw values to Tovbase.
- Derive `did:tov:<hash_id>` deterministically.
- Persist identity hash, DID document, WebAuthn credential metadata, registry
  event, registration receipt, and optional bank attestation in one transaction.
- Sign every registration receipt with an active registry node key.
- Resolve by DID or by hash id.
- Verify receipt payloads and signatures.
- Reject raw PII-like fields at schema validation.
- Treat duplicate identical registration as idempotent.
- Treat duplicate conflicting registration as `409 Conflict`.

### P0: Signed official actions

- Create timestamped action challenges for documents, media, mandates, and
  consent payloads.
- Sign only hashes/envelopes, not raw document or media contents.
- Include `issued_at`, `expires_at`, nonce, policy version, action type, and
  document/media hashes in every challenge.
- Verify submitted passkey assertions against the DID public key.
- Verify the bank-issued handshake credential reference or bank attestation
  expected for the user.
- Persist `signed_at` and verification result for every approved action.
- Complete passkey-only action approval in under 3 seconds on a warm path.

### P0: Timestamp policy

- Registration receipts, registry events, action challenges, action
  submissions, and attestation results all carry explicit timestamps.
- Challenges expire by default in 5 minutes or less.
- Server-observed receipt/action timestamps are authoritative for audit.

### P0: Mirror readiness

- Publish only DID registry tables through PostgreSQL logical replication.
- Keep the schema portable enough for SQLite-backed unit tests.
- Provide a mirror setup guide for a bank read replica.
- Expose `/v1/did/health` with node id, key id, registry table status, and
  replication/runtime metadata when available.
- Current status: publication/subscription SQL tooling, health metadata, and
  `docs/BANK_MIRROR_RUNBOOK.md` are present for pilot review.

### P0: Product surface

- Add `id.tovbase.com` as the dedicated Tovbase ID landing experience.
- Present the product as infrastructure, not a consumer social profile page.
- Explain the privacy boundary, mirror-node continuity, and bank-grade failure
  model above the fold.
- Include partner CTAs: pilot bank, technical spec, and API waitlist.

### P1: SDK hashing reference

- Browser reference implementation:
  - canonicalize fields locally,
  - receive/generate salt outside Tovbase,
  - derive SHA-256 hash,
  - create/attach WebAuthn credential metadata,
  - submit only hash/public metadata.
- Mobile SDK spec:
  - same payload shape as browser,
  - native passkey hooks,
  - bank app salt custody.
- Server-to-server batch format for migration of existing bank customers.
- Current status: dependency-free browser reference, batch JSON schema, and
  bank-authenticated batch registration endpoint are present for pilot review.

### P1: Bank attestation workflow

- Add bank registry and public-key configuration.
- Verify bank attestation signatures.
- Support attestation revocation.
- Provide audit export for all attestations on a hash.
- Current status: signed bank attestation verification, signed revocation, and
  audit export endpoints are implemented.
- Current status: action-level provider signatures are verified for
  `camera_liveness` and manual-review attestations.
- Support requested attestation policies:
  - `instant`: passkey only.
  - `aal2`: passkey plus bank handshake credential.
  - `aal3`: passkey plus bank handshake credential plus camera/liveness.
  - `manual_review`: step-up evidence plus human review reference.
- Store only liveness result metadata and evidence hashes, never raw face video
  or image captures in Tovbase.

### P1: Performance and operations

- Add microbenchmarks for register, resolve, receipt verify, and attestation
  upsert.
- Target p95 registry read under 20 ms against local DB.
- Target p95 write under 75 ms excluding bank network.
- Target signed action backend verification under 200 ms excluding user
  interaction and external liveness provider latency.
- Target passkey plus camera/liveness action completion under 30 seconds when
  the provider responds in under 20 seconds.
- Target steady API worker memory under 256 MB for registry-only traffic.
- Expose runtime RSS in health so Python memory cost is visible during pilots.
- Add structured logs without PII.
- Current status: PII-safe structured access logs are implemented with
  route-template paths, request ids, status codes, and durations only.
- Current status: `scripts/benchmark_registry_core.py` measures register,
  resolve, receipt verification, and attestation upsert paths against local
  pilot targets.
- Current status: `scripts/benchmark_action_flow.py` proves the local backend
  path for instant and camera/liveness signed actions is below the timing
  targets.

### P2: L3 event plane

- Add optional NATS JetStream append stream for registry events.
- Run a 3-node bank consortium simulation.
- Make PostgreSQL read models rebuildable from `registry_events`.
- Document conflict semantics and node recovery.
- Current status: optional out-of-band JetStream serialization and publisher
  prototype is implemented for `registry_events`.

### P3: Anchoring

- Batch event hashes into Merkle roots.
- Store root windows in `registry_anchors`.
- Provide optional public-chain anchoring adapter only when partner demand
  justifies it.
- Current status: internal Merkle anchor windows and receipt inclusion proofs
  are implemented. External-chain publication remains optional future work.

## System architecture

### Runtime shape

```text
id.tovbase.com
  - static/Next landing page
  - API docs and partner CTA

FastAPI backend /v1/did/*
  - Pydantic validation
  - hash normalization
  - DID derivation
  - receipt signing
  - bank attestation ingestion

PostgreSQL
  - identity_hashes
  - registry_events
  - did_documents
  - registration_receipts
  - bank_attestations
  - signed_actions
  - action_attestations
  - registry_anchors

Bank mirror
  - logical replication subscriber
  - local read API or direct SQL lookup

Optional L3
  - NATS JetStream event stream
  - 3+ bank quorum
```

### Data principles

- Canonical hash format is lowercase SHA-256 hex.
- Passport, BVN, NIN, and other bank-required identifiers are unified by
  bank/SDK-local canonicalization and hashing, not by storing raw fields.
- Every mutation has an append-only registry event.
- Every receipt is independently verifiable from canonical payload and
  registry public key.
- Registry event hash chains are verifiable through an admin API and CLI.
- DID documents contain only public verification material and service metadata.
- Bank-local customer mapping remains outside Tovbase.
- Official actions are signed over canonical envelopes that include payload
  hashes, timestamp windows, nonce, bank policy, and requested attestation
  method.

### Security controls

- API schema denies common raw PII keys such as `nin`, `bvn`, `dob`, `name`,
  `address`, `phone`, `email`, and `customer_id`.
- Registry signing key is separate from user keys and should be KMS/HSM-backed
  in production.
- Bank attestations require bank authentication and signature verification.
- Bank write endpoints require `X-Tovbase-Bank-Id` plus
  `X-Tovbase-Api-Key`; operator-only audit/anchor endpoints require
  `X-Tovbase-Admin-Key`.
- Signatures are verified, not decoded. If the bank needs confidential
  document/media content, that content is encrypted separately to the bank while
  Tovbase stores only content hashes and approval metadata.
- Camera/liveness proofs are provider-signed attestation results with evidence
  hashes; biometric media stays with the bank or liveness provider.
- Access logs use route templates, request ids, status codes, and durations
  only. They do not include request bodies, query strings, API keys, raw hashes,
  DIDs, client IPs, or bank customer metadata.
- Receipt and event hash chains make tampering detectable.
- Current status: admin event-chain audit and CLI verification are implemented
  for sequence, previous-hash, payload-hash, and event-hash checks.

## Landing page PRD: `id.tovbase.com`

### Audience

Bank executives, bank security teams, fintech infrastructure partners, and
investors.

### Message hierarchy

1. Headline: bank-grade identity without a central PII honeypot.
2. Proof: SDK hashes locally, user keys stay in passkeys, banks run mirrors.
3. Resilience: Tovbase primary can fail without breaking bank lookup.
4. Efficiency: PostgreSQL first, NATS only when quorum writes are needed, no
   blockchain in the hot path.
5. CTA: pilot the registry or read the technical spec.

### Required sections

- Hero with an infrastructure visual, not a generic marketing illustration.
- Three proof points: no PII, no central private keys, bank mirrors.
- Workflow band: Register, Mirror, Resolve, Attest.
- Architecture band: SDK, DID API, Postgres, mirror nodes, optional JetStream.
- Security model: what an attacker gets and what they cannot do.
- Pilot CTA: "Start a bank pilot" and "Read the architecture".

### UX constraints

- First screen must show the actual product concept immediately.
- Keep the visual style quiet, bank-grade, and operational.
- Avoid decorative blobs, vague gradients, and card-in-card layouts.
- Must fit desktop and mobile without text overlap.

## Delivery plan

### Milestone 0: Foundation and partner narrative

- Finalize architecture research and PRD.
- Launch `id.tovbase.com` landing page.
- Prepare GitHub milestones/issues.
- Keep DID implementation isolated in this standalone repo so trust-scoring
  backend schema drift cannot block registry delivery.

Exit criteria:

- Partner can read the architecture and understand failure modes.
- Landing page exists and routes correctly from `id.tovbase.com`.
- GitHub backlog is actionable.
- Complete for the current standalone repo baseline.

### Milestone 1: Registry core

- Add SQLAlchemy models and Pydantic schemas.
- Add idempotent `/v1/did/register`.
- Add DID/hash lookup endpoints.
- Add deterministic DID document generation.
- Add receipt signing and verification.
- Add timestamped action challenge and signed action submission endpoints.
- Add unit tests for all P0 cases.

Exit criteria:

- Local test suite passes for DID registry.
- API never accepts raw PII fields.
- Registration and lookup work without Redis, Qdrant, NATS, or blockchain.
- Passkey-only document/media signing path works against hashes and completes
  without liveness step-up.
- Current status: initial M1 slice implemented with 11 registry-core tests.
- Current status update: receipt key generation, public-key discovery, and
  verify-only rotated key support are implemented.

### Milestone 2: Bank mirror pilot

- Add registry publication setup script/docs.
- Add mirror health reporting.
- Add bank mirror runbook.
- Add load/performance benchmark script.
- Validate a local primary/subscriber topology with Docker/PostgreSQL.

Exit criteria:

- A bank can run a read mirror from published instructions.
- Mirror lookup stays live when Tovbase API is stopped.

### Milestone 3: SDK and attestations

- Add browser SDK reference.
- Add server-to-server batch registration format.
- Add bank public-key registry.
- Verify and persist bank attestations.
- Add requested attestation policy flow, including camera/liveness result
  metadata.
- Add revocation and audit export.

Exit criteria:

- A bank pilot can register a user through SDK hashing and attach a signed
  attestation.
- A bank can migrate precomputed existing-customer hashes through the
  bank-authenticated batch registration endpoint with per-entry retry results.
- A bank can request an `aal3` camera/liveness attestation for a high-risk
  signed action and receive a provider-signed result hash.
- Audit export verifies without database trust.

### Milestone 4: L3 quorum and anchoring

- Add optional JetStream registry event publisher.
- Run 3-bank quorum simulation.
- Add replay/rebuild tooling from registry events.
- Add Merkle root anchoring table and proof generation.

Exit criteria:

- Registry events replay into a clean read model.
- Quorum simulation documents conflict handling and recovery.

## Metrics

| Metric | Target |
| --- | --- |
| DID register p95 | < 75 ms excluding bank network |
| DID resolve p95 | < 20 ms local DB |
| Receipt verify p95 | < 5 ms in-process |
| Signed action backend verification p95 | < 200 ms excluding external providers |
| Passkey-only signed action UX | < 3 seconds on warm path |
| Passkey + bank credential UX | < 10 seconds on normal approval |
| Passkey + camera liveness UX | < 30 seconds when provider responds under 20 seconds |
| API memory | < 256 MB RSS per worker for registry traffic |
| Duplicate register behavior | 100% idempotent for exact duplicates |
| PII field rejection | 100% for blocked raw PII field names |
| Mirror RPO | seconds under healthy replication |
| Mirror read availability | continues during primary API outage |

## Open decisions

- Receipt signing algorithm: Ed25519 is preferred for small signatures and fast
  verification, but final choice depends on available Python dependency and
  bank HSM/KMS support.
- DID document key representation: JWK is easiest for bank interoperability;
  COSE-first may align better with WebAuthn. v1 can store both public forms.
- Mirror API shape: banks can query local SQL directly or run a tiny local REST
  resolver. Pilot bank preference should decide.
- Bank handshake credential shape: bank-issued VC, key reference, or signed
  attestation record. The pilot bank should choose based on its existing app
  security model.
- Liveness provider boundary: bank-hosted or third-party provider. Tovbase
  should receive only signed result metadata and evidence hash either way.
- Cloudflare vs existing web hosting for `id.tovbase.com`: route can work in
  the current Next app; edge deployment is optional.

## Risks

- Regulatory risk: "hashes are not PII" is not universally accepted. Treat the
  registry as sensitive pseudonymous data and keep NDPR/GDPR controls.
- Device recovery risk: passkeys can be synced or device-bound. Banks need a
  rekey/recovery process outside Tovbase.
- Biometric/privacy risk: camera liveness captures are highly sensitive and
  must stay outside Tovbase under bank/provider retention controls.
- Non-repudiation risk: action envelopes must include clear human-readable
  intent, timestamps, and policy version so users know exactly what they are
  approving.
- Schema drift risk: current graph/credential tests reference missing models.
  Fix before backend DID work to avoid fragile migrations.
- Partner integration risk: bank KYC systems differ. Keep SDK hashing rules
  versioned and bank-configurable.
- Overbuilding risk: Raft and public anchoring are easy to sell and expensive
  to operate early. Keep them optional until multiple banks require them.
