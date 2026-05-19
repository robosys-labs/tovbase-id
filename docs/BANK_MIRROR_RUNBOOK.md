# Bank Mirror Runbook

This runbook describes Phase 1 read mirrors for Tovbase ID. The mirror is a
PostgreSQL subscriber that receives only registry tables. It stores hashes,
DID documents, receipts, attestations, signed action metadata, and anchors. It
does not receive raw PII, salts, customer IDs, private keys, documents, or
biometric media.

## Primary prerequisites

On the Tovbase primary PostgreSQL server:

```conf
wal_level = logical
max_replication_slots = 10
max_wal_senders = 10
```

Create a replication user with least privilege for the pilot bank:

```sql
CREATE ROLE repl_tovbase_id WITH LOGIN REPLICATION PASSWORD '<strong-password>';
GRANT USAGE ON SCHEMA public TO repl_tovbase_id;
GRANT SELECT ON TABLE
  identity_hashes,
  registry_events,
  did_documents,
  registration_receipts,
  bank_attestations,
  signed_actions,
  action_attestations,
  registry_anchors
TO repl_tovbase_id;
```

Restrict `pg_hba.conf` or cloud firewall rules to the bank mirror network.

## Configure the publication

Render the SQL for review:

```bash
pip install -e ".[postgres]"
python scripts/configure_publication.py --print-sql
```

Apply it on the primary:

```bash
DATABASE_URL=postgresql+psycopg://<admin>@<primary-host>:5432/tovbase_id \
python scripts/configure_publication.py
```

The publication is named `did_registry_publication` by default and includes:

- `identity_hashes`
- `registry_events`
- `did_documents`
- `registration_receipts`
- `bank_attestations`
- `signed_actions`
- `action_attestations`
- `registry_anchors`

The publication emits inserts and updates. The registry design uses revocation
timestamps and status fields instead of hard deletes.

## Configure the bank subscriber

Create the same schema on the bank mirror first:

```bash
DATABASE_URL=postgresql+psycopg://<bank-admin>@<mirror-host>:5432/tovbase_id \
python scripts/migrate.py
```

Render subscriber SQL:

```bash
python scripts/render_subscription_sql.py \
  --subscription bank_a_did_registry_sub \
  --slot-name bank_a_did_registry_slot \
  --publisher-host primary.tovbase.internal \
  --publisher-db tovbase_id \
  --publisher-user repl_tovbase_id
```

Run the generated `CREATE SUBSCRIPTION` statement on the bank mirror and replace
`<publisher_replication_password>` with the actual secret in the bank's secure
SQL session.

## Health checks

Primary health:

```text
GET /v1/did/health
```

On PostgreSQL, the `replication` object reports:

- `mode`: `primary` or `mirror`
- `publication`
- `publication_exists`
- `publication_tables`
- `missing_tables`
- `current_lsn`
- `replication_clients`

On a hot standby mirror, it reports replay metadata such as:

- `replay_lsn`
- `replay_lag_seconds`

For SQLite development, `mode` is `not_configured`.

## Failure behavior

- If the Tovbase API is offline, the bank mirror can still answer DID/hash
  lookups from local SQL or a bank-hosted resolver.
- If replication pauses, signed receipts still let the bank verify that older
  entries were issued by the registry key.
- If a mirror is suspected stale, compare receipt timestamps and replication
  lag before accepting high-risk actions.

## Operational checklist

- Confirm `GET /v1/did/health` shows no `missing_tables`.
- Confirm the subscriber is enabled.
- Confirm new registrations appear in the bank mirror.
- Cache registry public keys from `GET /v1/did/keys`.
- Alert when replay lag exceeds the bank's RPO target.
- Never create mirror-side writes to replicated tables in Phase 1.
