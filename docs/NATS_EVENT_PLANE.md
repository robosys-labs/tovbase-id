# Optional NATS JetStream Event Plane

The NATS event plane is optional P2 infrastructure. Tovbase ID does not require
NATS for registration, lookup, receipt verification, mirror reads, or signed
actions.

The purpose of the prototype is to make the existing `registry_events` table
replayable through a lightweight append stream when a bank consortium needs a
shared event plane.

## Install

```bash
pip install -e ".[nats]"
```

## Configuration

```env
NATS_URL=nats://127.0.0.1:4222
NATS_STREAM_NAME=TOVBASE_ID_REGISTRY
NATS_SUBJECT_PREFIX=tovbase.id.registry
```

Stream config:

```json
{
  "name": "TOVBASE_ID_REGISTRY",
  "subjects": ["tovbase.id.registry.>"],
  "retention": "limits",
  "storage": "file",
  "discard": "old"
}
```

Subject format:

```text
tovbase.id.registry.<event-type>
```

Example:

```text
tovbase.id.registry.identity-registered
```

## Dry run

```bash
python scripts/publish_events_to_nats.py --dry-run --limit 10
```

Dry run prints stream configuration and serialized event messages without
connecting to NATS.

## Publish

```bash
python scripts/publish_events_to_nats.py --limit 1000
```

The script reads from `registry_events`, serializes JSON-safe envelopes, creates
or updates the JetStream stream, and publishes each event to its event-type
subject.

This is intentionally out-of-band. The registry write path remains a normal
database transaction, and PostgreSQL logical replication remains the Phase 1
mirror mechanism.
