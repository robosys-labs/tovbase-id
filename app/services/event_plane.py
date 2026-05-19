from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import RegistryEvent
from app.services.crypto import json_safe


def event_subject(event_type: str, *, prefix: str | None = None) -> str:
    prefix = (prefix or settings.nats_subject_prefix).strip(".")
    safe_event_type = event_type.replace("_", "-").lower()
    return f"{prefix}.{safe_event_type}"


def event_message(event: RegistryEvent) -> dict[str, Any]:
    return json_safe(
        {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "aggregate_id": event.aggregate_id,
            "aggregate_type": event.aggregate_type,
            "sequence_number": event.sequence_number,
            "occurred_at": event.occurred_at,
            "payload": event.payload,
            "payload_hash": event.payload_hash,
            "previous_event_hash": event.previous_event_hash,
            "event_hash": event.event_hash,
        }
    )


def stream_config() -> dict[str, Any]:
    return {
        "name": settings.nats_stream_name,
        "subjects": [f"{settings.nats_subject_prefix}.>"],
        "retention": "limits",
        "storage": "file",
        "discard": "old",
    }


def registry_events(db: Session, *, after_sequence: int = 0, limit: int = 1000) -> list[RegistryEvent]:
    return list(
        db.execute(
            select(RegistryEvent)
            .where(RegistryEvent.sequence_number > after_sequence)
            .order_by(RegistryEvent.occurred_at, RegistryEvent.sequence_number)
            .limit(limit)
        )
        .scalars()
        .all()
    )
