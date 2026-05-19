from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.config import settings  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.services.event_plane import event_message, event_subject, registry_events, stream_config  # noqa: E402


async def publish_events(*, limit: int, dry_run: bool) -> dict[str, object]:
    with SessionLocal() as db:
        events = registry_events(db, limit=limit)
    messages = [
        {
            "subject": event_subject(event.event_type),
            "message": event_message(event),
        }
        for event in events
    ]
    if dry_run:
        return {"dry_run": True, "stream": stream_config(), "published": 0, "messages": messages}

    try:
        import nats
    except ImportError as exc:
        raise RuntimeError('Install the optional NATS extra first: pip install -e ".[nats]"') from exc

    nc = await nats.connect(settings.nats_url)
    js = nc.jetstream()
    await js.add_stream(**stream_config())
    published = 0
    for message in messages:
        await js.publish(message["subject"], json.dumps(message["message"], sort_keys=True).encode("utf-8"))
        published += 1
    await nc.drain()
    return {"dry_run": False, "stream": stream_config(), "published": published}


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish registry_events to optional NATS JetStream.")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(publish_events(limit=args.limit, dry_run=args.dry_run)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
