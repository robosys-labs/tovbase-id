from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///./data/tovbase_id.db")

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.db import SessionLocal, init_db  # noqa: E402
from app.services.crypto import json_safe  # noqa: E402
from app.services.registry import audit_event_chain  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Tovbase ID registry event hash chains.")
    parser.add_argument("--aggregate-id", help="Optional aggregate id/hash/action id to audit.")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        audit = audit_event_chain(db, aggregate_id=args.aggregate_id)
    print(json.dumps(json_safe(audit.model_dump()), indent=2, sort_keys=True))
    if not audit.valid:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
