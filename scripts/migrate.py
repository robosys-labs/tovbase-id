from __future__ import annotations

import json
import sys
from pathlib import Path

from sqlalchemy import inspect

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.db import engine, init_db  # noqa: E402


def migrate() -> dict[str, object]:
    init_db()
    inspector = inspect(engine)
    tables = sorted(inspector.get_table_names())
    return {
        "status": "ok",
        "database_url": engine.url.render_as_string(hide_password=True),
        "tables": tables,
    }


def main() -> None:
    print(json.dumps(migrate(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
