from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.db import SessionLocal, init_db  # noqa: E402
from app.services.replication import configure_publication, publication_sql  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Configure PostgreSQL logical replication for Tovbase ID.")
    parser.add_argument("--publication", default=None, help="Publication name. Defaults to REGISTRY_PUBLICATION_NAME.")
    parser.add_argument("--print-sql", action="store_true", help="Print SQL without applying it.")
    args = parser.parse_args()

    statements = publication_sql(args.publication)
    if args.print_sql:
        print("\n\n".join(statements))
        return

    init_db()
    with SessionLocal() as db:
        result = configure_publication(db, args.publication)
    print(json.dumps(result, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
