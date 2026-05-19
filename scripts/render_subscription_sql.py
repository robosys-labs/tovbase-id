from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.replication import subscription_sql  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Render bank mirror CREATE SUBSCRIPTION SQL.")
    parser.add_argument("--subscription", required=True, help="Local subscription name, e.g. bank_a_did_registry_sub.")
    parser.add_argument("--publication", default=None, help="Primary publication name.")
    parser.add_argument("--publisher-host", required=True)
    parser.add_argument("--publisher-port", type=int, default=5432)
    parser.add_argument("--publisher-db", required=True)
    parser.add_argument("--publisher-user", required=True)
    parser.add_argument("--slot-name", default=None)
    parser.add_argument("--sslmode", default="require")
    args = parser.parse_args()
    print(
        subscription_sql(
            subscription_name=args.subscription,
            publication_name=args.publication,
            publisher_host=args.publisher_host,
            publisher_port=args.publisher_port,
            publisher_db=args.publisher_db,
            publisher_user=args.publisher_user,
            slot_name=args.slot_name,
            sslmode=args.sslmode,
        )
    )


if __name__ == "__main__":
    main()
