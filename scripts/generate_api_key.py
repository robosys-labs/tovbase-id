from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.api_keys import hash_api_key  # noqa: E402


def generate_api_key_record(
    *,
    key_id: str,
    bank_id: str | None = None,
    api_key: str | None = None,
) -> dict[str, object]:
    secret = api_key or f"tvbid_{secrets.token_urlsafe(32)}"
    record = {
        "key_id": key_id,
        "api_key_hash": hash_api_key(secret),
        "status": "active",
    }
    if bank_id is not None:
        record["bank_id"] = bank_id
    return {
        "api_key": secret,
        "record": record,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a hashed Tovbase ID API key config record.")
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--bank-id", help="Bank id for BANK_API_KEYS_JSON records.")
    parser.add_argument("--admin", action="store_true", help="Generate an ADMIN_API_KEYS_JSON record.")
    parser.add_argument("--api-key", help="Use an existing API key instead of generating a new one.")
    args = parser.parse_args()

    if args.admin and args.bank_id:
        parser.error("--admin and --bank-id are mutually exclusive")
    if not args.admin and not args.bank_id:
        parser.error("provide --bank-id for bank keys or --admin for admin keys")

    material = generate_api_key_record(
        key_id=args.key_id,
        bank_id=None if args.admin else args.bank_id,
        api_key=args.api_key,
    )
    env_name = "ADMIN_API_KEYS_JSON" if args.admin else "BANK_API_KEYS_JSON"
    output = {
        **material,
        "env_name": env_name,
        "env_value": json.dumps([material["record"]], separators=(",", ":")),
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
