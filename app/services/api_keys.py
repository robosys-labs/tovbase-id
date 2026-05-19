from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from json import JSONDecodeError

from app.config import settings


@dataclass(frozen=True)
class BankPrincipal:
    bank_id: str
    key_id: str


@dataclass(frozen=True)
class AdminPrincipal:
    key_id: str


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _records(value: str) -> list[dict]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (JSONDecodeError, TypeError):
        return []
    if isinstance(parsed, dict):
        return [record for record in parsed.values() if isinstance(record, dict)]
    if isinstance(parsed, list):
        return [record for record in parsed if isinstance(record, dict)]
    return []


def authenticate_bank_api_key(*, bank_id: str | None, api_key: str | None) -> BankPrincipal | None:
    if not bank_id or not api_key:
        return None
    candidate_hash = hash_api_key(api_key)
    for record in _records(settings.bank_api_keys_json):
        if record.get("status", "active") != "active":
            continue
        if record.get("bank_id") != bank_id:
            continue
        if hmac.compare_digest(str(record.get("api_key_hash", "")), candidate_hash):
            return BankPrincipal(bank_id=bank_id, key_id=str(record.get("key_id", "")))
    return None


def authenticate_admin_api_key(*, api_key: str | None) -> AdminPrincipal | None:
    if not api_key:
        return None
    candidate_hash = hash_api_key(api_key)
    for record in _records(settings.admin_api_keys_json):
        if record.get("status", "active") != "active":
            continue
        if hmac.compare_digest(str(record.get("api_key_hash", "")), candidate_hash):
            return AdminPrincipal(key_id=str(record.get("key_id", "")))
    return None
