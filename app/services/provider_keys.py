from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.config import settings
from app.schemas import ActionAttestationInput
from app.services.crypto import canonical_json_bytes, json_safe, verify_detached_signature


@dataclass(frozen=True)
class TrustedProviderKey:
    provider_id: str
    key_id: str
    signature_algorithm: str
    public_key_jwk: dict[str, Any]
    status: str = "active"


@dataclass(frozen=True)
class ProviderSignatureVerification:
    valid: bool
    error: str | None = None


def _load_trusted_provider_keys() -> list[TrustedProviderKey]:
    if not settings.trusted_attestation_provider_keys_json:
        return []
    parsed = json.loads(settings.trusted_attestation_provider_keys_json)
    records = parsed.values() if isinstance(parsed, dict) else parsed
    return [
        TrustedProviderKey(
            provider_id=str(record["provider_id"]),
            key_id=str(record["key_id"]),
            signature_algorithm=str(record.get("signature_algorithm", "ed25519")),
            public_key_jwk=dict(record["public_key_jwk"]),
            status=str(record.get("status", "active")),
        )
        for record in records
    ]


def find_trusted_provider_key(provider_id: str, key_id: str) -> TrustedProviderKey | None:
    for key in _load_trusted_provider_keys():
        if key.provider_id == provider_id and key.key_id == key_id:
            return key
    return None


def action_attestation_envelope(
    *,
    action_id: str,
    did: str,
    hash_id: str,
    bank_id: str,
    attestation: ActionAttestationInput,
) -> dict[str, Any]:
    return json_safe(
        {
            "purpose": "tovbase-id:action-attestation:v1",
            "action_id": action_id,
            "did": did,
            "hash_id": hash_id,
            "bank_id": bank_id,
            "attestation_type": attestation.attestation_type,
            "provider_id": attestation.provider_id,
            "evidence_hash": attestation.evidence_hash,
            "result": attestation.result,
            "issued_at": attestation.issued_at,
            "expires_at": attestation.expires_at,
            "key_id": attestation.key_id,
            "payload": attestation.payload,
        }
    )


def verify_action_attestation(
    *,
    action_id: str,
    did: str,
    hash_id: str,
    bank_id: str,
    attestation: ActionAttestationInput,
) -> ProviderSignatureVerification:
    trusted_key = find_trusted_provider_key(attestation.provider_id, attestation.key_id)
    if trusted_key is None:
        return ProviderSignatureVerification(False, "unknown_provider_key")
    if trusted_key.status != "active":
        return ProviderSignatureVerification(False, "provider_key_not_active")
    if trusted_key.signature_algorithm != "ed25519":
        return ProviderSignatureVerification(False, "unsupported_provider_key_algorithm")

    envelope = action_attestation_envelope(
        action_id=action_id,
        did=did,
        hash_id=hash_id,
        bank_id=bank_id,
        attestation=attestation,
    )
    if not verify_detached_signature(trusted_key.public_key_jwk, canonical_json_bytes(envelope), attestation.signature):
        return ProviderSignatureVerification(False, "invalid_provider_signature")
    return ProviderSignatureVerification(True)
