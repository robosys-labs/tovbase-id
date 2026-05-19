from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.config import settings
from app.schemas import BankAttestationInput, BankAttestationRevokeRequest
from app.services.crypto import canonical_json_bytes, json_safe, verify_detached_signature


@dataclass(frozen=True)
class TrustedBankKey:
    bank_id: str
    key_id: str
    signature_algorithm: str
    public_key_jwk: dict[str, Any]
    status: str = "active"


@dataclass(frozen=True)
class BankSignatureVerification:
    valid: bool
    error: str | None = None


def _load_trusted_bank_keys() -> list[TrustedBankKey]:
    if not settings.trusted_bank_keys_json:
        return []
    parsed = json.loads(settings.trusted_bank_keys_json)
    records = parsed.values() if isinstance(parsed, dict) else parsed
    return [
        TrustedBankKey(
            bank_id=str(record["bank_id"]),
            key_id=str(record["key_id"]),
            signature_algorithm=str(record.get("signature_algorithm", "ed25519")),
            public_key_jwk=dict(record["public_key_jwk"]),
            status=str(record.get("status", "active")),
        )
        for record in records
    ]


def trusted_bank_keys(bank_id: str | None = None) -> list[TrustedBankKey]:
    keys = _load_trusted_bank_keys()
    if bank_id is None:
        return keys
    return [key for key in keys if key.bank_id == bank_id]


def find_trusted_bank_key(bank_id: str, key_id: str) -> TrustedBankKey | None:
    for key in trusted_bank_keys(bank_id):
        if key.key_id == key_id:
            return key
    return None


def bank_attestation_envelope(
    *,
    hash_id: str,
    bank_id: str,
    attestation: BankAttestationInput,
) -> dict[str, Any]:
    return json_safe(
        {
            "purpose": "tovbase-id:bank-attestation:v1",
            "hash_id": hash_id,
            "bank_id": bank_id,
            "attestation_type": attestation.attestation_type,
            "attestation_hash": attestation.attestation_hash,
            "issued_at": attestation.issued_at,
            "expires_at": attestation.expires_at,
            "key_id": attestation.key_id,
            "payload": attestation.payload,
        }
    )


def bank_attestation_revocation_envelope(request: BankAttestationRevokeRequest) -> dict[str, Any]:
    return json_safe(
        {
            "purpose": "tovbase-id:bank-attestation-revocation:v1",
            "hash_id": request.hash_id,
            "bank_id": request.bank_id,
            "attestation_type": request.attestation_type,
            "revoked_at": request.revoked_at,
            "reason_code": request.reason_code,
            "key_id": request.key_id,
            "payload": request.payload,
        }
    )


def verify_bank_signed_envelope(
    *,
    bank_id: str,
    key_id: str,
    envelope: dict[str, Any],
    signature: str,
) -> BankSignatureVerification:
    trusted_key = find_trusted_bank_key(bank_id, key_id)
    if trusted_key is None:
        return BankSignatureVerification(False, "unknown_bank_key")
    if trusted_key.status != "active":
        return BankSignatureVerification(False, "bank_key_not_active")
    if trusted_key.signature_algorithm != "ed25519":
        return BankSignatureVerification(False, "unsupported_bank_key_algorithm")
    if not verify_detached_signature(trusted_key.public_key_jwk, canonical_json_bytes(envelope), signature):
        return BankSignatureVerification(False, "invalid_bank_signature")
    return BankSignatureVerification(True)


def verify_bank_attestation(
    *,
    hash_id: str,
    bank_id: str,
    attestation: BankAttestationInput,
) -> BankSignatureVerification:
    return verify_bank_signed_envelope(
        bank_id=bank_id,
        key_id=attestation.key_id,
        envelope=bank_attestation_envelope(hash_id=hash_id, bank_id=bank_id, attestation=attestation),
        signature=attestation.signature,
    )


def verify_bank_revocation(request: BankAttestationRevokeRequest) -> BankSignatureVerification:
    return verify_bank_signed_envelope(
        bank_id=request.bank_id,
        key_id=request.key_id,
        envelope=bank_attestation_revocation_envelope(request),
        signature=request.signature,
    )
