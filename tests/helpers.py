import base64
import json
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.schemas import BankAttestationInput, BankAttestationRevokeRequest
from app.services.bank_keys import bank_attestation_envelope, bank_attestation_revocation_envelope
from app.services.crypto import canonical_json_bytes

BANK_PRIVATE_KEY = ed25519.Ed25519PrivateKey.generate()
BANK_PUBLIC_BYTES = BANK_PRIVATE_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
BANK_PUBLIC_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": base64.urlsafe_b64encode(BANK_PUBLIC_BYTES).rstrip(b"=").decode("ascii"),
}
BANK_ID = "bank-a"
BANK_KEY_ID = "bank-a-signing-1"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def trusted_bank_keys_json() -> str:
    return json.dumps(
        [
            {
                "bank_id": BANK_ID,
                "key_id": BANK_KEY_ID,
                "signature_algorithm": "ed25519",
                "public_key_jwk": BANK_PUBLIC_JWK,
                "status": "active",
            }
        ]
    )


def sign_bank_attestation_payload(
    *,
    hash_id: str,
    bank_id: str = BANK_ID,
    attestation_type: str = "kyc_hash_seen",
    attestation_hash: str,
    issued_at: datetime | None = None,
    payload: dict | None = None,
) -> dict:
    issued_at = issued_at or datetime.now(UTC).replace(microsecond=0)
    payload = payload or {}
    attestation = BankAttestationInput(
        attestation_type=attestation_type,
        attestation_hash=attestation_hash,
        issued_at=issued_at,
        key_id=BANK_KEY_ID,
        signature="pending",
        payload=payload,
    )
    envelope = bank_attestation_envelope(hash_id=hash_id, bank_id=bank_id, attestation=attestation)
    signature = b64url(BANK_PRIVATE_KEY.sign(canonical_json_bytes(envelope)))
    return {
        "attestation_type": attestation_type,
        "attestation_hash": attestation_hash,
        "issued_at": issued_at.isoformat(),
        "key_id": BANK_KEY_ID,
        "signature": signature,
        "payload": payload,
    }


def sign_bank_revocation_payload(
    *,
    hash_id: str,
    bank_id: str = BANK_ID,
    attestation_type: str = "kyc_hash_seen",
    revoked_at: datetime | None = None,
    reason_code: str = "bank_revoked",
    payload: dict | None = None,
) -> dict:
    revoked_at = revoked_at or datetime.now(UTC).replace(microsecond=0)
    payload = payload or {}
    request = BankAttestationRevokeRequest(
        hash_id=hash_id,
        bank_id=bank_id,
        attestation_type=attestation_type,
        revoked_at=revoked_at,
        reason_code=reason_code,
        key_id=BANK_KEY_ID,
        signature="pending",
        payload=payload,
    )
    envelope = bank_attestation_revocation_envelope(request)
    signature = b64url(BANK_PRIVATE_KEY.sign(canonical_json_bytes(envelope)))
    return {
        "hash_id": hash_id,
        "bank_id": bank_id,
        "attestation_type": attestation_type,
        "revoked_at": revoked_at.isoformat(),
        "reason_code": reason_code,
        "key_id": BANK_KEY_ID,
        "signature": signature,
        "payload": payload,
    }
