from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")

FORBIDDEN_FIELD_NAMES = {
    "access_token",
    "address",
    "bank_customer_id",
    "birth_date",
    "bvn",
    "customer_id",
    "date_of_birth",
    "dob",
    "email",
    "face_image",
    "face_video",
    "full_name",
    "name",
    "nin",
    "passport",
    "passport_number",
    "phone",
    "private_key",
    "raw_media",
    "raw_payload",
    "salt",
    "token",
}


def normalize_hash(value: str) -> str:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise ValueError("must be a 64-character SHA-256 hex value")
    return value.lower()


def _forbidden_keys(value: Any, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            if str(key).lower() in FORBIDDEN_FIELD_NAMES:
                hits.append(key_path)
            hits.extend(_forbidden_keys(nested, key_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            hits.extend(_forbidden_keys(nested, f"{path}[{index}]"))
    return hits


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def reject_forbidden_fields(cls, data: Any) -> Any:
        hits = _forbidden_keys(data)
        if hits:
            raise ValueError(f"raw PII or secret-like fields are not accepted: {', '.join(hits)}")
        return data


class BankAttestationInput(StrictModel):
    attestation_type: str = Field(min_length=1, max_length=64)
    attestation_hash: str
    issued_at: datetime
    expires_at: datetime | None = None
    key_id: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    revoked_at: datetime | None = None

    @field_validator("attestation_hash")
    @classmethod
    def normalize_attestation_hash(cls, value: str) -> str:
        return normalize_hash(value)


class DidRegisterRequest(StrictModel):
    hash_id: str
    hash_algorithm: Literal["sha256"] = "sha256"
    hash_encoding: Literal["hex"] = "hex"
    sdk_version: str | None = Field(default=None, max_length=64)
    webauthn_credential_id: str = Field(min_length=1)
    webauthn_public_key: dict[str, Any]
    device_pubkey_fingerprint: str
    bank_id: str | None = None
    bank_attestation: BankAttestationInput | None = None
    metadata: dict[str, Any] | None = None

    @field_validator("hash_id", "device_pubkey_fingerprint")
    @classmethod
    def normalize_sha256_hex(cls, value: str) -> str:
        return normalize_hash(value)


class ReceiptSummary(BaseModel):
    receipt_id: str
    payload: dict[str, Any] | None = None
    payload_hash: str
    signature_algorithm: str
    key_id: str
    signature: str
    issued_at: datetime


class DidRegisterResponse(BaseModel):
    did: str
    hash_id: str
    status: Literal["registered", "exists"]
    registered_at: datetime
    receipt: ReceiptSummary


class AttestationSummary(BaseModel):
    attestation_id: str
    bank_id: str
    attestation_type: str
    attestation_hash: str
    issued_at: datetime
    expires_at: datetime | None = None
    key_id: str
    revoked_at: datetime | None = None


class DidResolveResponse(BaseModel):
    did: str
    hash_id: str
    did_document: dict[str, Any]
    registered_at: datetime
    status: str
    receipt: ReceiptSummary
    attestations: list[AttestationSummary] = Field(default_factory=list)


class ReceiptVerifyRequest(StrictModel):
    receipt_id: str
    payload: dict[str, Any]
    signature: str
    key_id: str


class ReceiptVerifyResponse(BaseModel):
    valid: bool
    payload_hash: str
    verified_at: datetime


class RegistryKeyResponse(BaseModel):
    node_id: str
    key_id: str
    signature_algorithm: str
    public_key_jwk: dict[str, Any]


class DidAttestRequest(StrictModel):
    hash_id: str
    bank_id: str = Field(min_length=1)
    attestation: BankAttestationInput

    @field_validator("hash_id")
    @classmethod
    def normalize_attested_hash(cls, value: str) -> str:
        return normalize_hash(value)


class DidAttestResponse(BaseModel):
    hash_id: str
    did: str
    attestation: AttestationSummary


class RequestedAttestation(StrictModel):
    level: Literal["instant", "aal2", "aal3", "manual_review"] = "instant"
    methods: list[Literal["passkey", "bank_handshake", "camera_liveness", "manual_review"]] = Field(
        default_factory=lambda: ["passkey"],
        min_length=1,
    )
    max_age_seconds: int = Field(default=300, ge=30, le=900)

    @field_validator("methods")
    @classmethod
    def ensure_passkey(cls, value: list[str]) -> list[str]:
        if "passkey" not in value:
            return ["passkey", *value]
        return value


class ActionChallengeRequest(StrictModel):
    did: str = Field(min_length=1)
    bank_id: str = Field(min_length=1)
    action_type: str = Field(min_length=1, max_length=64)
    document_hash: str | None = None
    media_hash: str | None = None
    requested_attestation: RequestedAttestation = Field(default_factory=RequestedAttestation)
    policy_version: str = Field(default="default-v1", min_length=1, max_length=128)

    @field_validator("document_hash", "media_hash")
    @classmethod
    def normalize_optional_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_hash(value)

    @model_validator(mode="after")
    def require_payload_hash(self) -> ActionChallengeRequest:
        if not self.document_hash and not self.media_hash:
            raise ValueError("document_hash or media_hash is required")
        return self


class ActionChallengeResponse(BaseModel):
    action_id: str
    challenge_hash: str
    issued_at: datetime
    expires_at: datetime
    canonical_envelope: dict[str, Any]


class ActionAttestationInput(StrictModel):
    attestation_type: str = Field(min_length=1, max_length=64)
    provider_id: str = Field(min_length=1)
    evidence_hash: str
    result: Literal["passed", "failed", "pending", "manual_review"]
    issued_at: datetime
    expires_at: datetime | None = None
    key_id: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_hash")
    @classmethod
    def normalize_evidence_hash(cls, value: str) -> str:
        return normalize_hash(value)


class ActionSubmitRequest(StrictModel):
    action_id: str = Field(min_length=1)
    bank_credential_id: str | None = None
    webauthn_assertion: dict[str, Any] = Field(default_factory=dict)
    signature: str = Field(min_length=1)
    signed_at: datetime | None = None
    signature_algorithm: Literal["ed25519"] = "ed25519"
    attestations: list[ActionAttestationInput] = Field(default_factory=list)


class ActionSubmitResponse(BaseModel):
    action_id: str
    status: Literal["approved", "rejected", "expired"]
    signed_at: datetime
    verification_result: dict[str, Any]


class ActionResponse(BaseModel):
    action_id: str
    did: str
    hash_id: str
    bank_id: str
    action_type: str
    document_hash: str | None = None
    media_hash: str | None = None
    challenge_hash: str
    requested_attestation: dict[str, Any]
    issued_at: datetime
    expires_at: datetime
    signed_at: datetime | None = None
    status: str
    verification_result: dict[str, Any] | None = None
    attestations: list[ActionAttestationInput] = Field(default_factory=list)


class DidHealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    database: bool
    registry_tables: bool
    node_id: str
    signing_key_id: str
    latest_receipt_at: datetime | None = None
    replication: dict[str, Any] = Field(default_factory=dict)
