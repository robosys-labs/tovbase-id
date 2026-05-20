from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Select, desc, func, inspect, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import (
    ActionAttestation,
    BankAttestation,
    DidDocument,
    IdentityHash,
    RegistrationReceipt,
    RegistryEvent,
    SignedAction,
)
from app.schemas import (
    ActionChallengeRequest,
    ActionChallengeResponse,
    ActionResponse,
    ActionSubmitRequest,
    ActionSubmitResponse,
    AttestationSummary,
    BankAttestationAuditRecord,
    BankAttestationAuditResponse,
    BankAttestationRevokeRequest,
    DidAttestRequest,
    DidAttestResponse,
    DidBatchRegisterRequest,
    DidBatchRegisterResponse,
    DidBatchRegisterResult,
    DidHealthResponse,
    DidRegisterRequest,
    DidRegisterResponse,
    DidRekeyRequest,
    DidRekeyResponse,
    DidResolveResponse,
    ReceiptSummary,
    ReceiptVerifyRequest,
    ReceiptVerifyResponse,
    RegistryEventAuditAggregate,
    RegistryEventAuditProblem,
    RegistryEventAuditResponse,
    RegistryKeyResponse,
)
from app.services.bank_keys import verify_bank_attestation, verify_bank_rekey, verify_bank_revocation
from app.services.crypto import (
    b64url_encode,
    canonical_json_bytes,
    json_safe,
    registry_signer,
    sha256_hex,
    utc_now,
    verify_detached_signature,
)
from app.services.provider_keys import verify_action_attestation
from app.services.replication import replication_status
from app.services.runtime import current_runtime_status


class RegistryError(Exception):
    status_code = 400


class RegistryNotFound(RegistryError):
    status_code = 404


class RegistryConflict(RegistryError):
    status_code = 409


class RegistryValidationError(RegistryError):
    status_code = 400


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


def derive_did(hash_id: str) -> str:
    return f"did:{settings.did_method}:{hash_id}"


def parse_hash_from_did(did: str) -> str:
    prefix = f"did:{settings.did_method}:"
    if not did.startswith(prefix):
        raise RegistryValidationError(f"unsupported DID method; expected {prefix}<hash_id>")
    hash_id = did.removeprefix(prefix)
    if len(hash_id) != 64:
        raise RegistryValidationError("DID hash component must be a 64-character SHA-256 hex value")
    return hash_id.lower()


def did_document_for(identity: IdentityHash) -> dict[str, Any]:
    key_id = f"{identity.did}#webauthn-1"
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": identity.did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "JsonWebKey2020",
                "controller": identity.did,
                "publicKeyJwk": identity.webauthn_public_key,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _latest_event_query(aggregate_id: str) -> Select[tuple[RegistryEvent]]:
    return (
        select(RegistryEvent)
        .where(RegistryEvent.aggregate_id == aggregate_id)
        .order_by(desc(RegistryEvent.sequence_number))
        .limit(1)
    )


def create_event(
    db: Session,
    *,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    payload: dict[str, Any],
) -> RegistryEvent:
    safe_payload = json_safe(payload)
    latest_event = db.execute(_latest_event_query(aggregate_id)).scalar_one_or_none()
    sequence_number = 1 if latest_event is None else latest_event.sequence_number + 1
    previous_hash = latest_event.event_hash if latest_event else None
    payload_hash = sha256_hex(canonical_json_bytes(safe_payload))
    hash_material = canonical_json_bytes({"payload": safe_payload, "previous_event_hash": previous_hash})
    event = RegistryEvent(
        event_id=new_id("evt"),
        event_type=event_type,
        aggregate_id=aggregate_id,
        aggregate_type=aggregate_type,
        sequence_number=sequence_number,
        occurred_at=utc_now(),
        payload=safe_payload,
        payload_hash=payload_hash,
        previous_event_hash=previous_hash,
        event_hash=sha256_hex(hash_material),
    )
    db.add(event)
    db.flush()
    return event


def _receipt_summary(receipt: RegistrationReceipt, *, include_payload: bool = True) -> ReceiptSummary:
    return ReceiptSummary(
        receipt_id=receipt.receipt_id,
        payload=receipt.payload if include_payload else None,
        payload_hash=receipt.payload_hash,
        signature_algorithm=receipt.signature_algorithm,
        key_id=receipt.key_id,
        signature=receipt.signature,
        issued_at=receipt.issued_at,
    )


def _attestation_summary(attestation: BankAttestation) -> AttestationSummary:
    return AttestationSummary(
        attestation_id=attestation.attestation_id,
        bank_id=attestation.bank_id,
        attestation_type=attestation.attestation_type,
        attestation_hash=attestation.attestation_hash,
        issued_at=attestation.issued_at,
        expires_at=attestation.expires_at,
        key_id=attestation.key_id,
        signature_verified=attestation.signature_verified,
        verification_error=attestation.verification_error,
        revoked_at=attestation.revoked_at,
    )


def _attestation_audit_record(attestation: BankAttestation) -> BankAttestationAuditRecord:
    return BankAttestationAuditRecord(
        attestation_id=attestation.attestation_id,
        hash_id=attestation.hash_id,
        bank_id=attestation.bank_id,
        attestation_type=attestation.attestation_type,
        attestation_hash=attestation.attestation_hash,
        issued_at=attestation.issued_at,
        expires_at=attestation.expires_at,
        key_id=attestation.key_id,
        signature=attestation.signature,
        signature_verified=attestation.signature_verified,
        verification_error=attestation.verification_error,
        payload=attestation.payload,
        revoked_at=attestation.revoked_at,
    )


def _latest_receipt(db: Session, hash_id: str) -> RegistrationReceipt:
    receipt = (
        db.execute(
            select(RegistrationReceipt)
            .where(RegistrationReceipt.hash_id == hash_id)
            .order_by(desc(RegistrationReceipt.issued_at))
            .limit(1)
        )
        .scalars()
        .first()
    )
    if receipt is None:
        raise RegistryNotFound("registration receipt not found")
    return receipt


def _active_attestations(db: Session, hash_id: str) -> list[BankAttestation]:
    return list(
        db.execute(
            select(BankAttestation)
            .where(BankAttestation.hash_id == hash_id, BankAttestation.revoked_at.is_(None))
            .order_by(BankAttestation.issued_at)
        )
        .scalars()
        .all()
    )


def _assert_registration_compatible(existing: IdentityHash, request: DidRegisterRequest) -> None:
    if existing.device_pubkey_fingerprint != request.device_pubkey_fingerprint:
        raise RegistryConflict("hash_id already exists with a different public-key fingerprint")
    if existing.webauthn_credential_id != request.webauthn_credential_id:
        raise RegistryConflict("hash_id already exists with a different WebAuthn credential id")
    if existing.webauthn_public_key != request.webauthn_public_key:
        raise RegistryConflict("hash_id already exists with different public-key material")


def _upsert_attestation(
    db: Session,
    *,
    hash_id: str,
    bank_id: str,
    attestation_type: str,
    attestation_hash: str,
    issued_at: datetime,
    expires_at: datetime | None,
    key_id: str,
    signature: str,
    signature_verified: bool,
    verification_error: str | None,
    payload: dict[str, Any],
    revoked_at: datetime | None = None,
) -> BankAttestation:
    existing = (
        db.execute(
            select(BankAttestation).where(
                BankAttestation.hash_id == hash_id,
                BankAttestation.bank_id == bank_id,
                BankAttestation.attestation_type == attestation_type,
            )
        )
        .scalars()
        .first()
    )
    if existing is None:
        attestation = BankAttestation(
            attestation_id=new_id("att"),
            hash_id=hash_id,
            bank_id=bank_id,
            attestation_type=attestation_type,
            attestation_hash=attestation_hash,
            issued_at=issued_at,
            expires_at=expires_at,
            key_id=key_id,
            signature=signature,
            signature_verified=signature_verified,
            verification_error=verification_error,
            payload=payload,
            revoked_at=revoked_at,
        )
        db.add(attestation)
    else:
        existing.attestation_hash = attestation_hash
        existing.issued_at = issued_at
        existing.expires_at = expires_at
        existing.key_id = key_id
        existing.signature = signature
        existing.signature_verified = signature_verified
        existing.verification_error = verification_error
        existing.payload = payload
        existing.revoked_at = revoked_at
        attestation = existing
    db.flush()
    return attestation


def _attach_registration_attestation(db: Session, request: DidRegisterRequest) -> BankAttestation | None:
    if request.bank_attestation is None:
        return None
    if not request.bank_id:
        raise RegistryValidationError("bank_id is required when bank_attestation is supplied")
    att = request.bank_attestation
    verification = verify_bank_attestation(hash_id=request.hash_id, bank_id=request.bank_id, attestation=att)
    if not verification.valid:
        raise RegistryValidationError(f"bank attestation signature invalid: {verification.error}")
    return _upsert_attestation(
        db,
        hash_id=request.hash_id,
        bank_id=request.bank_id,
        attestation_type=att.attestation_type,
        attestation_hash=att.attestation_hash,
        issued_at=att.issued_at,
        expires_at=att.expires_at,
        key_id=att.key_id,
        signature=att.signature,
        signature_verified=verification.valid,
        verification_error=verification.error,
        payload=att.payload,
        revoked_at=att.revoked_at,
    )


def register_identity(db: Session, request: DidRegisterRequest) -> DidRegisterResponse:
    existing = db.get(IdentityHash, request.hash_id)
    if existing is not None:
        _assert_registration_compatible(existing, request)
        if request.bank_attestation:
            _attach_registration_attestation(db, request)
            create_event(
                db,
                event_type="bank_attestation_upserted",
                aggregate_type="identity_hash",
                aggregate_id=request.hash_id,
                payload={"hash_id": request.hash_id, "bank_id": request.bank_id},
            )
            db.commit()
        return DidRegisterResponse(
            did=existing.did,
            hash_id=existing.hash_id,
            status="exists",
            registered_at=existing.registered_at,
            receipt=_receipt_summary(_latest_receipt(db, existing.hash_id)),
        )

    now = utc_now()
    did = derive_did(request.hash_id)
    identity = IdentityHash(
        hash_id=request.hash_id,
        did=did,
        hash_algorithm=request.hash_algorithm,
        hash_encoding=request.hash_encoding,
        sdk_version=request.sdk_version,
        device_pubkey_fingerprint=request.device_pubkey_fingerprint,
        webauthn_credential_id=request.webauthn_credential_id,
        webauthn_public_key=request.webauthn_public_key,
        registered_at=now,
        status="active",
        registry_metadata=request.metadata,
    )
    db.add(identity)
    db.flush()

    document = did_document_for(identity)
    did_doc = DidDocument(
        did=did,
        hash_id=request.hash_id,
        document=document,
        document_hash=sha256_hex(canonical_json_bytes(document)),
        version=1,
        created_at=now,
        updated_at=now,
    )
    db.add(did_doc)
    db.flush()

    bank_attestation = _attach_registration_attestation(db, request)
    event = create_event(
        db,
        event_type="identity_registered",
        aggregate_type="identity_hash",
        aggregate_id=request.hash_id,
        payload={
            "hash_id": request.hash_id,
            "did": did,
            "hash_algorithm": request.hash_algorithm,
            "hash_encoding": request.hash_encoding,
            "sdk_version": request.sdk_version,
            "device_pubkey_fingerprint": request.device_pubkey_fingerprint,
            "webauthn_credential_id": request.webauthn_credential_id,
            "registered_at": now,
            "bank_id": request.bank_id,
            "bank_attestation_id": bank_attestation.attestation_id if bank_attestation else None,
        },
    )

    receipt_id = new_id("tgr")
    receipt_payload = json_safe({
        "receipt_id": receipt_id,
        "hash_id": request.hash_id,
        "did": did,
        "registered_at": now,
        "issued_at": now,
        "node_id": registry_signer.node_id,
        "key_id": registry_signer.key_id,
        "hash_algorithm": request.hash_algorithm,
        "hash_encoding": request.hash_encoding,
        "sdk_version": request.sdk_version,
        "document_hash": did_doc.document_hash,
        "event_hash": event.event_hash,
        "bank_id": request.bank_id,
    })
    payload_hash, signature = registry_signer.sign_payload(receipt_payload)
    receipt = RegistrationReceipt(
        receipt_id=receipt_id,
        hash_id=request.hash_id,
        did=did,
        issued_at=now,
        node_id=registry_signer.node_id,
        key_id=registry_signer.key_id,
        payload=receipt_payload,
        payload_hash=payload_hash,
        signature=signature,
        signature_algorithm=registry_signer.signature_algorithm,
    )
    db.add(receipt)
    db.commit()

    return DidRegisterResponse(
        did=did,
        hash_id=request.hash_id,
        status="registered",
        registered_at=now,
        receipt=_receipt_summary(receipt),
    )


def register_batch(db: Session, request: DidBatchRegisterRequest) -> DidBatchRegisterResponse:
    results: list[DidBatchRegisterResult] = []
    for index, entry in enumerate(request.entries):
        registration = DidRegisterRequest(**entry.model_dump(), bank_id=request.bank_id)
        try:
            response = register_identity(db, registration)
        except RegistryError as exc:
            db.rollback()
            results.append(
                DidBatchRegisterResult(
                    index=index,
                    hash_id=entry.hash_id,
                    status="failed",
                    error=str(exc),
                    status_code=exc.status_code,
                )
            )
            continue
        results.append(
            DidBatchRegisterResult(
                index=index,
                hash_id=response.hash_id,
                did=response.did,
                status=response.status,
                receipt_id=response.receipt.receipt_id,
            )
        )

    registered_count = sum(1 for result in results if result.status == "registered")
    existing_count = sum(1 for result in results if result.status == "exists")
    failed_count = sum(1 for result in results if result.status == "failed")
    if failed_count == 0:
        status = "completed"
    elif failed_count == len(results):
        status = "failed"
    else:
        status = "partial"
    return DidBatchRegisterResponse(
        batch_id=request.batch_id,
        bank_id=request.bank_id,
        schema_version=request.schema_version,
        status=status,
        received_count=len(request.entries),
        registered_count=registered_count,
        existing_count=existing_count,
        failed_count=failed_count,
        results=results,
    )


def rekey_identity(db: Session, request: DidRekeyRequest) -> DidRekeyResponse:
    identity = db.get(IdentityHash, request.hash_id)
    if identity is None:
        raise RegistryNotFound("cannot rekey an unknown hash_id")
    if identity.did_document is None:
        raise RegistryNotFound("DID document not found")

    verification = verify_bank_rekey(request)
    if not verification.valid:
        raise RegistryValidationError(f"bank rekey signature invalid: {verification.error}")

    rekeyed_at = _aware(request.rekeyed_at)
    did_doc = identity.did_document
    unchanged = (
        identity.device_pubkey_fingerprint == request.device_pubkey_fingerprint
        and identity.webauthn_credential_id == request.webauthn_credential_id
        and identity.webauthn_public_key == request.webauthn_public_key
    )
    if unchanged:
        return DidRekeyResponse(
            did=identity.did,
            hash_id=identity.hash_id,
            status="unchanged",
            rekeyed_at=rekeyed_at,
            did_document=did_doc.document,
            document_hash=did_doc.document_hash,
            did_document_version=did_doc.version,
        )

    identity.device_pubkey_fingerprint = request.device_pubkey_fingerprint
    identity.webauthn_credential_id = request.webauthn_credential_id
    identity.webauthn_public_key = request.webauthn_public_key

    document = did_document_for(identity)
    did_doc.document = document
    did_doc.document_hash = sha256_hex(canonical_json_bytes(document))
    did_doc.version += 1
    did_doc.updated_at = rekeyed_at

    event = create_event(
        db,
        event_type="identity_rekeyed",
        aggregate_type="identity_hash",
        aggregate_id=request.hash_id,
        payload={
            "hash_id": request.hash_id,
            "did": identity.did,
            "bank_id": request.bank_id,
            "reason_code": request.reason_code,
            "bank_credential_id": request.bank_credential_id,
            "rekeyed_at": rekeyed_at,
            "device_pubkey_fingerprint": request.device_pubkey_fingerprint,
            "webauthn_credential_id": request.webauthn_credential_id,
            "webauthn_public_key": request.webauthn_public_key,
            "did_document_hash": did_doc.document_hash,
            "did_document_version": did_doc.version,
            "key_id": request.key_id,
            "payload": request.payload,
        },
    )
    db.commit()
    return DidRekeyResponse(
        did=identity.did,
        hash_id=identity.hash_id,
        status="rekeyed",
        rekeyed_at=rekeyed_at,
        did_document=document,
        document_hash=did_doc.document_hash,
        did_document_version=did_doc.version,
        event_hash=event.event_hash,
    )


def resolve_identity(db: Session, *, did: str | None = None, hash_id: str | None = None) -> DidResolveResponse:
    if did is None and hash_id is None:
        raise RegistryValidationError("did or hash_id is required")
    if hash_id is None and did is not None:
        hash_id = parse_hash_from_did(did)

    identity = db.get(IdentityHash, hash_id)
    if identity is None:
        raise RegistryNotFound("DID registry entry not found")

    receipt = _latest_receipt(db, identity.hash_id)
    if identity.did_document is None:
        raise RegistryNotFound("DID document not found")
    attestations = [_attestation_summary(att) for att in _active_attestations(db, identity.hash_id)]
    return DidResolveResponse(
        did=identity.did,
        hash_id=identity.hash_id,
        did_document=identity.did_document.document,
        registered_at=identity.registered_at,
        status=identity.status,
        receipt=_receipt_summary(receipt),
        attestations=attestations,
    )


def verify_receipt(request: ReceiptVerifyRequest) -> ReceiptVerifyResponse:
    payload_hash = sha256_hex(canonical_json_bytes(request.payload))
    return ReceiptVerifyResponse(
        valid=registry_signer.verify_payload(request.payload, request.signature, request.key_id),
        payload_hash=payload_hash,
        verified_at=utc_now(),
    )


def current_registry_key() -> RegistryKeyResponse:
    return RegistryKeyResponse(
        node_id=registry_signer.node_id,
        key_id=registry_signer.key_id,
        signature_algorithm=registry_signer.signature_algorithm,
        public_key_jwk=registry_signer.public_key_jwk,
        status="active",
    )


def registry_keys() -> list[RegistryKeyResponse]:
    return [RegistryKeyResponse(**key) for key in registry_signer.public_keys()]


def upsert_attestation(db: Session, request: DidAttestRequest) -> DidAttestResponse:
    identity = db.get(IdentityHash, request.hash_id)
    if identity is None:
        raise RegistryNotFound("cannot attest an unknown hash_id")

    att = request.attestation
    verification = verify_bank_attestation(hash_id=request.hash_id, bank_id=request.bank_id, attestation=att)
    if not verification.valid:
        raise RegistryValidationError(f"bank attestation signature invalid: {verification.error}")
    attestation = _upsert_attestation(
        db,
        hash_id=request.hash_id,
        bank_id=request.bank_id,
        attestation_type=att.attestation_type,
        attestation_hash=att.attestation_hash,
        issued_at=att.issued_at,
        expires_at=att.expires_at,
        key_id=att.key_id,
        signature=att.signature,
        signature_verified=verification.valid,
        verification_error=verification.error,
        payload=att.payload,
        revoked_at=att.revoked_at,
    )
    create_event(
        db,
        event_type="bank_attestation_upserted",
        aggregate_type="identity_hash",
        aggregate_id=request.hash_id,
        payload={
            "hash_id": request.hash_id,
            "bank_id": request.bank_id,
            "attestation_type": att.attestation_type,
            "attestation_hash": att.attestation_hash,
            "revoked_at": att.revoked_at,
        },
    )
    db.commit()
    return DidAttestResponse(hash_id=identity.hash_id, did=identity.did, attestation=_attestation_summary(attestation))


def revoke_attestation(db: Session, request: BankAttestationRevokeRequest) -> DidAttestResponse:
    identity = db.get(IdentityHash, request.hash_id)
    if identity is None:
        raise RegistryNotFound("cannot revoke an attestation for an unknown hash_id")

    verification = verify_bank_revocation(request)
    if not verification.valid:
        raise RegistryValidationError(f"bank attestation revocation signature invalid: {verification.error}")

    attestation = (
        db.execute(
            select(BankAttestation).where(
                BankAttestation.hash_id == request.hash_id,
                BankAttestation.bank_id == request.bank_id,
                BankAttestation.attestation_type == request.attestation_type,
            )
        )
        .scalars()
        .first()
    )
    if attestation is None:
        raise RegistryNotFound("bank attestation not found")

    revoked_at = request.revoked_at or utc_now()
    attestation.revoked_at = revoked_at
    create_event(
        db,
        event_type="bank_attestation_revoked",
        aggregate_type="identity_hash",
        aggregate_id=request.hash_id,
        payload={
            "hash_id": request.hash_id,
            "bank_id": request.bank_id,
            "attestation_type": request.attestation_type,
            "revoked_at": revoked_at,
            "reason_code": request.reason_code,
            "key_id": request.key_id,
        },
    )
    db.commit()
    return DidAttestResponse(hash_id=identity.hash_id, did=identity.did, attestation=_attestation_summary(attestation))


def export_attestation_audit(db: Session, hash_id: str) -> BankAttestationAuditResponse:
    identity = db.get(IdentityHash, hash_id)
    if identity is None:
        raise RegistryNotFound("DID registry entry not found")
    attestations = list(
        db.execute(
            select(BankAttestation)
            .where(BankAttestation.hash_id == hash_id)
            .order_by(BankAttestation.bank_id, BankAttestation.attestation_type, BankAttestation.issued_at)
        )
        .scalars()
        .all()
    )
    return BankAttestationAuditResponse(
        hash_id=identity.hash_id,
        did=identity.did,
        exported_at=utc_now(),
        attestations=[_attestation_audit_record(attestation) for attestation in attestations],
    )


def create_action_challenge(db: Session, request: ActionChallengeRequest) -> ActionChallengeResponse:
    hash_id = parse_hash_from_did(request.did)
    identity = db.get(IdentityHash, hash_id)
    if identity is None:
        raise RegistryNotFound("cannot create an action challenge for an unknown DID")

    issued_at = utc_now()
    max_age = request.requested_attestation.max_age_seconds or settings.action_challenge_ttl_seconds
    expires_at = issued_at + timedelta(seconds=max_age)
    action_id = new_id("act")
    envelope = json_safe({
        "action_id": action_id,
        "did": identity.did,
        "hash_id": identity.hash_id,
        "bank_id": request.bank_id,
        "action_type": request.action_type,
        "document_hash": request.document_hash,
        "media_hash": request.media_hash,
        "requested_attestation": request.requested_attestation.model_dump(),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": b64url_encode(secrets.token_bytes(24)),
        "policy_version": request.policy_version,
    })
    challenge_hash = sha256_hex(canonical_json_bytes(envelope))
    action = SignedAction(
        action_id=action_id,
        did=identity.did,
        hash_id=identity.hash_id,
        bank_id=request.bank_id,
        action_type=request.action_type,
        document_hash=request.document_hash,
        media_hash=request.media_hash,
        challenge_hash=challenge_hash,
        canonical_envelope=envelope,
        requested_attestation=request.requested_attestation.model_dump(),
        issued_at=issued_at,
        expires_at=expires_at,
        status="pending",
    )
    db.add(action)
    create_event(
        db,
        event_type="action_challenge_created",
        aggregate_type="signed_action",
        aggregate_id=action_id,
        payload={"action_id": action_id, "hash_id": identity.hash_id, "challenge_hash": challenge_hash},
    )
    db.commit()
    return ActionChallengeResponse(
        action_id=action_id,
        challenge_hash=challenge_hash,
        issued_at=issued_at,
        expires_at=expires_at,
        canonical_envelope=envelope,
    )


def _policy_satisfied(action: SignedAction, request: ActionSubmitRequest, now: datetime) -> dict[str, Any]:
    methods = set(action.requested_attestation.get("methods", ["passkey"]))
    supplied_attestations = {att.attestation_type: att for att in request.attestations}
    attestation_signature_results = {
        att.attestation_type: verify_action_attestation(
            action_id=action.action_id,
            did=action.did,
            hash_id=action.hash_id,
            bank_id=action.bank_id,
            attestation=att,
        )
        for att in request.attestations
    }

    signature_valid = verify_detached_signature(
        action.identity_hash.webauthn_public_key,
        bytes.fromhex(action.challenge_hash),
        request.signature,
    )
    bank_credential_valid = "bank_handshake" not in methods or bool(request.bank_credential_id)
    liveness = supplied_attestations.get("camera_liveness")
    liveness_signature = attestation_signature_results.get("camera_liveness")
    liveness_valid = "camera_liveness" not in methods or (
        liveness is not None
        and liveness.result == "passed"
        and (liveness.expires_at is None or _aware(liveness.expires_at) >= now)
        and liveness_signature is not None
        and liveness_signature.valid
    )
    manual_review = supplied_attestations.get("manual_review")
    manual_review_signature = attestation_signature_results.get("manual_review")
    manual_review_valid = "manual_review" not in methods or (
        manual_review is not None and manual_review.result in {"passed", "manual_review"}
        and manual_review_signature is not None
        and manual_review_signature.valid
    )
    attestation_signatures_valid = all(result.valid for result in attestation_signature_results.values())
    return {
        "signature_valid": signature_valid,
        "bank_credential_valid": bank_credential_valid,
        "attestation_signatures_valid": attestation_signatures_valid,
        "attestation_policy_satisfied": liveness_valid and manual_review_valid and attestation_signatures_valid,
        "required_methods": sorted(methods),
        "provided_attestations": sorted(supplied_attestations.keys()),
        "attestation_signature_results": {
            attestation_type: {"valid": result.valid, "error": result.error}
            for attestation_type, result in attestation_signature_results.items()
        },
    }


def submit_action(db: Session, request: ActionSubmitRequest) -> ActionSubmitResponse:
    action = db.get(SignedAction, request.action_id)
    if action is None:
        raise RegistryNotFound("action challenge not found")

    now = utc_now()
    signed_at = _aware(request.signed_at) if request.signed_at else now
    if _aware(action.expires_at) < now:
        action.status = "expired"
        action.signed_at = signed_at
        action.verification_result = {"expired": True, "signature_valid": False}
        db.commit()
        return ActionSubmitResponse(
            action_id=action.action_id,
            status="expired",
            signed_at=signed_at,
            verification_result=action.verification_result,
        )

    verification = _policy_satisfied(action, request, now)
    approved = (
        verification["signature_valid"]
        and verification["bank_credential_valid"]
        and verification["attestation_policy_satisfied"]
    )

    action.bank_credential_id = request.bank_credential_id
    action.signed_at = signed_at
    action.signature = request.signature
    action.signature_algorithm = request.signature_algorithm
    action.verification_result = verification
    action.status = "approved" if approved else "rejected"

    for att in request.attestations:
        attestation_result = verification["attestation_signature_results"].get(
            att.attestation_type,
            {"valid": False, "error": "not_verified"},
        )
        action_attestation = ActionAttestation(
            action_attestation_id=new_id("aatt"),
            action_id=action.action_id,
            attestation_type=att.attestation_type,
            provider_id=att.provider_id,
            evidence_hash=att.evidence_hash,
            result=att.result,
            issued_at=att.issued_at,
            expires_at=att.expires_at,
            key_id=att.key_id,
            signature=att.signature,
            signature_verified=attestation_result["valid"],
            verification_error=attestation_result["error"],
            payload=att.payload,
        )
        db.add(action_attestation)

    create_event(
        db,
        event_type="action_signed",
        aggregate_type="signed_action",
        aggregate_id=action.action_id,
        payload={
            "action_id": action.action_id,
            "hash_id": action.hash_id,
            "status": action.status,
            "signed_at": signed_at,
            "verification_result": verification,
        },
    )
    db.commit()
    return ActionSubmitResponse(
        action_id=action.action_id,
        status=action.status,  # type: ignore[arg-type]
        signed_at=signed_at,
        verification_result=verification,
    )


def get_action(db: Session, action_id: str) -> ActionResponse:
    action = db.get(SignedAction, action_id)
    if action is None:
        raise RegistryNotFound("action challenge not found")
    return ActionResponse(
        action_id=action.action_id,
        did=action.did,
        hash_id=action.hash_id,
        bank_id=action.bank_id,
        action_type=action.action_type,
        document_hash=action.document_hash,
        media_hash=action.media_hash,
        challenge_hash=action.challenge_hash,
        requested_attestation=action.requested_attestation,
        issued_at=action.issued_at,
        expires_at=action.expires_at,
        signed_at=action.signed_at,
        status=action.status,
        verification_result=action.verification_result,
        attestations=[
            {
                "attestation_type": att.attestation_type,
                "provider_id": att.provider_id,
                "evidence_hash": att.evidence_hash,
                "result": att.result,
                "issued_at": att.issued_at,
                "expires_at": att.expires_at,
                "key_id": att.key_id,
                "signature": att.signature,
                "signature_verified": att.signature_verified,
                "verification_error": att.verification_error,
                "payload": att.payload,
            }
            for att in action.attestations
        ],
    )


def audit_event_chain(db: Session, *, aggregate_id: str | None = None) -> RegistryEventAuditResponse:
    query = select(RegistryEvent).order_by(
        RegistryEvent.aggregate_type,
        RegistryEvent.aggregate_id,
        RegistryEvent.sequence_number,
        RegistryEvent.occurred_at,
    )
    if aggregate_id is not None:
        query = query.where(RegistryEvent.aggregate_id == aggregate_id)
    events = list(db.execute(query).scalars().all())
    grouped: dict[tuple[str, str], list[RegistryEvent]] = {}
    for event in events:
        grouped.setdefault((event.aggregate_type, event.aggregate_id), []).append(event)

    aggregates: list[RegistryEventAuditAggregate] = []
    for (aggregate_type, grouped_aggregate_id), aggregate_events in grouped.items():
        problems: list[RegistryEventAuditProblem] = []
        previous_hash: str | None = None
        expected_sequence = 1
        for event in aggregate_events:
            safe_payload = json_safe(event.payload)
            expected_payload_hash = sha256_hex(canonical_json_bytes(safe_payload))
            expected_event_hash = sha256_hex(
                canonical_json_bytes({"payload": safe_payload, "previous_event_hash": previous_hash})
            )
            if event.sequence_number != expected_sequence:
                problems.append(
                    RegistryEventAuditProblem(
                        event_id=event.event_id,
                        aggregate_type=event.aggregate_type,
                        aggregate_id=event.aggregate_id,
                        sequence_number=event.sequence_number,
                        error="sequence_mismatch",
                        expected=expected_sequence,
                        actual=event.sequence_number,
                    )
                )
            if event.previous_event_hash != previous_hash:
                problems.append(
                    RegistryEventAuditProblem(
                        event_id=event.event_id,
                        aggregate_type=event.aggregate_type,
                        aggregate_id=event.aggregate_id,
                        sequence_number=event.sequence_number,
                        error="previous_hash_mismatch",
                        expected=previous_hash,
                        actual=event.previous_event_hash,
                    )
                )
            if event.payload_hash != expected_payload_hash:
                problems.append(
                    RegistryEventAuditProblem(
                        event_id=event.event_id,
                        aggregate_type=event.aggregate_type,
                        aggregate_id=event.aggregate_id,
                        sequence_number=event.sequence_number,
                        error="payload_hash_mismatch",
                        expected=expected_payload_hash,
                        actual=event.payload_hash,
                    )
                )
            if event.event_hash != expected_event_hash:
                problems.append(
                    RegistryEventAuditProblem(
                        event_id=event.event_id,
                        aggregate_type=event.aggregate_type,
                        aggregate_id=event.aggregate_id,
                        sequence_number=event.sequence_number,
                        error="event_hash_mismatch",
                        expected=expected_event_hash,
                        actual=event.event_hash,
                    )
                )
            previous_hash = event.event_hash
            expected_sequence += 1

        aggregates.append(
            RegistryEventAuditAggregate(
                aggregate_type=aggregate_type,
                aggregate_id=grouped_aggregate_id,
                event_count=len(aggregate_events),
                valid=not problems,
                first_event_hash=aggregate_events[0].event_hash if aggregate_events else None,
                latest_event_hash=aggregate_events[-1].event_hash if aggregate_events else None,
                problems=problems,
            )
        )

    problem_count = sum(len(aggregate.problems) for aggregate in aggregates)
    invalid_aggregate_count = sum(1 for aggregate in aggregates if not aggregate.valid)
    return RegistryEventAuditResponse(
        valid=problem_count == 0,
        checked_at=utc_now(),
        aggregate_count=len(aggregates),
        event_count=len(events),
        invalid_aggregate_count=invalid_aggregate_count,
        problem_count=problem_count,
        aggregates=aggregates,
    )


def health(db: Session) -> DidHealthResponse:
    registry_tables = {
        "identity_hashes",
        "did_documents",
        "registry_events",
        "registration_receipts",
        "bank_attestations",
        "signed_actions",
        "action_attestations",
        "registry_anchors",
    }
    inspector = inspect(db.bind)
    existing_tables = set(inspector.get_table_names())
    latest_receipt_at = db.execute(select(func.max(RegistrationReceipt.issued_at))).scalar_one_or_none()
    tables_ready = registry_tables.issubset(existing_tables)
    return DidHealthResponse(
        status="ok" if tables_ready else "degraded",
        database=True,
        registry_tables=tables_ready,
        node_id=settings.did_node_id,
        signing_key_id=settings.did_signing_key_id,
        latest_receipt_at=latest_receipt_at,
        replication=replication_status(db),
        runtime=current_runtime_status(),
    )
