from collections.abc import Callable
from typing import Annotated, TypeVar

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.auth import assert_bank_scope, require_admin_api_key, require_bank_api_key
from app.db import get_db
from app.schemas import (
    ActionChallengeRequest,
    ActionChallengeResponse,
    ActionResponse,
    ActionSubmitRequest,
    ActionSubmitResponse,
    AnchorCreateRequest,
    AnchorProofResponse,
    AnchorResponse,
    BankAttestationAuditResponse,
    BankAttestationRevokeRequest,
    DidAttestRequest,
    DidAttestResponse,
    DidBatchRegisterRequest,
    DidBatchRegisterResponse,
    DidHealthResponse,
    DidRegisterRequest,
    DidRegisterResponse,
    DidResolveResponse,
    ReceiptVerifyRequest,
    ReceiptVerifyResponse,
    RegistryEventAuditResponse,
    RegistryKeyResponse,
    normalize_hash,
)
from app.services import anchors, registry
from app.services.api_keys import AdminPrincipal, BankPrincipal
from app.services.registry import RegistryError

router = APIRouter(prefix="/v1/did", tags=["did-registry"])
T = TypeVar("T")
DBSession = Annotated[Session, Depends(get_db)]
BankAuth = Annotated[BankPrincipal, Depends(require_bank_api_key)]
AdminAuth = Annotated[AdminPrincipal, Depends(require_admin_api_key)]


def _service(call: Callable[[], T]) -> T:
    try:
        return call()
    except RegistryError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post("/register", response_model=DidRegisterResponse)
def register(request: DidRegisterRequest, principal: BankAuth, db: DBSession) -> DidRegisterResponse:
    request.bank_id = assert_bank_scope(principal, request.bank_id)
    return _service(lambda: registry.register_identity(db, request))


@router.post("/register/batch", response_model=DidBatchRegisterResponse)
def register_batch(request: DidBatchRegisterRequest, principal: BankAuth, db: DBSession) -> DidBatchRegisterResponse:
    assert_bank_scope(principal, request.bank_id)
    return registry.register_batch(db, request)


@router.get("/health", response_model=DidHealthResponse)
def health(db: DBSession) -> DidHealthResponse:
    return _service(lambda: registry.health(db))


@router.get("/hash/{hash_id}", response_model=DidResolveResponse)
def resolve_by_hash(hash_id: str, db: DBSession) -> DidResolveResponse:
    try:
        normalized = normalize_hash(hash_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _service(lambda: registry.resolve_identity(db, hash_id=normalized))


@router.post("/receipt/verify", response_model=ReceiptVerifyResponse)
def verify_receipt(request: ReceiptVerifyRequest) -> ReceiptVerifyResponse:
    return registry.verify_receipt(request)


@router.get("/keys/current", response_model=RegistryKeyResponse)
def current_registry_key() -> RegistryKeyResponse:
    return registry.current_registry_key()


@router.get("/keys", response_model=list[RegistryKeyResponse])
def registry_keys() -> list[RegistryKeyResponse]:
    return registry.registry_keys()


@router.post("/attest", response_model=DidAttestResponse)
def attest(request: DidAttestRequest, principal: BankAuth, db: DBSession) -> DidAttestResponse:
    assert_bank_scope(principal, request.bank_id)
    return _service(lambda: registry.upsert_attestation(db, request))


@router.post("/attest/revoke", response_model=DidAttestResponse)
def revoke_attestation(request: BankAttestationRevokeRequest, principal: BankAuth, db: DBSession) -> DidAttestResponse:
    assert_bank_scope(principal, request.bank_id)
    return _service(lambda: registry.revoke_attestation(db, request))


@router.get("/attest/{hash_id}/audit", response_model=BankAttestationAuditResponse)
def export_attestation_audit(hash_id: str, _: AdminAuth, db: DBSession) -> BankAttestationAuditResponse:
    try:
        normalized = normalize_hash(hash_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _service(lambda: registry.export_attestation_audit(db, normalized))


@router.post("/actions/challenge", response_model=ActionChallengeResponse)
def create_action_challenge(
    request: ActionChallengeRequest,
    principal: BankAuth,
    db: DBSession,
) -> ActionChallengeResponse:
    assert_bank_scope(principal, request.bank_id)
    return _service(lambda: registry.create_action_challenge(db, request))


@router.post("/actions/submit", response_model=ActionSubmitResponse)
def submit_action(request: ActionSubmitRequest, db: DBSession) -> ActionSubmitResponse:
    return _service(lambda: registry.submit_action(db, request))


@router.get("/actions/{action_id}", response_model=ActionResponse)
def get_action(action_id: str, db: DBSession) -> ActionResponse:
    return _service(lambda: registry.get_action(db, action_id))


@router.get("/events/audit", response_model=RegistryEventAuditResponse)
def audit_events(_: AdminAuth, db: DBSession, aggregate_id: str | None = None) -> RegistryEventAuditResponse:
    return registry.audit_event_chain(db, aggregate_id=aggregate_id)


@router.post("/anchors", response_model=AnchorResponse)
def create_anchor(request: AnchorCreateRequest, _: AdminAuth, db: DBSession) -> AnchorResponse:
    return _service(lambda: anchors.create_anchor(db, request))


@router.get("/anchors/{anchor_id}", response_model=AnchorResponse)
def get_anchor(anchor_id: str, db: DBSession) -> AnchorResponse:
    return _service(lambda: anchors.get_anchor(db, anchor_id))


@router.get("/anchors/{anchor_id}/proof/{receipt_id}", response_model=AnchorProofResponse)
def get_anchor_proof(anchor_id: str, receipt_id: str, db: DBSession) -> AnchorProofResponse:
    return _service(lambda: anchors.get_anchor_proof(db, anchor_id=anchor_id, receipt_id=receipt_id))


@router.get("/{did}", response_model=DidResolveResponse)
def resolve_by_did(did: str, db: DBSession) -> DidResolveResponse:
    return _service(lambda: registry.resolve_identity(db, did=did))
