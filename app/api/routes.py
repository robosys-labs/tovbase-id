from collections.abc import Callable
from typing import Annotated, TypeVar

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.schemas import (
    ActionChallengeRequest,
    ActionChallengeResponse,
    ActionResponse,
    ActionSubmitRequest,
    ActionSubmitResponse,
    DidAttestRequest,
    DidAttestResponse,
    DidHealthResponse,
    DidRegisterRequest,
    DidRegisterResponse,
    DidResolveResponse,
    ReceiptVerifyRequest,
    ReceiptVerifyResponse,
    RegistryKeyResponse,
    normalize_hash,
)
from app.services import registry
from app.services.registry import RegistryError

router = APIRouter(prefix="/v1/did", tags=["did-registry"])
T = TypeVar("T")
DBSession = Annotated[Session, Depends(get_db)]


def _service(call: Callable[[], T]) -> T:
    try:
        return call()
    except RegistryError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.post("/register", response_model=DidRegisterResponse)
def register(request: DidRegisterRequest, db: DBSession) -> DidRegisterResponse:
    return _service(lambda: registry.register_identity(db, request))


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
def attest(request: DidAttestRequest, db: DBSession) -> DidAttestResponse:
    return _service(lambda: registry.upsert_attestation(db, request))


@router.post("/actions/challenge", response_model=ActionChallengeResponse)
def create_action_challenge(
    request: ActionChallengeRequest,
    db: DBSession,
) -> ActionChallengeResponse:
    return _service(lambda: registry.create_action_challenge(db, request))


@router.post("/actions/submit", response_model=ActionSubmitResponse)
def submit_action(request: ActionSubmitRequest, db: DBSession) -> ActionSubmitResponse:
    return _service(lambda: registry.submit_action(db, request))


@router.get("/actions/{action_id}", response_model=ActionResponse)
def get_action(action_id: str, db: DBSession) -> ActionResponse:
    return _service(lambda: registry.get_action(db, action_id))


@router.get("/{did}", response_model=DidResolveResponse)
def resolve_by_did(did: str, db: DBSession) -> DidResolveResponse:
    return _service(lambda: registry.resolve_identity(db, did=did))
