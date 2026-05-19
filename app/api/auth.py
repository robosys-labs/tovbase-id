from typing import Annotated

from fastapi import Header, HTTPException

from app.services.api_keys import AdminPrincipal, BankPrincipal, authenticate_admin_api_key, authenticate_bank_api_key

BankIdHeader = Annotated[str | None, Header(alias="X-Tovbase-Bank-Id")]
ApiKeyHeader = Annotated[str | None, Header(alias="X-Tovbase-Api-Key")]
AdminKeyHeader = Annotated[str | None, Header(alias="X-Tovbase-Admin-Key")]


def require_bank_api_key(bank_id: BankIdHeader = None, api_key: ApiKeyHeader = None) -> BankPrincipal:
    principal = authenticate_bank_api_key(bank_id=bank_id, api_key=api_key)
    if principal is None:
        raise HTTPException(status_code=401, detail="valid bank API key required")
    return principal


def require_admin_api_key(api_key: AdminKeyHeader = None) -> AdminPrincipal:
    principal = authenticate_admin_api_key(api_key=api_key)
    if principal is None:
        raise HTTPException(status_code=401, detail="valid admin API key required")
    return principal


def assert_bank_scope(principal: BankPrincipal, request_bank_id: str | None) -> str:
    if request_bank_id is not None and request_bank_id != principal.bank_id:
        raise HTTPException(status_code=403, detail="bank API key does not match request bank_id")
    return principal.bank_id
