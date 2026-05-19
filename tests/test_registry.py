import base64
import hashlib
import os
from datetime import UTC, datetime, timedelta

os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from app.db import Base, engine, init_db
from app.main import app
from tests.helpers import (
    admin_headers,
    bank_headers,
    sign_action_attestation_payload,
    sign_bank_attestation_payload,
    sign_bank_revocation_payload,
)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sha256_hex(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


@pytest.fixture()
def client() -> TestClient:
    Base.metadata.drop_all(bind=engine)
    init_db()
    with TestClient(app) as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def user_key() -> tuple[ed25519.Ed25519PrivateKey, dict[str, str], str, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(public_bytes)}
    credential_id = b64url(hashlib.sha256(public_bytes + b"credential").digest())
    fingerprint = sha256_hex(public_bytes)
    return private_key, jwk, credential_id, fingerprint


def register_payload(
    user_key: tuple[ed25519.Ed25519PrivateKey, dict[str, str], str, str],
    *,
    hash_id: str | None = None,
) -> dict:
    _, jwk, credential_id, fingerprint = user_key
    final_hash_id = hash_id or sha256_hex("sdk-local-canonical-identity")
    return {
        "hash_id": final_hash_id,
        "hash_algorithm": "sha256",
        "hash_encoding": "hex",
        "sdk_version": "tovbase-js/0.1.0",
        "webauthn_credential_id": credential_id,
        "webauthn_public_key": jwk,
        "device_pubkey_fingerprint": fingerprint,
        "bank_id": "bank-a",
        "bank_attestation": sign_bank_attestation_payload(
            hash_id=final_hash_id,
            attestation_hash=sha256_hex("bank-a-evidence"),
        ),
        "metadata": {"schema_version": "kyc-ng-v1"},
    }


def batch_entry(
    user_key: tuple[ed25519.Ed25519PrivateKey, dict[str, str], str, str],
    *,
    hash_id: str | None = None,
) -> dict:
    entry = register_payload(user_key, hash_id=hash_id)
    entry.pop("bank_id")
    return entry


def register_identity(client: TestClient, user_key: tuple[ed25519.Ed25519PrivateKey, dict[str, str], str, str]) -> dict:
    response = client.post("/v1/did/register", json=register_payload(user_key), headers=bank_headers())
    assert response.status_code == 200, response.text
    return response.json()


def sign_challenge(private_key: ed25519.Ed25519PrivateKey, challenge_hash: str) -> str:
    return b64url(private_key.sign(bytes.fromhex(challenge_hash)))


def test_register_and_resolve_by_did_and_hash(client: TestClient, user_key) -> None:
    registered = register_identity(client, user_key)

    did_response = client.get(f"/v1/did/{registered['did']}")
    assert did_response.status_code == 200
    did_body = did_response.json()
    assert did_body["hash_id"] == registered["hash_id"]
    assert did_body["did_document"]["id"] == registered["did"]
    assert did_body["attestations"][0]["bank_id"] == "bank-a"
    assert did_body["attestations"][0]["signature_verified"] is True

    hash_response = client.get(f"/v1/did/hash/{registered['hash_id']}")
    assert hash_response.status_code == 200
    assert hash_response.json()["did"] == registered["did"]


def test_duplicate_registration_is_idempotent(client: TestClient, user_key) -> None:
    first = register_identity(client, user_key)
    second_response = client.post("/v1/did/register", json=register_payload(user_key), headers=bank_headers())

    assert second_response.status_code == 200
    second = second_response.json()
    assert second["status"] == "exists"
    assert second["did"] == first["did"]
    assert second["receipt"]["payload_hash"] == first["receipt"]["payload_hash"]


def test_conflicting_duplicate_registration_returns_409(client: TestClient, user_key) -> None:
    registered = register_identity(client, user_key)
    other_key = user_key
    payload = register_payload(other_key, hash_id=registered["hash_id"])
    payload["device_pubkey_fingerprint"] = sha256_hex("conflicting-fingerprint")

    response = client.post("/v1/did/register", json=payload, headers=bank_headers())

    assert response.status_code == 409
    assert "different public-key fingerprint" in response.json()["detail"]


def test_invalid_hash_format_is_rejected(client: TestClient, user_key) -> None:
    payload = register_payload(user_key)
    payload["hash_id"] = "not-a-sha256"

    response = client.post("/v1/did/register", json=payload, headers=bank_headers())

    assert response.status_code == 422


def test_forbidden_pii_like_fields_are_rejected(client: TestClient, user_key) -> None:
    payload = register_payload(user_key)
    payload["metadata"] = {"nin": "12345678901"}

    response = client.post("/v1/did/register", json=payload, headers=bank_headers())

    assert response.status_code == 422


def test_register_requires_bank_api_key(client: TestClient, user_key) -> None:
    response = client.post("/v1/did/register", json=register_payload(user_key))

    assert response.status_code == 401
    assert "valid bank API key required" in response.json()["detail"]


def test_batch_registration_registers_and_replays_idempotently(client: TestClient, user_key) -> None:
    batch = {
        "batch_id": "batch-test-001",
        "bank_id": "bank-a",
        "schema_version": "batch-registration-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "entries": [
            batch_entry(user_key, hash_id=sha256_hex("batch-user-1")),
            batch_entry(user_key, hash_id=sha256_hex("batch-user-2")),
        ],
    }

    response = client.post("/v1/did/register/batch", headers=bank_headers(), json=batch)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["received_count"] == 2
    assert body["registered_count"] == 2
    assert body["failed_count"] == 0
    assert {result["status"] for result in body["results"]} == {"registered"}

    replay_response = client.post("/v1/did/register/batch", headers=bank_headers(), json=batch)

    assert replay_response.status_code == 200, replay_response.text
    replay = replay_response.json()
    assert replay["status"] == "completed"
    assert replay["registered_count"] == 0
    assert replay["existing_count"] == 2
    assert {result["status"] for result in replay["results"]} == {"exists"}


def test_batch_registration_reports_partial_failures(client: TestClient, user_key) -> None:
    registered = register_identity(client, user_key)
    conflicting = batch_entry(user_key, hash_id=registered["hash_id"])
    conflicting["device_pubkey_fingerprint"] = sha256_hex("batch-conflict-fingerprint")
    batch = {
        "batch_id": "batch-test-partial",
        "bank_id": "bank-a",
        "schema_version": "batch-registration-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "entries": [
            conflicting,
            batch_entry(user_key, hash_id=sha256_hex("batch-user-success-after-conflict")),
        ],
    }

    response = client.post("/v1/did/register/batch", headers=bank_headers(), json=batch)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "partial"
    assert body["registered_count"] == 1
    assert body["failed_count"] == 1
    assert body["results"][0]["status"] == "failed"
    assert body["results"][0]["status_code"] == 409
    assert "different public-key fingerprint" in body["results"][0]["error"]
    assert body["results"][1]["status"] == "registered"


def test_batch_registration_requires_bank_api_key(client: TestClient, user_key) -> None:
    response = client.post(
        "/v1/did/register/batch",
        json={
            "batch_id": "batch-test-auth",
            "bank_id": "bank-a",
            "schema_version": "batch-registration-v1",
            "created_at": datetime.now(UTC).isoformat(),
            "entries": [batch_entry(user_key, hash_id=sha256_hex("batch-auth-user"))],
        },
    )

    assert response.status_code == 401
    assert "valid bank API key required" in response.json()["detail"]


def test_batch_registration_bank_id_must_match_api_key(client: TestClient, user_key) -> None:
    response = client.post(
        "/v1/did/register/batch",
        headers=bank_headers(bank_id="bank-a"),
        json={
            "batch_id": "batch-test-wrong-bank",
            "bank_id": "bank-b",
            "schema_version": "batch-registration-v1",
            "created_at": datetime.now(UTC).isoformat(),
            "entries": [batch_entry(user_key, hash_id=sha256_hex("batch-wrong-bank-user"))],
        },
    )

    assert response.status_code == 403
    assert "does not match request bank_id" in response.json()["detail"]


def test_batch_registration_rejects_pii_like_fields(client: TestClient, user_key) -> None:
    entry = batch_entry(user_key, hash_id=sha256_hex("batch-pii-user"))
    entry["metadata"] = {"bvn": "22233344455"}
    response = client.post(
        "/v1/did/register/batch",
        headers=bank_headers(),
        json={
            "batch_id": "batch-test-pii",
            "bank_id": "bank-a",
            "schema_version": "batch-registration-v1",
            "created_at": datetime.now(UTC).isoformat(),
            "entries": [entry],
        },
    )

    assert response.status_code == 422


def test_receipt_verification_success_and_failure(client: TestClient, user_key) -> None:
    registered = register_identity(client, user_key)
    receipt = registered["receipt"]

    valid_response = client.post(
        "/v1/did/receipt/verify",
        json={
            "receipt_id": receipt["receipt_id"],
            "payload": receipt["payload"],
            "signature": receipt["signature"],
            "key_id": receipt["key_id"],
        },
    )
    assert valid_response.status_code == 200
    assert valid_response.json()["valid"] is True

    invalid_response = client.post(
        "/v1/did/receipt/verify",
        json={
            "receipt_id": receipt["receipt_id"],
            "payload": {**receipt["payload"], "did": "did:tov:bad"},
            "signature": receipt["signature"],
            "key_id": receipt["key_id"],
        },
    )
    assert invalid_response.status_code == 200
    assert invalid_response.json()["valid"] is False


def test_current_registry_key_endpoint(client: TestClient) -> None:
    response = client.get("/v1/did/keys/current")

    assert response.status_code == 200
    body = response.json()
    assert body["key_id"]
    assert body["signature_algorithm"] == "ed25519"
    assert body["public_key_jwk"]["kty"] == "OKP"
    assert body["public_key_jwk"]["crv"] == "Ed25519"


def test_registry_keys_endpoint(client: TestClient) -> None:
    response = client.get("/v1/did/keys")

    assert response.status_code == 200
    body = response.json()
    assert len(body) >= 1
    assert any(key["status"] == "active" for key in body)


def test_attestation_upsert(client: TestClient, user_key) -> None:
    registered = register_identity(client, user_key)
    attestation_hash = sha256_hex("bank-a-account-evidence")
    response = client.post(
        "/v1/did/attest",
        headers=bank_headers(),
        json={
            "hash_id": registered["hash_id"],
            "bank_id": "bank-a",
            "attestation": sign_bank_attestation_payload(
                hash_id=registered["hash_id"],
                attestation_type="bank_account_seen",
                attestation_hash=attestation_hash,
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["attestation"]["bank_id"] == "bank-a"
    assert response.json()["attestation"]["signature_verified"] is True

    resolved = client.get(f"/v1/did/{registered['did']}").json()
    assert {att["attestation_type"] for att in resolved["attestations"]} == {"kyc_hash_seen", "bank_account_seen"}


def test_bank_api_key_must_match_request_bank_id(client: TestClient, user_key) -> None:
    registered = register_identity(client, user_key)
    response = client.post(
        "/v1/did/attest",
        headers=bank_headers(bank_id="bank-a"),
        json={
            "hash_id": registered["hash_id"],
            "bank_id": "bank-b",
            "attestation": sign_bank_attestation_payload(
                hash_id=registered["hash_id"],
                bank_id="bank-b",
                attestation_type="bank_account_seen",
                attestation_hash=sha256_hex("bank-b-account-evidence"),
            ),
        },
    )

    assert response.status_code == 403
    assert "does not match request bank_id" in response.json()["detail"]


def test_invalid_bank_attestation_signature_is_rejected(client: TestClient, user_key) -> None:
    registered = register_identity(client, user_key)
    attestation = sign_bank_attestation_payload(
        hash_id=registered["hash_id"],
        attestation_type="bank_account_seen",
        attestation_hash=sha256_hex("bank-a-account-evidence"),
    )
    attestation["signature"] = b64url(b"invalid-signature")

    response = client.post(
        "/v1/did/attest",
        headers=bank_headers(),
        json={"hash_id": registered["hash_id"], "bank_id": "bank-a", "attestation": attestation},
    )

    assert response.status_code == 400
    assert "invalid_bank_signature" in response.json()["detail"]


def test_attestation_revoke_and_audit_export(client: TestClient, user_key) -> None:
    registered = register_identity(client, user_key)
    revoke_response = client.post(
        "/v1/did/attest/revoke",
        headers=bank_headers(),
        json=sign_bank_revocation_payload(hash_id=registered["hash_id"]),
    )

    assert revoke_response.status_code == 200
    assert revoke_response.json()["attestation"]["revoked_at"] is not None

    resolved = client.get(f"/v1/did/{registered['did']}").json()
    assert resolved["attestations"] == []

    audit_response = client.get(f"/v1/did/attest/{registered['hash_id']}/audit", headers=admin_headers())
    assert audit_response.status_code == 200
    audit = audit_response.json()
    assert audit["hash_id"] == registered["hash_id"]
    assert audit["attestations"][0]["signature_verified"] is True
    assert audit["attestations"][0]["revoked_at"] is not None
    assert audit["attestations"][0]["signature"]


def test_attestation_audit_requires_admin_api_key(client: TestClient, user_key) -> None:
    registered = register_identity(client, user_key)
    response = client.get(f"/v1/did/attest/{registered['hash_id']}/audit")

    assert response.status_code == 401
    assert "valid admin API key required" in response.json()["detail"]


def test_action_challenge_requires_matching_bank_api_key(client: TestClient, user_key) -> None:
    registered = register_identity(client, user_key)
    response = client.post(
        "/v1/did/actions/challenge",
        headers=bank_headers(bank_id="bank-a"),
        json={
            "did": registered["did"],
            "bank_id": "bank-b",
            "action_type": "document_signature",
            "document_hash": sha256_hex("document-bytes"),
            "requested_attestation": {"level": "instant", "methods": ["passkey"], "max_age_seconds": 300},
            "policy_version": "bank-b-actions-v1",
        },
    )

    assert response.status_code == 403
    assert "does not match request bank_id" in response.json()["detail"]


def test_passkey_only_action_can_be_approved(client: TestClient, user_key) -> None:
    private_key, _, _, _ = user_key
    registered = register_identity(client, user_key)
    challenge_response = client.post(
        "/v1/did/actions/challenge",
        headers=bank_headers(),
        json={
            "did": registered["did"],
            "bank_id": "bank-a",
            "action_type": "document_signature",
            "document_hash": sha256_hex("document-bytes"),
            "requested_attestation": {"level": "instant", "methods": ["passkey"], "max_age_seconds": 300},
            "policy_version": "bank-a-actions-v1",
        },
    )
    assert challenge_response.status_code == 200
    challenge = challenge_response.json()

    submit_response = client.post(
        "/v1/did/actions/submit",
        json={
            "action_id": challenge["action_id"],
            "signature": sign_challenge(private_key, challenge["challenge_hash"]),
            "signed_at": datetime.now(UTC).isoformat(),
        },
    )

    assert submit_response.status_code == 200
    body = submit_response.json()
    assert body["status"] == "approved"
    assert body["verification_result"]["signature_valid"] is True


def test_camera_liveness_policy_rejects_missing_attestation(client: TestClient, user_key) -> None:
    private_key, _, _, _ = user_key
    registered = register_identity(client, user_key)
    challenge = client.post(
        "/v1/did/actions/challenge",
        headers=bank_headers(),
        json={
            "did": registered["did"],
            "bank_id": "bank-a",
            "action_type": "mandate_approval",
            "document_hash": sha256_hex("mandate"),
            "requested_attestation": {
                "level": "aal3",
                "methods": ["passkey", "bank_handshake", "camera_liveness"],
                "max_age_seconds": 300,
            },
            "policy_version": "bank-a-actions-v1",
        },
    ).json()

    submit_response = client.post(
        "/v1/did/actions/submit",
        json={
            "action_id": challenge["action_id"],
            "bank_credential_id": "bankcred_123",
            "signature": sign_challenge(private_key, challenge["challenge_hash"]),
        },
    )

    assert submit_response.status_code == 200
    body = submit_response.json()
    assert body["status"] == "rejected"
    assert body["verification_result"]["attestation_policy_satisfied"] is False


def test_camera_liveness_policy_can_be_approved(client: TestClient, user_key) -> None:
    private_key, _, _, _ = user_key
    registered = register_identity(client, user_key)
    challenge = client.post(
        "/v1/did/actions/challenge",
        headers=bank_headers(),
        json={
            "did": registered["did"],
            "bank_id": "bank-a",
            "action_type": "mandate_approval",
            "media_hash": sha256_hex("video-proof-envelope"),
            "requested_attestation": {
                "level": "aal3",
                "methods": ["passkey", "bank_handshake", "camera_liveness"],
                "max_age_seconds": 300,
            },
            "policy_version": "bank-a-actions-v1",
        },
    ).json()

    submit_response = client.post(
        "/v1/did/actions/submit",
        json={
            "action_id": challenge["action_id"],
            "bank_credential_id": "bankcred_123",
            "signature": sign_challenge(private_key, challenge["challenge_hash"]),
            "attestations": [
                {
                    **sign_action_attestation_payload(
                        action_id=challenge["action_id"],
                        did=registered["did"],
                        hash_id=registered["hash_id"],
                        evidence_hash=sha256_hex("provider-held-evidence"),
                        expires_at=datetime.now(UTC) + timedelta(minutes=5),
                    )
                },
            ],
        },
    )

    assert submit_response.status_code == 200
    body = submit_response.json()
    assert body["status"] == "approved"
    assert body["verification_result"]["bank_credential_valid"] is True
    assert body["verification_result"]["attestation_signatures_valid"] is True
    assert body["verification_result"]["attestation_policy_satisfied"] is True


def test_camera_liveness_policy_rejects_invalid_provider_signature(client: TestClient, user_key) -> None:
    private_key, _, _, _ = user_key
    registered = register_identity(client, user_key)
    challenge = client.post(
        "/v1/did/actions/challenge",
        headers=bank_headers(),
        json={
            "did": registered["did"],
            "bank_id": "bank-a",
            "action_type": "mandate_approval",
            "media_hash": sha256_hex("video-proof-envelope"),
            "requested_attestation": {
                "level": "aal3",
                "methods": ["passkey", "bank_handshake", "camera_liveness"],
                "max_age_seconds": 300,
            },
            "policy_version": "bank-a-actions-v1",
        },
    ).json()
    attestation = sign_action_attestation_payload(
        action_id=challenge["action_id"],
        did=registered["did"],
        hash_id=registered["hash_id"],
        evidence_hash=sha256_hex("provider-held-evidence"),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    attestation["signature"] = b64url(b"invalid-provider-signature")

    submit_response = client.post(
        "/v1/did/actions/submit",
        json={
            "action_id": challenge["action_id"],
            "bank_credential_id": "bankcred_123",
            "signature": sign_challenge(private_key, challenge["challenge_hash"]),
            "attestations": [attestation],
        },
    )

    assert submit_response.status_code == 200
    body = submit_response.json()
    assert body["status"] == "rejected"
    assert body["verification_result"]["attestation_signatures_valid"] is False


def test_health_reports_registry_ready(client: TestClient) -> None:
    response = client.get("/v1/did/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["registry_tables"] is True
