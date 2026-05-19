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
    return {
        "hash_id": hash_id or sha256_hex("sdk-local-canonical-identity"),
        "hash_algorithm": "sha256",
        "hash_encoding": "hex",
        "sdk_version": "tovbase-js/0.1.0",
        "webauthn_credential_id": credential_id,
        "webauthn_public_key": jwk,
        "device_pubkey_fingerprint": fingerprint,
        "bank_id": "bank-a",
        "bank_attestation": {
            "attestation_type": "kyc_hash_seen",
            "attestation_hash": sha256_hex("bank-a-evidence"),
            "issued_at": datetime.now(UTC).isoformat(),
            "key_id": "bank-a-signing-1",
            "signature": b64url(b"bank-signature"),
            "payload": {},
        },
        "metadata": {"schema_version": "kyc-ng-v1"},
    }


def register_identity(client: TestClient, user_key: tuple[ed25519.Ed25519PrivateKey, dict[str, str], str, str]) -> dict:
    response = client.post("/v1/did/register", json=register_payload(user_key))
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

    hash_response = client.get(f"/v1/did/hash/{registered['hash_id']}")
    assert hash_response.status_code == 200
    assert hash_response.json()["did"] == registered["did"]


def test_duplicate_registration_is_idempotent(client: TestClient, user_key) -> None:
    first = register_identity(client, user_key)
    second_response = client.post("/v1/did/register", json=register_payload(user_key))

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

    response = client.post("/v1/did/register", json=payload)

    assert response.status_code == 409
    assert "different public-key fingerprint" in response.json()["detail"]


def test_invalid_hash_format_is_rejected(client: TestClient, user_key) -> None:
    payload = register_payload(user_key)
    payload["hash_id"] = "not-a-sha256"

    response = client.post("/v1/did/register", json=payload)

    assert response.status_code == 422


def test_forbidden_pii_like_fields_are_rejected(client: TestClient, user_key) -> None:
    payload = register_payload(user_key)
    payload["metadata"] = {"nin": "12345678901"}

    response = client.post("/v1/did/register", json=payload)

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
    response = client.post(
        "/v1/did/attest",
        json={
            "hash_id": registered["hash_id"],
            "bank_id": "bank-b",
            "attestation": {
                "attestation_type": "kyc_hash_seen",
                "attestation_hash": sha256_hex("bank-b-evidence"),
                "issued_at": datetime.now(UTC).isoformat(),
                "key_id": "bank-b-signing-1",
                "signature": b64url(b"bank-b-signature"),
                "payload": {},
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["attestation"]["bank_id"] == "bank-b"

    resolved = client.get(f"/v1/did/{registered['did']}").json()
    assert {att["bank_id"] for att in resolved["attestations"]} == {"bank-a", "bank-b"}


def test_passkey_only_action_can_be_approved(client: TestClient, user_key) -> None:
    private_key, _, _, _ = user_key
    registered = register_identity(client, user_key)
    challenge_response = client.post(
        "/v1/did/actions/challenge",
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
                    "attestation_type": "camera_liveness",
                    "provider_id": "bank-a-liveness",
                    "evidence_hash": sha256_hex("provider-held-evidence"),
                    "result": "passed",
                    "issued_at": datetime.now(UTC).isoformat(),
                    "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                    "key_id": "bank-a-liveness-1",
                    "signature": b64url(b"liveness-signature"),
                    "payload": {},
                }
            ],
        },
    )

    assert submit_response.status_code == 200
    body = submit_response.json()
    assert body["status"] == "approved"
    assert body["verification_result"]["bank_credential_valid"] is True
    assert body["verification_result"]["attestation_policy_satisfied"] is True


def test_health_reports_registry_ready(client: TestClient) -> None:
    response = client.get("/v1/did/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["registry_tables"] is True
