import hashlib
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.services.anchors import merkle_proof, merkle_root, verify_merkle_proof
from tests.helpers import admin_headers, b64url
from tests.test_registry import register_identity


def test_merkle_root_and_proof_round_trip() -> None:
    leaves = [
        "00" * 32,
        "11" * 32,
        "22" * 32,
    ]
    root = merkle_root(leaves)
    proof = merkle_proof(leaves, leaves[1])

    assert root != leaves[1]
    assert verify_merkle_proof(payload_hash=leaves[1], proof=proof.steps, merkle_root_hash=root) is True
    assert verify_merkle_proof(payload_hash=leaves[2], proof=proof.steps, merkle_root_hash=root) is False


def _user_key() -> tuple[ed25519.Ed25519PrivateKey, dict[str, str], str, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(public_bytes)}
    credential_id = b64url(public_bytes)
    fingerprint = hashlib.sha256(public_bytes).hexdigest()
    return private_key, jwk, credential_id, fingerprint


def test_anchor_create_and_receipt_proof(client) -> None:
    user_key = _user_key()
    registered = register_identity(client, user_key)
    receipt_id = registered["receipt"]["receipt_id"]
    window_start = datetime.now(UTC) - timedelta(minutes=5)
    window_end = datetime.now(UTC) + timedelta(minutes=5)

    anchor_response = client.post(
        "/v1/did/anchors",
        headers=admin_headers(),
        json={
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "anchor_network": "internal",
            "anchor_txid": "anchor-placeholder",
        },
    )

    assert anchor_response.status_code == 200, anchor_response.text
    anchor = anchor_response.json()
    assert anchor["hash_count"] == 1
    assert anchor["merkle_root"] == registered["receipt"]["payload_hash"]

    proof_response = client.get(f"/v1/did/anchors/{anchor['anchor_id']}/proof/{receipt_id}")
    assert proof_response.status_code == 200
    proof = proof_response.json()
    assert proof["verified"] is True
    assert proof["payload_hash"] == registered["receipt"]["payload_hash"]
    assert proof["proof"] == []


def test_anchor_rejects_empty_window(client) -> None:
    now = datetime.now(UTC)
    response = client.post(
        "/v1/did/anchors",
        headers=admin_headers(),
        json={
            "window_start": (now - timedelta(days=2)).isoformat(),
            "window_end": (now - timedelta(days=1)).isoformat(),
        },
    )

    assert response.status_code == 400
    assert "empty receipt window" in response.json()["detail"]


def test_anchor_create_requires_admin_api_key(client) -> None:
    now = datetime.now(UTC)
    response = client.post(
        "/v1/did/anchors",
        json={
            "window_start": (now - timedelta(minutes=5)).isoformat(),
            "window_end": now.isoformat(),
        },
    )

    assert response.status_code == 401
    assert "valid admin API key required" in response.json()["detail"]
