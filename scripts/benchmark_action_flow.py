from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import median

os.environ.setdefault("DATABASE_URL", "sqlite://")

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.db import Base, engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.schemas import ActionAttestationInput, BankAttestationInput  # noqa: E402
from app.services.bank_keys import bank_attestation_envelope  # noqa: E402
from app.services.crypto import canonical_json_bytes  # noqa: E402
from app.services.provider_keys import action_attestation_envelope  # noqa: E402


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sha256_hex(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _key_jwk(private_key: ed25519.Ed25519PrivateKey) -> dict[str, str]:
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(public_bytes)}


def _configure_trusted_keys(
    *,
    bank_public_jwk: dict[str, str],
    provider_public_jwk: dict[str, str],
    bank_id: str,
    bank_key_id: str,
    provider_id: str,
    provider_key_id: str,
) -> None:
    settings.trusted_bank_keys_json = json.dumps(
        [
            {
                "bank_id": bank_id,
                "key_id": bank_key_id,
                "signature_algorithm": "ed25519",
                "public_key_jwk": bank_public_jwk,
                "status": "active",
            }
        ]
    )
    settings.trusted_attestation_provider_keys_json = json.dumps(
        [
            {
                "provider_id": provider_id,
                "key_id": provider_key_id,
                "signature_algorithm": "ed25519",
                "public_key_jwk": provider_public_jwk,
                "status": "active",
            }
        ]
    )


def _signed_bank_attestation(
    *,
    bank_private_key: ed25519.Ed25519PrivateKey,
    hash_id: str,
    bank_id: str,
    bank_key_id: str,
) -> dict:
    issued_at = datetime.now(UTC).replace(microsecond=0)
    attestation_hash = sha256_hex("benchmark-bank-evidence")
    attestation = BankAttestationInput(
        attestation_type="kyc_hash_seen",
        attestation_hash=attestation_hash,
        issued_at=issued_at,
        key_id=bank_key_id,
        signature="pending",
        payload={"benchmark": True},
    )
    envelope = bank_attestation_envelope(hash_id=hash_id, bank_id=bank_id, attestation=attestation)
    return {
        "attestation_type": attestation.attestation_type,
        "attestation_hash": attestation.attestation_hash,
        "issued_at": issued_at.isoformat(),
        "key_id": bank_key_id,
        "signature": b64url(bank_private_key.sign(canonical_json_bytes(envelope))),
        "payload": attestation.payload,
    }


def _signed_action_attestation(
    *,
    provider_private_key: ed25519.Ed25519PrivateKey,
    action_id: str,
    did: str,
    hash_id: str,
    bank_id: str,
    provider_id: str,
    provider_key_id: str,
) -> dict:
    issued_at = datetime.now(UTC).replace(microsecond=0)
    expires_at = issued_at + timedelta(minutes=5)
    attestation = ActionAttestationInput(
        attestation_type="camera_liveness",
        provider_id=provider_id,
        evidence_hash=sha256_hex("benchmark-provider-held-evidence"),
        result="passed",
        issued_at=issued_at,
        expires_at=expires_at,
        key_id=provider_key_id,
        signature="pending",
        payload={"benchmark": True},
    )
    envelope = action_attestation_envelope(
        action_id=action_id,
        did=did,
        hash_id=hash_id,
        bank_id=bank_id,
        attestation=attestation,
    )
    return {
        "attestation_type": attestation.attestation_type,
        "provider_id": attestation.provider_id,
        "evidence_hash": attestation.evidence_hash,
        "result": attestation.result,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "key_id": provider_key_id,
        "signature": b64url(provider_private_key.sign(canonical_json_bytes(envelope))),
        "payload": attestation.payload,
    }


def _register_identity(
    *,
    client: TestClient,
    user_public_jwk: dict[str, str],
    user_public_bytes: bytes,
    bank_private_key: ed25519.Ed25519PrivateKey,
    bank_id: str,
    bank_key_id: str,
) -> dict:
    hash_id = sha256_hex(f"benchmark-identity-{time.time_ns()}")
    credential_id = b64url(hashlib.sha256(user_public_bytes + b"credential").digest())
    response = client.post(
        "/v1/did/register",
        json={
            "hash_id": hash_id,
            "hash_algorithm": "sha256",
            "hash_encoding": "hex",
            "sdk_version": "benchmark/0.1.0",
            "webauthn_credential_id": credential_id,
            "webauthn_public_key": user_public_jwk,
            "device_pubkey_fingerprint": sha256_hex(user_public_bytes),
            "bank_id": bank_id,
            "bank_attestation": _signed_bank_attestation(
                bank_private_key=bank_private_key,
                hash_id=hash_id,
                bank_id=bank_id,
                bank_key_id=bank_key_id,
            ),
        },
    )
    response.raise_for_status()
    return response.json()


def _sign_user_challenge(private_key: ed25519.Ed25519PrivateKey, challenge_hash: str) -> str:
    return b64url(private_key.sign(bytes.fromhex(challenge_hash)))


def _action_round_trip(
    *,
    client: TestClient,
    registered: dict,
    user_private_key: ed25519.Ed25519PrivateKey,
    provider_private_key: ed25519.Ed25519PrivateKey,
    bank_id: str,
    provider_id: str,
    provider_key_id: str,
    liveness: bool,
    provider_latency_seconds: float,
) -> dict[str, float | str | bool]:
    challenge_started = time.perf_counter()
    challenge = client.post(
        "/v1/did/actions/challenge",
        json={
            "did": registered["did"],
            "bank_id": bank_id,
            "action_type": "mandate_approval" if liveness else "document_signature",
            "document_hash": sha256_hex("benchmark-document"),
            "requested_attestation": {
                "level": "aal3" if liveness else "instant",
                "methods": ["passkey", "bank_handshake", "camera_liveness"] if liveness else ["passkey"],
                "max_age_seconds": 300,
            },
            "policy_version": "benchmark-v1",
        },
    )
    challenge.raise_for_status()
    challenge_body = challenge.json()

    attestations = []
    if liveness:
        time.sleep(provider_latency_seconds)
        attestations.append(
            _signed_action_attestation(
                provider_private_key=provider_private_key,
                action_id=challenge_body["action_id"],
                did=registered["did"],
                hash_id=registered["hash_id"],
                bank_id=bank_id,
                provider_id=provider_id,
                provider_key_id=provider_key_id,
            )
        )

    submit_started = time.perf_counter()
    submit = client.post(
        "/v1/did/actions/submit",
        json={
            "action_id": challenge_body["action_id"],
            "bank_credential_id": "bankcred_benchmark" if liveness else None,
            "signature": _sign_user_challenge(user_private_key, challenge_body["challenge_hash"]),
            "attestations": attestations,
        },
    )
    submit.raise_for_status()
    submit_body = submit.json()
    finished = time.perf_counter()
    return {
        "status": submit_body["status"],
        "approved": submit_body["status"] == "approved",
        "total_seconds": finished - challenge_started,
        "backend_submit_seconds": finished - submit_started,
    }


def run_benchmark(*, iterations: int = 5, provider_latency_seconds: float = 0.0) -> dict[str, object]:
    bank_id = "bank-a"
    bank_key_id = "bank-a-signing-benchmark"
    provider_id = "bank-a-liveness"
    provider_key_id = "bank-a-liveness-benchmark"
    bank_private_key = ed25519.Ed25519PrivateKey.generate()
    provider_private_key = ed25519.Ed25519PrivateKey.generate()
    user_private_key = ed25519.Ed25519PrivateKey.generate()
    user_public_bytes = user_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    user_public_jwk = _key_jwk(user_private_key)
    _configure_trusted_keys(
        bank_public_jwk=_key_jwk(bank_private_key),
        provider_public_jwk=_key_jwk(provider_private_key),
        bank_id=bank_id,
        bank_key_id=bank_key_id,
        provider_id=provider_id,
        provider_key_id=provider_key_id,
    )

    Base.metadata.drop_all(bind=engine)
    init_db()
    instant_results = []
    liveness_results = []
    with TestClient(app) as client:
        for _ in range(iterations):
            registered = _register_identity(
                client=client,
                user_public_jwk=user_public_jwk,
                user_public_bytes=user_public_bytes,
                bank_private_key=bank_private_key,
                bank_id=bank_id,
                bank_key_id=bank_key_id,
            )
            instant_results.append(
                _action_round_trip(
                    client=client,
                    registered=registered,
                    user_private_key=user_private_key,
                    provider_private_key=provider_private_key,
                    bank_id=bank_id,
                    provider_id=provider_id,
                    provider_key_id=provider_key_id,
                    liveness=False,
                    provider_latency_seconds=0,
                )
            )
            liveness_results.append(
                _action_round_trip(
                    client=client,
                    registered=registered,
                    user_private_key=user_private_key,
                    provider_private_key=provider_private_key,
                    bank_id=bank_id,
                    provider_id=provider_id,
                    provider_key_id=provider_key_id,
                    liveness=True,
                    provider_latency_seconds=provider_latency_seconds,
                )
            )

    instant_seconds = [float(result["total_seconds"]) for result in instant_results]
    liveness_seconds = [float(result["total_seconds"]) for result in liveness_results]
    backend_submit_seconds = [float(result["backend_submit_seconds"]) for result in liveness_results]
    return {
        "iterations": iterations,
        "provider_latency_seconds": provider_latency_seconds,
        "instant_median_seconds": median(instant_seconds),
        "liveness_median_seconds": median(liveness_seconds),
        "liveness_backend_submit_median_seconds": median(backend_submit_seconds),
        "all_instant_approved": all(bool(result["approved"]) for result in instant_results),
        "all_liveness_approved": all(bool(result["approved"]) for result in liveness_results),
        "target_pass": median(instant_seconds) < 3
        and median(liveness_seconds) < 30
        and all(bool(result["approved"]) for result in instant_results + liveness_results),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Tovbase ID signed action flows.")
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--provider-latency-seconds", type=float, default=0.0)
    args = parser.parse_args()
    print(
        json.dumps(
            run_benchmark(iterations=args.iterations, provider_latency_seconds=args.provider_latency_seconds),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
