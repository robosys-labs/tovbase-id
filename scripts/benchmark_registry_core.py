from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from datetime import UTC, datetime
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
from app.schemas import BankAttestationInput  # noqa: E402
from app.services.api_keys import hash_api_key  # noqa: E402
from app.services.bank_keys import bank_attestation_envelope  # noqa: E402
from app.services.crypto import canonical_json_bytes  # noqa: E402

BENCHMARK_BANK_API_KEY = "benchmark-bank-api-key"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sha256_hex(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]


def _key_jwk(private_key: ed25519.Ed25519PrivateKey) -> dict[str, str]:
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(public_bytes)}


def _bank_headers(bank_id: str) -> dict[str, str]:
    return {
        "X-Tovbase-Bank-Id": bank_id,
        "X-Tovbase-Api-Key": BENCHMARK_BANK_API_KEY,
    }


def _configure_auth_and_bank_key(
    *,
    bank_id: str,
    bank_key_id: str,
    bank_public_jwk: dict[str, str],
) -> None:
    settings.bank_api_keys_json = json.dumps(
        [
            {
                "bank_id": bank_id,
                "key_id": f"{bank_id}-api-benchmark",
                "api_key_hash": hash_api_key(BENCHMARK_BANK_API_KEY),
                "status": "active",
            }
        ]
    )
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


def _signed_bank_attestation(
    *,
    bank_private_key: ed25519.Ed25519PrivateKey,
    hash_id: str,
    bank_id: str,
    bank_key_id: str,
    attestation_type: str,
    evidence: str,
) -> dict:
    issued_at = datetime.now(UTC).replace(microsecond=0)
    attestation = BankAttestationInput(
        attestation_type=attestation_type,
        attestation_hash=sha256_hex(evidence),
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


def _register_identity(
    *,
    client: TestClient,
    bank_private_key: ed25519.Ed25519PrivateKey,
    bank_id: str,
    bank_key_id: str,
    sequence: int,
) -> dict:
    user_private_key = ed25519.Ed25519PrivateKey.generate()
    user_public_bytes = user_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    hash_id = sha256_hex(f"registry-core-benchmark-{sequence}-{time.time_ns()}")
    response = client.post(
        "/v1/did/register",
        headers=_bank_headers(bank_id),
        json={
            "hash_id": hash_id,
            "hash_algorithm": "sha256",
            "hash_encoding": "hex",
            "sdk_version": "benchmark/0.1.0",
            "webauthn_credential_id": b64url(hashlib.sha256(user_public_bytes + b"credential").digest()),
            "webauthn_public_key": _key_jwk(user_private_key),
            "device_pubkey_fingerprint": sha256_hex(user_public_bytes),
            "bank_id": bank_id,
            "bank_attestation": _signed_bank_attestation(
                bank_private_key=bank_private_key,
                hash_id=hash_id,
                bank_id=bank_id,
                bank_key_id=bank_key_id,
                attestation_type="kyc_hash_seen",
                evidence=f"benchmark-registration-evidence-{sequence}",
            ),
        },
    )
    response.raise_for_status()
    return response.json()


def _time_call(call) -> tuple[float, object]:
    started = time.perf_counter()
    result = call()
    return time.perf_counter() - started, result


def run_benchmark(*, iterations: int = 10) -> dict[str, object]:
    bank_id = "bank-a"
    bank_key_id = "bank-a-signing-benchmark"
    bank_private_key = ed25519.Ed25519PrivateKey.generate()
    _configure_auth_and_bank_key(
        bank_id=bank_id,
        bank_key_id=bank_key_id,
        bank_public_jwk=_key_jwk(bank_private_key),
    )

    Base.metadata.drop_all(bind=engine)
    init_db()
    timings: dict[str, list[float]] = {
        "register": [],
        "resolve_by_did": [],
        "resolve_by_hash": [],
        "receipt_verify": [],
        "attestation_upsert": [],
    }

    with TestClient(app) as client:
        for sequence in range(iterations):
            elapsed, registered = _time_call(
                lambda sequence=sequence: _register_identity(
                    client=client,
                    bank_private_key=bank_private_key,
                    bank_id=bank_id,
                    bank_key_id=bank_key_id,
                    sequence=sequence,
                )
            )
            timings["register"].append(elapsed)

            elapsed, did_response = _time_call(lambda registered=registered: client.get(f"/v1/did/{registered['did']}"))
            did_response.raise_for_status()
            timings["resolve_by_did"].append(elapsed)

            elapsed, hash_response = _time_call(
                lambda registered=registered: client.get(f"/v1/did/hash/{registered['hash_id']}")
            )
            hash_response.raise_for_status()
            timings["resolve_by_hash"].append(elapsed)

            receipt = registered["receipt"]
            elapsed, verify_response = _time_call(
                lambda receipt=receipt: client.post(
                    "/v1/did/receipt/verify",
                    json={
                        "receipt_id": receipt["receipt_id"],
                        "payload": receipt["payload"],
                        "signature": receipt["signature"],
                        "key_id": receipt["key_id"],
                    },
                )
            )
            verify_response.raise_for_status()
            timings["receipt_verify"].append(elapsed)

            elapsed, attest_response = _time_call(
                lambda registered=registered, sequence=sequence: client.post(
                    "/v1/did/attest",
                    headers=_bank_headers(bank_id),
                    json={
                        "hash_id": registered["hash_id"],
                        "bank_id": bank_id,
                        "attestation": _signed_bank_attestation(
                            bank_private_key=bank_private_key,
                            hash_id=registered["hash_id"],
                            bank_id=bank_id,
                            bank_key_id=bank_key_id,
                            attestation_type="bank_account_seen",
                            evidence=f"benchmark-account-evidence-{sequence}",
                        ),
                    },
                )
            )
            attest_response.raise_for_status()
            timings["attestation_upsert"].append(elapsed)

    metrics = {
        name: {
            "median_seconds": median(values),
            "p95_seconds": _percentile(values, 0.95),
        }
        for name, values in timings.items()
    }
    return {
        "iterations": iterations,
        "metrics": metrics,
        "target_pass": metrics["register"]["p95_seconds"] < 0.075
        and metrics["resolve_by_did"]["p95_seconds"] < 0.02
        and metrics["resolve_by_hash"]["p95_seconds"] < 0.02
        and metrics["receipt_verify"]["p95_seconds"] < 0.02
        and metrics["attestation_upsert"]["p95_seconds"] < 0.075,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Tovbase ID registry-core API paths.")
    parser.add_argument("--iterations", type=int, default=10)
    args = parser.parse_args()
    print(json.dumps(run_benchmark(iterations=args.iterations), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
