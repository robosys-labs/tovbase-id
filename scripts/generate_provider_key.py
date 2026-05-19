from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.crypto import b64url_encode  # noqa: E402


def generate_provider_key_material(provider_id: str, key_id: str) -> dict[str, object]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_key_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(public_bytes)}
    trusted_key_record = {
        "provider_id": provider_id,
        "key_id": key_id,
        "signature_algorithm": "ed25519",
        "public_key_jwk": public_key_jwk,
        "status": "active",
    }
    return {
        "provider_id": provider_id,
        "key_id": key_id,
        "signature_algorithm": "ed25519",
        "provider_private_key_b64": b64url_encode(private_bytes),
        "trusted_key_record": trusted_key_record,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an Ed25519 action/liveness attestation provider key.")
    parser.add_argument("--provider-id", required=True)
    parser.add_argument("--key-id", required=True)
    args = parser.parse_args()
    print(json.dumps(generate_provider_key_material(args.provider_id, args.key_id), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
