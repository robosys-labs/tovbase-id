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


def generate_key_material(key_id: str, node_id: str) -> dict[str, object]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "node_id": node_id,
        "key_id": key_id,
        "signature_algorithm": "ed25519",
        "env": {
            "DID_NODE_ID": node_id,
            "DID_SIGNING_KEY_ID": key_id,
            "DID_SIGNING_PRIVATE_KEY_B64": b64url_encode(private_bytes),
        },
        "public_key_jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url_encode(public_bytes),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a Tovbase ID Ed25519 receipt-signing key.")
    parser.add_argument("--key-id", default="tovbase-registry-dev-1")
    parser.add_argument("--node-id", default="tovbase-id-dev-1")
    args = parser.parse_args()
    print(json.dumps(generate_key_material(args.key_id, args.node_id), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
