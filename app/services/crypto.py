from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.config import settings


def utc_now() -> datetime:
    return datetime.now(UTC)


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}")


def sha256_hex(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): json_safe(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [json_safe(nested) for nested in value]
    return value


def canonical_json_bytes(value: Any) -> bytes:
    safe_value = json_safe(value)
    return json.dumps(safe_value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _public_key_from_jwk(public_key_jwk: dict[str, Any]) -> ed25519.Ed25519PublicKey:
    if public_key_jwk.get("kty") != "OKP" or public_key_jwk.get("crv") != "Ed25519":
        raise ValueError("only Ed25519 OKP JWK registry keys are supported")
    return ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(str(public_key_jwk["x"])))


class RegistrySigner:
    def __init__(
        self,
        *,
        key_id: str | None = None,
        node_id: str | None = None,
        private_key_b64: str | None = None,
        verifying_keys_json: str | None = None,
    ) -> None:
        self.key_id = key_id or settings.did_signing_key_id
        self.node_id = node_id or settings.did_node_id
        self.signature_algorithm = "ed25519"
        private_key_b64 = settings.did_signing_private_key_b64 if private_key_b64 is None else private_key_b64
        if private_key_b64:
            private_bytes = b64url_decode(private_key_b64)
            self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        else:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._verifying_keys = self._load_verifying_keys(
            settings.did_verifying_keys_json if verifying_keys_json is None else verifying_keys_json
        )
        self._verifying_keys[self.key_id] = self.public_key_jwk

    @property
    def public_key_jwk(self) -> dict[str, str]:
        public_bytes = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(public_bytes)}

    @staticmethod
    def _load_verifying_keys(value: str) -> dict[str, dict[str, Any]]:
        if not value:
            return {}
        parsed = json.loads(value)
        records = parsed.values() if isinstance(parsed, dict) else parsed
        keyring: dict[str, dict[str, Any]] = {}
        for record in records:
            key_id = record["key_id"]
            public_key_jwk = record["public_key_jwk"]
            _public_key_from_jwk(public_key_jwk)
            keyring[key_id] = public_key_jwk
        return keyring

    def public_keys(self) -> list[dict[str, Any]]:
        return [
            {
                "node_id": self.node_id,
                "key_id": key_id,
                "signature_algorithm": self.signature_algorithm,
                "public_key_jwk": public_key_jwk,
                "status": "active" if key_id == self.key_id else "verify_only",
            }
            for key_id, public_key_jwk in sorted(self._verifying_keys.items())
        ]

    def sign_payload(self, payload: dict[str, Any]) -> tuple[str, str]:
        payload_bytes = canonical_json_bytes(payload)
        payload_hash = sha256_hex(payload_bytes)
        signature = self._private_key.sign(payload_bytes)
        return payload_hash, b64url_encode(signature)

    def verify_payload(self, payload: dict[str, Any], signature: str, key_id: str) -> bool:
        public_key_jwk = self._verifying_keys.get(key_id)
        if public_key_jwk is None:
            return False
        try:
            public_key = _public_key_from_jwk(public_key_jwk)
            public_key.verify(b64url_decode(signature), canonical_json_bytes(payload))
        except (InvalidSignature, ValueError):
            return False
        return True


registry_signer = RegistrySigner()


def verify_detached_signature(public_jwk: dict[str, Any], message: bytes, signature: str) -> bool:
    """Verify a compact detached signature over the provided bytes.

    v1 uses this lightweight proof-of-control path for backend tests and early
    SDK work. Full WebAuthn ceremony verification remains a later integration
    layer around the same challenge hash.
    """

    try:
        signature_bytes = b64url_decode(signature)
    except ValueError:
        return False

    kty = public_jwk.get("kty")
    crv = public_jwk.get("crv")

    try:
        if kty == "OKP" and crv == "Ed25519":
            public_bytes = b64url_decode(str(public_jwk["x"]))
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
            public_key.verify(signature_bytes, message)
            return True

        if kty == "EC" and crv in {"P-256", "secp256r1"}:
            x = int.from_bytes(b64url_decode(str(public_jwk["x"])), "big")
            y = int.from_bytes(b64url_decode(str(public_jwk["y"])), "big")
            public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
            if len(signature_bytes) == 64:
                r = int.from_bytes(signature_bytes[:32], "big")
                s = int.from_bytes(signature_bytes[32:], "big")
                signature_bytes = utils.encode_dss_signature(r, s)
            public_key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
            return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False

    return False
