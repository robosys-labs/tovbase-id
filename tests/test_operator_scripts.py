import json
import re

from app.services.crypto import RegistrySigner
from scripts.generate_bank_key import generate_bank_key_material
from scripts.generate_signing_key import generate_key_material


def test_generate_signing_key_outputs_env_and_public_jwk() -> None:
    material = generate_key_material("test-key", "test-node")

    assert material["key_id"] == "test-key"
    assert material["node_id"] == "test-node"
    assert material["signature_algorithm"] == "ed25519"
    assert material["env"]["DID_SIGNING_KEY_ID"] == "test-key"
    assert material["env"]["DID_NODE_ID"] == "test-node"
    assert re.fullmatch(r"[A-Za-z0-9_-]+", material["env"]["DID_SIGNING_PRIVATE_KEY_B64"])
    assert material["public_key_jwk"]["kty"] == "OKP"
    assert material["public_key_jwk"]["crv"] == "Ed25519"
    assert re.fullmatch(r"[A-Za-z0-9_-]+", material["public_key_jwk"]["x"])
    assert material["verifying_key_record"]["key_id"] == "test-key"


def test_registry_signer_verifies_retired_keys() -> None:
    old_material = generate_key_material("old-key", "node-a")
    new_material = generate_key_material("new-key", "node-a")
    old_signer = RegistrySigner(
        key_id="old-key",
        node_id="node-a",
        private_key_b64=old_material["env"]["DID_SIGNING_PRIVATE_KEY_B64"],
    )
    new_signer = RegistrySigner(
        key_id="new-key",
        node_id="node-a",
        private_key_b64=new_material["env"]["DID_SIGNING_PRIVATE_KEY_B64"],
        verifying_keys_json=json.dumps([old_material["verifying_key_record"]]),
    )

    payload = {"receipt_id": "tgr_test", "hash_id": "abc"}
    _, signature = old_signer.sign_payload(payload)

    assert new_signer.verify_payload(payload, signature, "old-key") is True
    assert new_signer.verify_payload({**payload, "hash_id": "def"}, signature, "old-key") is False


def test_generate_bank_key_outputs_trusted_key_record() -> None:
    material = generate_bank_key_material("bank-a", "bank-a-signing-1")

    assert material["bank_id"] == "bank-a"
    assert material["key_id"] == "bank-a-signing-1"
    assert re.fullmatch(r"[A-Za-z0-9_-]+", material["bank_private_key_b64"])
    assert material["trusted_key_record"]["bank_id"] == "bank-a"
    assert material["trusted_key_record"]["key_id"] == "bank-a-signing-1"
    assert material["trusted_key_record"]["public_key_jwk"]["kty"] == "OKP"
