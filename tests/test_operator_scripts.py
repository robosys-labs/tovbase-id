import re

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
