# Action Attestation Provider Workflow

Action attestations are step-up results attached to signed official actions.
The main v1 use case is `camera_liveness`, but the same envelope also supports
manual review or other provider-scored methods.

Tovbase stores only result metadata and `evidence_hash`. Raw face images,
videos, documents, and provider session data stay with the bank or provider.

## 1. Generate a provider key

```bash
python scripts/generate_provider_key.py \
  --provider-id bank-a-liveness \
  --key-id bank-a-liveness-2026-01
```

The provider keeps `provider_private_key_b64`. Tovbase receives only the
`trusted_key_record` through `TRUSTED_ATTESTATION_PROVIDER_KEYS_JSON`.

Example registry config:

```json
[
  {
    "provider_id": "bank-a-liveness",
    "key_id": "bank-a-liveness-2026-01",
    "signature_algorithm": "ed25519",
    "public_key_jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "base64url public key"
    },
    "status": "active"
  }
]
```

## 2. Provider signs the result

The provider signs this canonical envelope:

```json
{
  "purpose": "tovbase-id:action-attestation:v1",
  "action_id": "act_...",
  "did": "did:tov:<hash_id>",
  "hash_id": "<sha256 hex>",
  "bank_id": "bank-a",
  "attestation_type": "camera_liveness",
  "provider_id": "bank-a-liveness",
  "evidence_hash": "<sha256 hex provider evidence digest>",
  "result": "passed",
  "issued_at": "2026-05-19T22:15:00Z",
  "expires_at": "2026-05-19T22:20:00Z",
  "key_id": "bank-a-liveness-2026-01",
  "payload": {}
}
```

Rules:

- Serialize canonical JSON with sorted keys and no insignificant whitespace.
- Sign the UTF-8 canonical JSON bytes with Ed25519.
- Send the base64url signature in `attestations[].signature`.
- Keep raw biometric media outside Tovbase.

## 3. Submit with signed action

The bank/user submits the passkey signature and provider result:

```text
POST /v1/did/actions/submit
```

For `aal3` camera liveness, Tovbase now requires:

- valid user passkey signature over the action challenge,
- bank handshake credential reference,
- `camera_liveness` result of `passed`,
- unexpired liveness result,
- valid provider signature from `TRUSTED_ATTESTATION_PROVIDER_KEYS_JSON`.

If the provider signature is invalid, the action is recorded as `rejected` and
`verification_result.attestation_signatures_valid` is `false`.
