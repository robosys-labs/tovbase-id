# KYC Canonicalization Schema v1

Schema id: `kyc-ng-v1`

This schema defines how a bank-controlled SDK turns passport, BVN, NIN, and
other bank-approved identity inputs into a deterministic local payload before
hashing. The canonical payload is never sent to Tovbase.

## Canonical payload shape

```json
{
  "schema_version": "kyc-ng-v1",
  "fields": {
    "bvn": "22233344455",
    "nin": "12345678901",
    "passport_number": "A1234567"
  }
}
```

The final registry hash is derived from:

```text
SHA-256(
  "tovbase-id:identity-hash:v1." ||
  canonical_json({
    canonical_identity,
    device_pubkey_fingerprint,
    domain
  }) ||
  "." ||
  bank_held_user_salt_bytes
)
```

## Field normalization

| Field | Normalization | Example |
| --- | --- | --- |
| `nin` | digits only | `123 456 789 01` -> `12345678901` |
| `bvn` | digits only | `222-333-44455` -> `22233344455` |
| `passport_number` | remove spaces/hyphens, uppercase | `a-1234567` -> `A1234567` |
| `account_number` | digits only | `001-234-5678` -> `0012345678` |
| `bank_code` | remove spaces/hyphens, uppercase | `bank-a` -> `BANKA` |
| `phone` | keep leading `+`, otherwise digits only | `+234 801 000 0000` -> `+2348010000000` |
| `email` | trim and lowercase | ` USER@BANK.COM ` -> `user@bank.com` |

Banks may add extra local-only fields by SDK release, but each added field must
have a documented normalizer and a schema version bump if it changes the meaning
of existing hashes.

## Required controls

- At least one bank-approved identity field must be present.
- Empty values are omitted before canonical JSON is produced.
- Field names are sorted lexicographically.
- JSON is serialized with sorted keys and no insignificant whitespace.
- Per-user salt is generated and stored under bank controls.
- The canonical payload, raw fields, and salt must not be sent to Tovbase.

## Hash stability

The following inputs produce the same canonical payload:

```json
{ "nin": "123 456 789 01", "bvn": "222-333-44455", "passport_number": "a-1234567" }
```

```json
{ "passport_number": "A1234567", "bvn": "22233344455", "nin": "12345678901" }
```

They produce different registry hashes if the salt or WebAuthn public key
changes.
