# Tovbase ID Browser SDK Reference

This is the minimal, dependency-free browser reference for bank-side hashing.
It is intentionally small enough for bank security teams to audit.

The SDK receives raw identity inputs inside the bank-controlled app/browser
session, canonicalizes them locally, combines them with a bank-held per-user
salt and the device public-key fingerprint, and returns a Tovbase registration
request that contains no raw PII and no salt.

## Important boundary

Do not send `identity`, raw document/media, or `saltBase64Url` to Tovbase. They
exist only inside the bank app or SDK call.

## Example

```js
import { createRegistrationRequest } from "./tovbase-id-sdk.mjs";

const request = await createRegistrationRequest({
  identity: {
    nin: "12345678901",
    bvn: "22233344455",
    passport_number: "a1234567",
  },
  saltBase64Url: bankProvidedSalt,
  webauthnCredentialId: credentialId,
  webauthnPublicKeyJwk: publicKeyJwk,
  bankId: "bank-a",
});

await fetch("https://api.tovbase.com/v1/did/register", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(request),
});
```

## Local verification

```bash
node sdk/browser/test-sdk.mjs
```
