# Signed Artifact Browser Demo

The `/demo` route is a browser-first proof experience for partners who need to
see the product in seconds without provisioning a bank sandbox.

## What It Shows

- A demo DID key is generated in the browser with WebCrypto.
- A PDF or WebRTC-style video artifact is hashed locally with SHA-256.
- The browser signs a canonical proof envelope with the user key.
- The browser verifies the signature immediately with the exported public key.
- The proof envelope carries timestamps, artifact hash, bank credential
  reference, requested attestation policy, DID, and public key material.

## Demo Modes

### Signed PDF

The demo can generate a small bank-mandate PDF or accept an uploaded PDF. The
PDF bytes stay in the browser. Only the SHA-256 artifact hash is included in the
proof envelope.

### WebRTC Media Proof

The demo can record a short camera stream through `getUserMedia` and
`MediaRecorder`, then sign the resulting `video/webm` blob. It also includes a
canvas-generated sample clip for rooms where camera permissions or hardware are
unavailable.

## Why This Is Separate From Production

This is deliberately a demonstration layer. It does not replace the production
registry API, bank key custody, passkey ceremony verification, or liveness
provider integration.

Production flow:

1. Bank app or SDK creates the identity hash locally.
2. Tovbase registers only the hash, DID document, public metadata, and receipt.
3. User signs document/media action challenges with a real passkey.
4. Bank or liveness provider signs step-up evidence hashes.
5. Registry verifies policy and persists the signed action result.

Demo flow:

1. Browser creates a demo key.
2. Browser hashes and signs a PDF or video artifact.
3. Browser verifies the signature immediately.
4. The JSON envelope can be downloaded for partner walkthroughs.

## Local Run

```bash
cd web
pnpm install
pnpm dev
```

Open:

```text
http://localhost:3003/demo
```

Camera capture requires a secure browser context. `localhost` is treated as
secure by modern browsers. If camera capture fails, use the sample video proof
button.
