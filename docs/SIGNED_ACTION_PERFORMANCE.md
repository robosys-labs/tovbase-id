# Signed Action Performance Proof

Tovbase ID includes an in-process benchmark for the P1 timing target:

- instant passkey-only action: under 3 seconds,
- passkey plus camera/liveness action: under 30 seconds when the provider
  responds inside the expected provider window,
- backend action submission: milliseconds on the local warm path.

Run:

```bash
python scripts/benchmark_action_flow.py --iterations 5 --provider-latency-seconds 0
```

Simulate a slow liveness provider:

```bash
python scripts/benchmark_action_flow.py --iterations 1 --provider-latency-seconds 20
```

The benchmark exercises the actual FastAPI app through `TestClient`:

1. Generates user, bank, and provider Ed25519 keys.
2. Registers a DID with a signed bank attestation.
3. Creates an instant signed action challenge and submits the user signature.
4. Creates an `aal3` camera-liveness action challenge.
5. Generates a provider-signed `camera_liveness` result.
6. Submits the user signature, bank credential reference, and liveness result.
7. Reports median instant, liveness, and backend-submit timings.

Example local output on May 19, 2026:

```json
{
  "all_instant_approved": true,
  "all_liveness_approved": true,
  "instant_median_seconds": 0.0114,
  "iterations": 2,
  "liveness_backend_submit_median_seconds": 0.0052,
  "liveness_median_seconds": 0.0092,
  "provider_latency_seconds": 0.0,
  "target_pass": true
}
```

This is not a substitute for device UX testing with real passkeys and a real
liveness provider. It proves the registry backend path is not the bottleneck.
