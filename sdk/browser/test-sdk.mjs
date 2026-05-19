import assert from "node:assert/strict";
import {
  SUPPORTED_IDENTITY_FIELDS,
  canonicalJson,
  canonicalizeIdentity,
  createRegistrationRequest,
  deriveIdentityHash,
} from "./tovbase-id-sdk.mjs";

if (!globalThis.atob) {
  globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
}

const publicKeyJwk = {
  crv: "Ed25519",
  kty: "OKP",
  x: "6xIdyBRkdl4QTH-2PwsX0h0mEDHXsVnES5SYE0c_WXE",
};
const saltBase64Url = "c2FtcGxlLWJhbmstaGVsZC1zYWx0";
const identityA = {
  passport_number: " a-1234567 ",
  nin: "123 456 789 01",
  bvn: "222-333-44455",
};
const identityB = {
  bvn: "22233344455",
  nin: "12345678901",
  passport_number: "A1234567",
};

const canonicalA = canonicalizeIdentity(identityA);
const canonicalB = canonicalizeIdentity(identityB);
assert.deepEqual(canonicalA, canonicalB);
assert.equal(canonicalJson({ b: 2, a: 1 }), '{"a":1,"b":2}');
assert.ok(SUPPORTED_IDENTITY_FIELDS.includes("nin"));
assert.throws(() => canonicalizeIdentity({ nickname: "raw-local-only" }), /unsupported identity field/);

const derivedA = await deriveIdentityHash({
  identity: identityA,
  saltBase64Url,
  webauthnPublicKeyJwk: publicKeyJwk,
});
const derivedB = await deriveIdentityHash({
  identity: identityB,
  saltBase64Url,
  webauthnPublicKeyJwk: publicKeyJwk,
});
assert.match(derivedA.hash_id, /^[0-9a-f]{64}$/);
assert.equal(derivedA.hash_id, derivedB.hash_id);

const differentSalt = await deriveIdentityHash({
  identity: identityA,
  saltBase64Url: "ZGlmZmVyZW50LXNhbHQ",
  webauthnPublicKeyJwk: publicKeyJwk,
});
assert.notEqual(derivedA.hash_id, differentSalt.hash_id);

const request = await createRegistrationRequest({
  identity: identityA,
  saltBase64Url,
  webauthnCredentialId: "cred_123",
  webauthnPublicKeyJwk: publicKeyJwk,
  bankId: "bank-a",
});
const serialized = JSON.stringify(request);
assert.equal(request.hash_id, derivedA.hash_id);
assert.equal(request.hash_algorithm, "sha256");
assert.equal(request.hash_encoding, "hex");
assert.ok(!serialized.includes("12345678901"));
assert.ok(!serialized.includes("22233344455"));
assert.ok(!serialized.includes("A1234567"));
assert.ok(!serialized.includes("saltBase64Url"));

console.log("browser SDK reference checks passed");
