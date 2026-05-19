const SDK_VERSION = "tovbase-id-browser/0.1.0";
const HASH_DOMAIN = "tovbase-id:identity-hash:v1";

const NORMALIZERS = {
  account_number: digitsOnly,
  bank_code: uppercaseCompact,
  bvn: digitsOnly,
  email: lowercaseTrim,
  nin: digitsOnly,
  passport_number: uppercaseCompact,
  phone: phoneCompact,
};
const SUPPORTED_IDENTITY_FIELDS = Object.freeze(Object.keys(NORMALIZERS).sort());

function assertObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
}

function digitsOnly(value) {
  return String(value ?? "").replace(/\D/g, "");
}

function lowercaseTrim(value) {
  return String(value ?? "").trim().toLowerCase();
}

function uppercaseCompact(value) {
  return String(value ?? "").replace(/[\s-]/g, "").toUpperCase();
}

function phoneCompact(value) {
  const trimmed = String(value ?? "").trim();
  if (trimmed.startsWith("+")) {
    return `+${trimmed.slice(1).replace(/\D/g, "")}`;
  }
  return trimmed.replace(/\D/g, "");
}

function base64UrlToBytes(value) {
  const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function concatBytes(parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function encodeUtf8(value) {
  return new TextEncoder().encode(value);
}

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

export async function sha256Hex(value) {
  const bytes = typeof value === "string" ? encodeUtf8(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

export function canonicalizeIdentity(identity, schemaVersion = "kyc-ng-v1") {
  assertObject(identity, "identity");
  const normalized = {};
  for (const [key, value] of Object.entries(identity)) {
    if (!Object.prototype.hasOwnProperty.call(NORMALIZERS, key)) {
      throw new TypeError(`unsupported identity field for ${schemaVersion}: ${key}`);
    }
    if (value === undefined || value === null || value === "") {
      continue;
    }
    const normalizer = NORMALIZERS[key] ?? ((input) => String(input).trim());
    normalized[key] = normalizer(value);
  }
  if (Object.keys(normalized).length === 0) {
    throw new TypeError("at least one bank-approved identity field is required");
  }
  return {
    schema_version: schemaVersion,
    fields: Object.fromEntries(Object.entries(normalized).sort(([left], [right]) => left.localeCompare(right))),
  };
}

export async function fingerprintPublicKeyJwk(publicKeyJwk) {
  assertObject(publicKeyJwk, "publicKeyJwk");
  return sha256Hex(canonicalJson(publicKeyJwk));
}

export async function deriveIdentityHash({
  identity,
  saltBase64Url,
  webauthnPublicKeyJwk,
  schemaVersion = "kyc-ng-v1",
}) {
  if (!saltBase64Url) {
    throw new TypeError("saltBase64Url is required");
  }
  const canonicalIdentity = canonicalizeIdentity(identity, schemaVersion);
  const publicKeyFingerprint = await fingerprintPublicKeyJwk(webauthnPublicKeyJwk);
  const payload = canonicalJson({
    canonical_identity: canonicalIdentity,
    device_pubkey_fingerprint: publicKeyFingerprint,
    domain: HASH_DOMAIN,
  });
  const hashMaterial = concatBytes([
    encodeUtf8(`${HASH_DOMAIN}.`),
    encodeUtf8(payload),
    encodeUtf8("."),
    base64UrlToBytes(saltBase64Url),
  ]);
  return {
    hash_id: await sha256Hex(hashMaterial),
    device_pubkey_fingerprint: publicKeyFingerprint,
    canonical_identity: canonicalIdentity,
  };
}

export async function createRegistrationRequest({
  identity,
  saltBase64Url,
  webauthnCredentialId,
  webauthnPublicKeyJwk,
  bankId,
  schemaVersion = "kyc-ng-v1",
  bankAttestation,
}) {
  if (!webauthnCredentialId) {
    throw new TypeError("webauthnCredentialId is required");
  }
  const derived = await deriveIdentityHash({
    identity,
    saltBase64Url,
    webauthnPublicKeyJwk,
    schemaVersion,
  });
  const request = {
    hash_id: derived.hash_id,
    hash_algorithm: "sha256",
    hash_encoding: "hex",
    sdk_version: SDK_VERSION,
    webauthn_credential_id: webauthnCredentialId,
    webauthn_public_key: webauthnPublicKeyJwk,
    device_pubkey_fingerprint: derived.device_pubkey_fingerprint,
    bank_id: bankId,
    metadata: {
      schema_version: schemaVersion,
      client: SDK_VERSION,
    },
  };
  if (bankAttestation) {
    request.bank_attestation = bankAttestation;
  }
  return request;
}

export { SDK_VERSION, SUPPORTED_IDENTITY_FIELDS };
