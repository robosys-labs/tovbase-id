"use client";

import { useEffect, useMemo, useRef, useState } from "react";

type DemoMode = "pdf" | "video";
type Stage = "ready" | "working" | "signed" | "error";

type DemoKey = {
  did: string;
  hashId: string;
  fingerprint: string;
  publicJwk: JsonWebKey;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
};

type ProofEnvelope = {
  purpose: "tovbase-id:demo-signed-artifact:v1";
  did: string;
  hash_id: string;
  artifact_type: "application/pdf" | "video/webm";
  artifact_name: string;
  artifact_sha256: string;
  artifact_size_bytes: number;
  bank_id: string;
  bank_credential_id: string;
  requested_attestation: {
    level: "instant" | "aal3";
    methods: string[];
  };
  issued_at: string;
  expires_at: string;
  nonce: string;
  public_key_jwk: JsonWebKey;
  signature_algorithm: "ECDSA-P256-SHA256";
  challenge_hash: string;
  signature: string;
};

type ProofState = {
  envelope: ProofEnvelope;
  artifactUrl: string;
  verified: boolean;
  signingMs: number;
};

const encoder = new TextEncoder();

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function bytesToHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64Url(bytes: ArrayBuffer): string {
  const binary = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomBase64Url(byteLength = 18): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes.buffer);
}

async function sha256Hex(value: string | ArrayBuffer | Uint8Array): Promise<string> {
  let bytes: BufferSource;
  if (typeof value === "string") {
    const encoded = encoder.encode(value);
    bytes = encoded.buffer.slice(encoded.byteOffset, encoded.byteOffset + encoded.byteLength) as ArrayBuffer;
  } else if (value instanceof Uint8Array) {
    bytes = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
  } else {
    bytes = value;
  }
  return bytesToHex(await crypto.subtle.digest("SHA-256", bytes));
}

async function createDemoKey(): Promise<DemoKey> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const fingerprint = await sha256Hex(canonicalJson(publicJwk));
  const hashId = await sha256Hex(
    canonicalJson({
      domain: "tovbase-id:browser-demo-identity:v1",
      device_pubkey_fingerprint: fingerprint,
      bank_id: "bank-demo",
    }),
  );
  return {
    did: `did:tov:${hashId}`,
    hashId,
    fingerprint,
    publicJwk,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

function escapePdfText(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

function createPdfBytes(): ArrayBuffer {
  const issuedAt = new Date().toISOString();
  const stream = [
    "BT",
    "/F1 20 Tf",
    "72 740 Td",
    `(Tovbase ID signed PDF demo) Tj`,
    "/F1 12 Tf",
    "0 -34 Td",
    `(Artifact: bank mandate approval) Tj`,
    "0 -22 Td",
    `(Issued: ${escapePdfText(issuedAt)}) Tj`,
    "0 -22 Td",
    "(This PDF is hashed and signed locally in the browser.) Tj",
    "0 -22 Td",
    "(No raw identity data is sent to the registry.) Tj",
    "ET",
  ].join("\n");
  const objects = [
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
    "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
    "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    `5 0 obj\n<< /Length ${stream.length} >>\nstream\n${stream}\nendstream\nendobj\n`,
  ];
  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  for (const object of objects) {
    offsets.push(pdf.length);
    pdf += object;
  }
  const xrefOffset = pdf.length;
  pdf += "xref\n0 6\n0000000000 65535 f \n";
  pdf += offsets
    .slice(1)
    .map((offset) => `${String(offset).padStart(10, "0")} 00000 n \n`)
    .join("");
  pdf += `trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  const bytes = encoder.encode(pdf);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function preferredVideoMimeType(): string {
  if (typeof MediaRecorder === "undefined") {
    throw new Error("MediaRecorder is unavailable in this browser");
  }
  const options = ["video/webm;codecs=vp9", "video/webm;codecs=vp8", "video/webm"];
  return options.find((type) => MediaRecorder.isTypeSupported(type)) ?? "";
}

function mediaRecorderOptions(): MediaRecorderOptions {
  const mimeType = preferredVideoMimeType();
  return mimeType ? { mimeType } : {};
}

async function recordCanvasClip(): Promise<Blob> {
  const canvas = document.createElement("canvas");
  canvas.width = 960;
  canvas.height = 540;
  const context = canvas.getContext("2d");
  if (!context) {
    throw new Error("canvas is unavailable");
  }
  const stream = canvas.captureStream(24);
  const chunks: Blob[] = [];
  const recorder = new MediaRecorder(stream, mediaRecorderOptions());
  recorder.ondataavailable = (event) => {
    if (event.data.size > 0) {
      chunks.push(event.data);
    }
  };
  const finished = new Promise<Blob>((resolve) => {
    recorder.onstop = () => {
      stream.getTracks().forEach((track) => track.stop());
      resolve(new Blob(chunks, { type: "video/webm" }));
    };
  });
  let frame = 0;
  const draw = () => {
    const gradient = context.createLinearGradient(0, 0, canvas.width, canvas.height);
    gradient.addColorStop(0, "#f8faf9");
    gradient.addColorStop(1, "#d8e3de");
    context.fillStyle = gradient;
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.fillStyle = "#0f6e56";
    context.fillRect(72, 72, 180 + frame * 5, 18);
    context.fillStyle = "#111827";
    context.font = "bold 42px system-ui";
    context.fillText("Tovbase ID media proof", 72, 170);
    context.font = "24px system-ui";
    context.fillText("Signed WebRTC-style video envelope", 72, 220);
    context.fillStyle = "#ba7517";
    context.fillRect(72, 290, 72 + frame * 8, 72);
    context.fillStyle = "#2563eb";
    context.fillRect(180 + frame * 6, 390, 260, 20);
    frame += 1;
  };
  const interval = window.setInterval(draw, 80);
  recorder.start();
  draw();
  window.setTimeout(() => {
    window.clearInterval(interval);
    recorder.stop();
  }, 2400);
  return finished;
}

function unsignedEnvelope(envelope: ProofEnvelope): Omit<ProofEnvelope, "signature" | "challenge_hash"> {
  const { signature: _signature, challenge_hash: _challengeHash, ...unsigned } = envelope;
  return unsigned;
}

async function signArtifact(params: {
  key: DemoKey;
  artifact: Blob;
  artifactName: string;
  artifactType: ProofEnvelope["artifact_type"];
  level: ProofEnvelope["requested_attestation"]["level"];
}): Promise<ProofState> {
  const started = performance.now();
  const artifactBytes = await params.artifact.arrayBuffer();
  const artifactHash = await sha256Hex(artifactBytes);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);
  const partial: ProofEnvelope = {
    purpose: "tovbase-id:demo-signed-artifact:v1",
    did: params.key.did,
    hash_id: params.key.hashId,
    artifact_type: params.artifactType,
    artifact_name: params.artifactName,
    artifact_sha256: artifactHash,
    artifact_size_bytes: artifactBytes.byteLength,
    bank_id: "bank-demo",
    bank_credential_id: "bankcred_demo_handshake_001",
    requested_attestation: {
      level: params.level,
      methods: params.level === "aal3" ? ["passkey", "bank_handshake", "camera_liveness"] : ["passkey"],
    },
    issued_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    nonce: randomBase64Url(),
    public_key_jwk: params.key.publicJwk,
    signature_algorithm: "ECDSA-P256-SHA256",
    challenge_hash: "pending",
    signature: "pending",
  };
  const challengeBytes = encoder.encode(canonicalJson(unsignedEnvelope(partial)));
  const challengeHash = await sha256Hex(challengeBytes);
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    params.key.privateKey,
    challengeBytes,
  );
  const envelope = {
    ...partial,
    challenge_hash: challengeHash,
    signature: bytesToBase64Url(signature),
  };
  const verified = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    params.key.publicKey,
    signature,
    challengeBytes,
  );
  return {
    envelope,
    artifactUrl: URL.createObjectURL(params.artifact),
    verified,
    signingMs: Math.round((performance.now() - started) * 10) / 10,
  };
}

function shortHash(value: string): string {
  return `${value.slice(0, 12)}...${value.slice(-10)}`;
}

export default function DemoWorkbench() {
  const [mode, setMode] = useState<DemoMode>("pdf");
  const [stage, setStage] = useState<Stage>("ready");
  const [demoKey, setDemoKey] = useState<DemoKey | null>(null);
  const [proof, setProof] = useState<ProofState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [recording, setRecording] = useState(false);
  const [cameraLive, setCameraLive] = useState(false);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const recorderRef = useRef<MediaRecorder | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const chunksRef = useRef<Blob[]>([]);

  useEffect(() => {
    createDemoKey()
      .then(setDemoKey)
      .catch((err: unknown) => {
        setStage("error");
        setError(err instanceof Error ? err.message : "could not create demo key");
      });
  }, []);

  useEffect(() => {
    return () => {
      streamRef.current?.getTracks().forEach((track) => track.stop());
      if (proof?.artifactUrl) {
        URL.revokeObjectURL(proof.artifactUrl);
      }
    };
  }, [proof?.artifactUrl]);

  const envelopePreview = useMemo(() => {
    if (!proof) {
      return "{}";
    }
    return JSON.stringify(proof.envelope, null, 2);
  }, [proof]);

  async function createSignedPdf() {
    if (!demoKey) {
      return;
    }
    setError(null);
    setStage("working");
    setMode("pdf");
    try {
      const bytes = createPdfBytes();
      const artifact = new Blob([bytes], { type: "application/pdf" });
      setProof(
        await signArtifact({
          key: demoKey,
          artifact,
          artifactName: "bank-mandate-demo.pdf",
          artifactType: "application/pdf",
          level: "instant",
        }),
      );
      setStage("signed");
    } catch (err: unknown) {
      setStage("error");
      setError(err instanceof Error ? err.message : "could not sign PDF");
    }
  }

  async function signUploadedPdf(file: File | null) {
    if (!demoKey || !file) {
      return;
    }
    setError(null);
    setStage("working");
    setMode("pdf");
    try {
      setProof(
        await signArtifact({
          key: demoKey,
          artifact: file,
          artifactName: file.name || "uploaded-demo.pdf",
          artifactType: "application/pdf",
          level: "instant",
        }),
      );
      setStage("signed");
    } catch (err: unknown) {
      setStage("error");
      setError(err instanceof Error ? err.message : "could not sign uploaded PDF");
    }
  }

  async function signCanvasVideo() {
    if (!demoKey) {
      return;
    }
    setError(null);
    setStage("working");
    setMode("video");
    try {
      const artifact = await recordCanvasClip();
      setProof(
        await signArtifact({
          key: demoKey,
          artifact,
          artifactName: "sample-webrtc-proof.webm",
          artifactType: "video/webm",
          level: "aal3",
        }),
      );
      setStage("signed");
    } catch (err: unknown) {
      setStage("error");
      setError(err instanceof Error ? err.message : "could not create sample video proof");
    }
  }

  async function startCameraRecording() {
    if (!demoKey) {
      return;
    }
    setError(null);
    setProof(null);
    setMode("video");
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
      }
      const recorder = new MediaRecorder(stream, mediaRecorderOptions());
      chunksRef.current = [];
      recorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          chunksRef.current.push(event.data);
        }
      };
      recorder.onstop = async () => {
        setRecording(false);
        setCameraLive(false);
        stream.getTracks().forEach((track) => track.stop());
        streamRef.current = null;
        if (videoRef.current) {
          videoRef.current.srcObject = null;
        }
        setStage("working");
        try {
          const artifact = new Blob(chunksRef.current, { type: "video/webm" });
          setProof(
            await signArtifact({
              key: demoKey,
              artifact,
              artifactName: "camera-webrtc-proof.webm",
              artifactType: "video/webm",
              level: "aal3",
            }),
          );
          setStage("signed");
        } catch (err: unknown) {
          setStage("error");
          setError(err instanceof Error ? err.message : "could not sign recorded video");
        }
      };
      recorderRef.current = recorder;
      recorder.start();
      setRecording(true);
      setCameraLive(true);
      setStage("working");
      window.setTimeout(() => {
        if (recorder.state === "recording") {
          recorder.stop();
        }
      }, 5000);
    } catch (err: unknown) {
      setStage("error");
      setRecording(false);
      setCameraLive(false);
      setError(err instanceof Error ? err.message : "camera capture is unavailable");
    }
  }

  function stopCameraRecording() {
    if (recorderRef.current?.state === "recording") {
      recorderRef.current.stop();
    }
  }

  function downloadEnvelope() {
    if (!proof) {
      return;
    }
    const blob = new Blob([envelopePreview], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${proof.envelope.artifact_name}.proof.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="min-h-screen bg-[#f7f8f9] text-[#111827]">
      <section className="border-b border-[#d9e2df] bg-white">
        <div className="mx-auto grid max-w-7xl gap-8 px-4 py-8 sm:px-6 lg:grid-cols-[0.75fr_1.25fr] lg:px-8">
          <div className="flex flex-col justify-between">
            <div>
              <a href="/" className="text-sm font-semibold text-[#0f6e56]">
                Tovbase ID
              </a>
              <h1 className="mt-4 text-3xl font-semibold tracking-normal sm:text-5xl">
                Signed PDF and WebRTC media proof demo
              </h1>
              <p className="mt-5 max-w-xl text-base leading-7 text-[#4b5563]">
                Hash the artifact, sign the canonical proof envelope with a demo
                user key, and verify the signature in the same browser session.
              </p>
            </div>
            <div className="mt-8 grid grid-cols-3 border border-[#d9e2df] bg-[#f8faf9]">
              {[
                ["DID", demoKey ? shortHash(demoKey.hashId) : "creating"],
                ["Key", demoKey ? "P-256 ready" : "pending"],
                ["Status", stage],
              ].map(([label, value]) => (
                <div key={label} className="border-r border-[#d9e2df] p-4 last:border-r-0">
                  <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[#6b7280]">{label}</p>
                  <p className="mt-2 text-sm font-semibold text-[#111827]">{value}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="border border-[#d9e2df] bg-[#f8faf9] p-4">
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setMode("pdf")}
                  className={`h-10 flex-1 border px-3 text-sm font-semibold ${
                    mode === "pdf" ? "border-[#0f6e56] bg-[#0f6e56] text-white" : "border-[#b8c8c0] bg-white"
                  }`}
                >
                  Signed PDF
                </button>
                <button
                  type="button"
                  onClick={() => setMode("video")}
                  className={`h-10 flex-1 border px-3 text-sm font-semibold ${
                    mode === "video" ? "border-[#0f6e56] bg-[#0f6e56] text-white" : "border-[#b8c8c0] bg-white"
                  }`}
                >
                  WebRTC video
                </button>
              </div>

              {mode === "pdf" ? (
                <div className="mt-5 space-y-3">
                  <button
                    type="button"
                    onClick={createSignedPdf}
                    disabled={!demoKey || stage === "working"}
                    className="h-11 w-full bg-[#0f6e56] px-4 text-sm font-semibold text-white disabled:bg-[#9ca3af]"
                  >
                    Generate signed PDF proof
                  </button>
                  <label className="block border border-dashed border-[#b8c8c0] bg-white p-4 text-sm font-semibold text-[#374151]">
                    Upload PDF
                    <input
                      type="file"
                      accept="application/pdf,.pdf"
                      className="mt-3 block w-full text-sm"
                      onChange={(event) => signUploadedPdf(event.target.files?.[0] ?? null)}
                    />
                  </label>
                </div>
              ) : (
                <div className="mt-5 space-y-3">
                  <button
                    type="button"
                    onClick={recording ? stopCameraRecording : startCameraRecording}
                    disabled={!demoKey}
                    className="h-11 w-full bg-[#0f6e56] px-4 text-sm font-semibold text-white disabled:bg-[#9ca3af]"
                  >
                    {recording ? "Stop and sign recording" : "Record camera proof"}
                  </button>
                  <button
                    type="button"
                    onClick={signCanvasVideo}
                    disabled={!demoKey || stage === "working"}
                    className="h-11 w-full border border-[#b8c8c0] bg-white px-4 text-sm font-semibold text-[#111827] disabled:text-[#9ca3af]"
                  >
                    Create sample video proof
                  </button>
                  <video ref={videoRef} className="aspect-video w-full bg-[#111827]" muted playsInline />
                </div>
              )}
              {cameraLive ? (
                <p className="mt-3 text-sm font-semibold text-[#ba7517]">Recording media stream...</p>
              ) : null}
              {error ? <p className="mt-3 text-sm font-semibold text-[#dc2626]">{error}</p> : null}
            </div>

            <div className="border border-[#d9e2df] bg-white p-4">
              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[#6b7280]">Verification</p>
              <div className="mt-4 grid grid-cols-2 gap-3">
                <div className="border border-[#d9e2df] p-3">
                  <p className="text-xs text-[#6b7280]">Signature</p>
                  <p className={`mt-2 text-lg font-semibold ${proof?.verified ? "text-[#0f6e56]" : "text-[#6b7280]"}`}>
                    {proof?.verified ? "Verified" : "Waiting"}
                  </p>
                </div>
                <div className="border border-[#d9e2df] p-3">
                  <p className="text-xs text-[#6b7280]">Time</p>
                  <p className="mt-2 text-lg font-semibold">{proof ? `${proof.signingMs} ms` : "--"}</p>
                </div>
              </div>
              <div className="mt-4 border border-[#d9e2df] p-3">
                <p className="text-xs text-[#6b7280]">Artifact hash</p>
                <p className="mt-2 break-all font-mono text-xs">
                  {proof ? proof.envelope.artifact_sha256 : "No artifact signed yet"}
                </p>
              </div>
              <button
                type="button"
                onClick={downloadEnvelope}
                disabled={!proof}
                className="mt-4 h-10 w-full border border-[#111827] bg-[#111827] px-4 text-sm font-semibold text-white disabled:border-[#9ca3af] disabled:bg-[#9ca3af]"
              >
                Download proof JSON
              </button>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto grid max-w-7xl gap-6 px-4 py-6 sm:px-6 lg:grid-cols-[0.9fr_1.1fr] lg:px-8">
        <div className="min-h-[520px] border border-[#d9e2df] bg-white">
          <div className="flex h-12 items-center justify-between border-b border-[#d9e2df] px-4">
            <p className="text-sm font-semibold">Artifact preview</p>
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[#6b7280]">
              {proof ? proof.envelope.artifact_type : mode}
            </p>
          </div>
          {proof?.envelope.artifact_type === "application/pdf" ? (
            <iframe title="Signed PDF preview" src={proof.artifactUrl} className="h-[520px] w-full" />
          ) : proof?.envelope.artifact_type === "video/webm" ? (
            <div className="flex h-[520px] items-center bg-[#111827] p-4">
              <video src={proof.artifactUrl} className="max-h-full w-full" controls />
            </div>
          ) : (
            <div className="flex h-[520px] items-center justify-center bg-[#f8faf9] p-6 text-center text-sm text-[#4b5563]">
              Choose a proof type to create a signed artifact.
            </div>
          )}
        </div>

        <div className="min-h-[520px] border border-[#d9e2df] bg-[#111827]">
          <div className="flex h-12 items-center justify-between border-b border-[#374151] px-4">
            <p className="text-sm font-semibold text-white">Canonical proof envelope</p>
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[#9ca3af]">
              SHA-256 + ECDSA
            </p>
          </div>
          <pre className="h-[520px] overflow-auto p-4 text-xs leading-5 text-[#d1d5db]">{envelopePreview}</pre>
        </div>
      </section>
    </main>
  );
}
