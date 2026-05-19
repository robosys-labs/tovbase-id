import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Tovbase ID - Bank-grade identity without a PII honeypot",
  description:
    "A federated DID and hash registry for banks: SDK-side hashing, user-held passkeys, signed receipts, and bank-operated mirrors.",
};

const proofPoints = [
  {
    label: "No raw PII",
    value: "SDK hashes locally",
    detail:
      "NIN, BVN, names, salts, and customer mappings stay inside the bank boundary.",
  },
  {
    label: "No central user keys",
    value: "Passkey controlled",
    detail:
      "Users approve with WebAuthn passkeys; Tovbase stores public material only.",
  },
  {
    label: "No forced dependency",
    value: "Bank mirrors",
    detail:
      "Partner banks can keep local read mirrors and continue verification during primary outages.",
  },
];

const workflow = [
  "Hash",
  "Register",
  "Mirror",
  "Resolve",
  "Attest",
];

const stack = [
  ["SDK", "local SHA-256 + passkey"],
  ["API", "FastAPI /v1/did"],
  ["Registry", "PostgreSQL events"],
  ["Mirror", "logical replication"],
  ["L3 optional", "NATS JetStream"],
];

const guarantees = [
  "A registry breach exposes hashes and public keys, not customer identity data.",
  "A primary outage leaves bank mirrors available for local lookup.",
  "A signed receipt verifies registration time without trusting the database.",
  "A bank breach maps only that bank's customers, not the entire network.",
];

function RegistryScene() {
  return (
    <div className="absolute inset-0 overflow-hidden" aria-hidden="true">
      <div className="absolute inset-0 bg-[#f6f8f7]" />
      <div className="absolute inset-x-0 bottom-0 h-28 bg-white" />
      <div className="absolute left-1/2 top-1/2 h-[620px] w-[920px] -translate-x-1/2 -translate-y-1/2">
        <div className="absolute left-[6%] top-[16%] h-20 w-44 border border-[#b8c8c0] bg-white/90 shadow-sm">
          <div className="h-2 bg-[#0f6e56]" />
          <div className="p-3">
            <div className="h-2 w-20 bg-[#1f2a37]" />
            <div className="mt-3 h-2 w-32 bg-[#d8e3de]" />
            <div className="mt-2 h-2 w-24 bg-[#d8e3de]" />
          </div>
        </div>
        <div className="absolute right-[7%] top-[20%] h-20 w-44 border border-[#b8c8c0] bg-white/90 shadow-sm">
          <div className="h-2 bg-[#2563eb]" />
          <div className="p-3">
            <div className="h-2 w-24 bg-[#1f2a37]" />
            <div className="mt-3 h-2 w-28 bg-[#d8e3de]" />
            <div className="mt-2 h-2 w-36 bg-[#d8e3de]" />
          </div>
        </div>
        <div className="absolute bottom-[18%] left-[12%] h-20 w-44 border border-[#b8c8c0] bg-white/90 shadow-sm">
          <div className="h-2 bg-[#ba7517]" />
          <div className="p-3">
            <div className="h-2 w-28 bg-[#1f2a37]" />
            <div className="mt-3 h-2 w-32 bg-[#d8e3de]" />
            <div className="mt-2 h-2 w-20 bg-[#d8e3de]" />
          </div>
        </div>
        <div className="absolute bottom-[16%] right-[14%] h-20 w-44 border border-[#b8c8c0] bg-white/90 shadow-sm">
          <div className="h-2 bg-[#334155]" />
          <div className="p-3">
            <div className="h-2 w-20 bg-[#1f2a37]" />
            <div className="mt-3 h-2 w-32 bg-[#d8e3de]" />
            <div className="mt-2 h-2 w-28 bg-[#d8e3de]" />
          </div>
        </div>
        <div className="absolute left-1/2 top-1/2 h-44 w-72 -translate-x-1/2 -translate-y-1/2 border border-[#8fb3a5] bg-white shadow-lg">
          <div className="flex h-10 items-center justify-between border-b border-[#d8e3de] px-4">
            <div className="h-2 w-20 bg-[#0f6e56]" />
            <div className="h-5 w-16 border border-[#b8c8c0]" />
          </div>
          <div className="p-4">
            <div className="h-3 w-44 bg-[#1f2a37]" />
            <div className="mt-4 grid grid-cols-4 gap-2">
              <div className="h-12 border border-[#d8e3de] bg-[#f6f8f7]" />
              <div className="h-12 border border-[#d8e3de] bg-[#f6f8f7]" />
              <div className="h-12 border border-[#d8e3de] bg-[#f6f8f7]" />
              <div className="h-12 border border-[#d8e3de] bg-[#f6f8f7]" />
            </div>
            <div className="mt-4 h-2 w-56 bg-[#d8e3de]" />
            <div className="mt-2 h-2 w-40 bg-[#d8e3de]" />
          </div>
        </div>
        <div className="absolute left-[24%] top-[28%] h-px w-[210px] rotate-[18deg] bg-[#8fb3a5]" />
        <div className="absolute right-[24%] top-[31%] h-px w-[205px] -rotate-[16deg] bg-[#8fb3a5]" />
        <div className="absolute bottom-[33%] left-[26%] h-px w-[205px] -rotate-[20deg] bg-[#8fb3a5]" />
        <div className="absolute bottom-[32%] right-[27%] h-px w-[175px] rotate-[22deg] bg-[#8fb3a5]" />
      </div>
    </div>
  );
}

export default function TovbaseIdPage() {
  return (
    <div className="bg-white text-[#111827]">
      <section className="relative min-h-[720px] overflow-hidden">
        <RegistryScene />
        <div className="relative mx-auto flex min-h-[720px] max-w-6xl flex-col justify-end px-4 pb-16 pt-24 sm:px-6 lg:px-8">
          <div className="max-w-3xl">
            <p className="text-sm font-semibold uppercase tracking-[0.18em] text-[#0f6e56]">
              Tovbase ID
            </p>
            <h1 className="mt-4 max-w-3xl text-4xl font-semibold leading-tight tracking-normal text-[#111827] sm:text-6xl">
              Bank-grade identity without a central PII honeypot.
            </h1>
            <p className="mt-6 max-w-2xl text-lg leading-8 text-[#4b5563]">
              A federated DID and hash registry where banks keep customer
              mappings, users keep passkeys, and every registration returns a
              signed receipt that mirrors across bank-operated nodes.
            </p>
            <div className="mt-8 flex flex-col gap-3 sm:flex-row">
              <a
                href="mailto:partners@tovbase.com?subject=Tovbase%20ID%20bank%20pilot"
                className="inline-flex h-11 items-center justify-center bg-[#0f6e56] px-5 text-sm font-semibold text-white transition-colors hover:bg-[#0b5945]"
              >
                Start a bank pilot
              </a>
              <a
                href="https://github.com/robosys-labs/tovbase/blob/main/docs/DID_REGISTRY_ARCHITECTURE.md"
                className="inline-flex h-11 items-center justify-center border border-[#9ca3af] bg-white/90 px-5 text-sm font-semibold text-[#111827] transition-colors hover:bg-white"
              >
                Read the architecture
              </a>
            </div>
          </div>
          <div className="mt-14 grid gap-3 sm:grid-cols-3">
            {proofPoints.map((point) => (
              <div key={point.label} className="border border-[#d8e3de] bg-white/92 p-5 shadow-sm">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#6b7280]">
                  {point.label}
                </p>
                <p className="mt-3 text-xl font-semibold text-[#111827]">
                  {point.value}
                </p>
                <p className="mt-2 text-sm leading-6 text-[#4b5563]">
                  {point.detail}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="border-y border-[#e5e7eb] bg-white">
        <div className="mx-auto grid max-w-6xl gap-10 px-4 py-16 sm:px-6 lg:grid-cols-[0.9fr_1.1fr] lg:px-8">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.16em] text-[#0f6e56]">
              Workflow
            </p>
            <h2 className="mt-3 text-3xl font-semibold tracking-normal text-[#111827]">
              One primitive across every channel.
            </h2>
            <p className="mt-4 text-base leading-7 text-[#4b5563]">
              Mobile app, browser, bank batch job, mirror lookup, and offline
              audit all share the same hash, DID, receipt, and attestation
              envelope.
            </p>
          </div>
          <div className="grid gap-3 sm:grid-cols-5">
            {workflow.map((item, index) => (
              <div key={item} className="border border-[#d8e3de] bg-[#f8faf9] p-4">
                <p className="text-xs font-semibold text-[#6b7280]">
                  0{index + 1}
                </p>
                <p className="mt-8 text-base font-semibold text-[#111827]">
                  {item}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="architecture" className="bg-[#f6f8f7]">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 lg:px-8">
          <div className="max-w-2xl">
            <p className="text-sm font-semibold uppercase tracking-[0.16em] text-[#0f6e56]">
              Architecture
            </p>
            <h2 className="mt-3 text-3xl font-semibold tracking-normal text-[#111827]">
              PostgreSQL first. Quorum only when the network needs it.
            </h2>
          </div>
          <div className="mt-8 grid gap-4 md:grid-cols-5">
            {stack.map(([title, detail]) => (
              <div key={title} className="border border-[#d8e3de] bg-white p-5">
                <p className="text-lg font-semibold text-[#111827]">{title}</p>
                <p className="mt-3 text-sm leading-6 text-[#4b5563]">
                  {detail}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="bg-white">
        <div className="mx-auto grid max-w-6xl gap-10 px-4 py-16 sm:px-6 lg:grid-cols-[1fr_1fr] lg:px-8">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.16em] text-[#0f6e56]">
              Security model
            </p>
            <h2 className="mt-3 text-3xl font-semibold tracking-normal text-[#111827]">
              Designed for limited blast radius.
            </h2>
            <p className="mt-4 text-base leading-7 text-[#4b5563]">
              The registry proves that a hash and DID were registered. The
              real-world mapping remains bank-local, and user signing keys
              remain on user-controlled authenticators.
            </p>
          </div>
          <div className="space-y-3">
            {guarantees.map((item) => (
              <div key={item} className="border border-[#d8e3de] p-4">
                <p className="text-sm leading-6 text-[#374151]">{item}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="border-t border-[#e5e7eb] bg-[#111827]">
        <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-14 sm:px-6 lg:flex-row lg:items-center lg:justify-between lg:px-8">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.16em] text-[#8fb3a5]">
              Pilot readiness
            </p>
            <h2 className="mt-3 text-3xl font-semibold tracking-normal text-white">
              Run a mirror. Verify receipts. Keep PII inside the bank.
            </h2>
          </div>
          <a
            href="mailto:partners@tovbase.com?subject=Tovbase%20ID%20technical%20review"
            className="inline-flex h-11 shrink-0 items-center justify-center bg-white px-5 text-sm font-semibold text-[#111827] transition-colors hover:bg-[#f3f4f6]"
          >
            Request technical review
          </a>
        </div>
      </section>
    </div>
  );
}
