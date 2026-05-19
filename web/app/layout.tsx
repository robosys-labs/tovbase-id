import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Tovbase ID - Bank-grade identity without a PII honeypot",
  description:
    "A federated DID and hash registry for banks: SDK-side hashing, user-held passkeys, signed receipts, and bank-operated mirrors.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
