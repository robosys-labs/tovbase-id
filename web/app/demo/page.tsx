import type { Metadata } from "next";
import DemoWorkbench from "./DemoWorkbench";

export const metadata: Metadata = {
  title: "Tovbase ID Demo - Signed PDF and WebRTC media proof",
  description:
    "A browser-first Tovbase ID demo for signing a PDF or WebRTC-style media proof with a user-held key.",
};

export default function DemoPage() {
  return <DemoWorkbench />;
}
