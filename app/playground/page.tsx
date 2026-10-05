import type { Metadata } from "next"

import { PageHeader } from "@/components/page-header"
import { ScannerPlayground } from "@/components/scanner/scanner-playground"

export const metadata: Metadata = {
  title: "Scanner",
  description: "Compile patterns into an Aho-Corasick Next-Move DFA and scan payloads in your browser.",
}

export default function PlaygroundPage() {
  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-8 px-4 py-10 md:px-6">
      <PageHeader
        eyebrow="Module 1 · AC Prefilter"
        title="Aho-Corasick scanner"
        description="Patterns compile into a trie, failure links, and a dense Σ=256 Next-Move table — a faithful TypeScript port of ac_prefilter/. Every byte costs exactly one table lookup."
      />
      <ScannerPlayground />
    </div>
  )
}
