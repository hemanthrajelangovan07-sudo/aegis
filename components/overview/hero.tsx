import Link from "next/link"
import { ArrowRightIcon, ChartLineIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"

export function Hero() {
  return (
    <section className="flex flex-col gap-6" aria-labelledby="hero-title">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="secondary" className="font-mono">
          Network IDS · Reference implementation
        </Badge>
        <Badge variant="outline" className="font-mono">
          Σ = 256 · 1 transition / byte
        </Badge>
      </div>
      <h1
        id="hero-title"
        className="max-w-3xl text-4xl font-semibold tracking-tight text-balance md:text-5xl"
      >
        Signature matching that doesn&apos;t slow down as the ruleset grows.
      </h1>
      <p className="max-w-2xl text-lg leading-relaxed text-pretty text-muted-foreground">
        AEGIS-AC compiles thousands of Snort-style rules into a single Aho-Corasick Next-Move DFA,
        escalates only real candidates to a minimized regex verifier bank, and recognizes SQL
        injection structurally with an LALR(1) pushdown automaton.
      </p>
      <div className="flex flex-wrap gap-3">
        <Button render={<Link href="/playground" />} nativeButton={false}>
          Open the scanner
          <ArrowRightIcon data-icon="inline-end" />
        </Button>
        <Button variant="outline" render={<Link href="/benchmarks" />} nativeButton={false}>
          <ChartLineIcon data-icon="inline-start" />
          View benchmarks
        </Button>
      </div>
    </section>
  )
}
