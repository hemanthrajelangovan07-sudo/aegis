import Link from "next/link"
import { ArrowRightIcon, ChartLineIcon, SparklesIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { LiveScanVisual } from "@/components/overview/live-scan-visual"

export function Hero() {
  return (
    <section
      className="relative grid items-center gap-12 pt-6 lg:grid-cols-[1.1fr_1fr] lg:gap-10 lg:pt-12"
      aria-labelledby="hero-title"
    >
      <div className="flex flex-col gap-7">
        <div className="flex w-fit items-center gap-2 rounded-full border border-primary/25 bg-primary/10 py-1 pr-3 pl-1 text-xs font-medium text-primary">
          <span className="flex items-center gap-1 rounded-full bg-primary px-2 py-0.5 text-primary-foreground">
            <SparklesIcon className="size-3" aria-hidden="true" />
            New
          </span>
          k-independent detection engine
        </div>

        <h1
          id="hero-title"
          className="text-5xl leading-[1.02] font-bold tracking-tight text-balance md:text-6xl xl:text-7xl"
        >
          Detect every attack.{" "}
          <span className="text-gradient">At line speed.</span>
        </h1>

        <p className="max-w-xl text-lg leading-relaxed text-pretty text-muted-foreground">
          AEGIS-AC compiles thousands of Snort-style rules into a single Aho-Corasick automaton,
          verifies candidates with minimized regex DFAs, and catches SQL injection structurally with
          an LALR(1) pushdown automaton.
        </p>

        <div className="flex flex-wrap items-center gap-3">
          <Button
            size="lg"
            className="h-11 rounded-xl px-5 shadow-[0_0_40px_-6px_oklch(0.86_0.15_192/0.6)]"
            render={<Link href="/playground" />}
            nativeButton={false}
          >
            Launch live scanner
            <ArrowRightIcon data-icon="inline-end" />
          </Button>
          <Button
            size="lg"
            variant="outline"
            className="h-11 rounded-xl px-5 backdrop-blur"
            render={<Link href="/benchmarks" />}
            nativeButton={false}
          >
            <ChartLineIcon data-icon="inline-start" />
            See benchmarks
          </Button>
        </div>

        <dl className="flex flex-wrap gap-x-8 gap-y-3 border-t border-foreground/10 pt-6 font-mono text-sm">
          <div className="flex flex-col gap-0.5">
            <dt className="text-xs text-muted-foreground">Rules compiled</dt>
            <dd className="text-lg font-semibold">10,000</dd>
          </div>
          <div className="flex flex-col gap-0.5">
            <dt className="text-xs text-muted-foreground">Cost per byte</dt>
            <dd className="text-lg font-semibold">1 lookup</dd>
          </div>
          <div className="flex flex-col gap-0.5">
            <dt className="text-xs text-muted-foreground">Grammar conflicts</dt>
            <dd className="text-lg font-semibold">0</dd>
          </div>
        </dl>
      </div>

      <LiveScanVisual />
    </section>
  )
}
