import Link from "next/link"
import { ArrowUpRightIcon, ScanLineIcon, ChartNoAxesCombinedIcon, DatabaseZapIcon } from "lucide-react"

import { SectionHeading } from "@/components/section-heading"
import { cn } from "@/lib/utils"

const FEATURES = [
  {
    href: "/playground",
    icon: ScanLineIcon,
    title: "Interactive scanner",
    body: "Compile your own patterns into a Next-Move DFA in the browser. Watch every byte transition, failure link, and match light up in real time.",
    cta: "Try it live",
    className: "lg:col-span-2 lg:row-span-2",
    visual: true,
  },
  {
    href: "/benchmarks",
    icon: ChartNoAxesCombinedIcon,
    title: "Benchmarks",
    body: "Flat latency as rules grow from 10 to 10,000. ReDoS-safe by construction.",
    cta: "View charts",
    className: "",
  },
  {
    href: "/sqli",
    icon: DatabaseZapIcon,
    title: "SQLi engine",
    body: "LALR(1) pushdown recognizer catches injections structurally, not by keywords.",
    cta: "Explore parser",
    className: "",
  },
]

const STATES = ["q0", "h", "he", "her", "hers", "s", "sh", "she"]

function TrieVisual() {
  return (
    <div className="mt-8 flex flex-col gap-4 rounded-2xl border border-foreground/10 bg-background/50 p-5 font-mono text-xs" aria-hidden="true">
      <div className="flex items-center justify-between text-muted-foreground">
        <span>patterns: he · she · his · hers</span>
        <span className="text-chart-5">2 matches</span>
      </div>
      <div className="flex gap-1 text-base">
        {"ushers".split("").map((c, i) => (
          <span
            key={i}
            className={cn(
              "flex size-9 items-center justify-center rounded-lg border",
              i >= 1 && i <= 3
                ? "border-accent/50 bg-accent/15 text-accent"
                : i >= 2
                  ? "border-primary/50 bg-primary/15 text-primary"
                  : "border-foreground/10 text-muted-foreground",
            )}
          >
            {c}
          </span>
        ))}
      </div>
      <div className="flex flex-wrap gap-2">
      {STATES.map((s, i) => (
        <span
          key={s}
          className={cn(
            "rounded-lg border px-2.5 py-1.5",
            s === "hers" || s === "she"
              ? "border-primary/50 bg-primary/15 text-primary shadow-[0_0_20px_-4px_oklch(0.86_0.15_192/0.6)]"
              : "border-foreground/10 bg-foreground/5 text-muted-foreground",
          )}
          style={{ animationDelay: `${i * 120}ms` }}
        >
          {s}
        </span>
      ))}
      </div>
    </div>
  )
}

export function FeatureBento() {
  return (
    <section aria-labelledby="features-title" className="flex flex-col gap-10">
      <SectionHeading
        id="features-title"
        eyebrow="Live demo"
        title="See it work, not just read about it"
        description="Every module is runnable in the browser with real data from the reference implementation."
      />
      <div className="grid gap-4 lg:grid-cols-3 lg:grid-rows-2">
        {FEATURES.map((f) => (
          <Link
            key={f.href}
            href={f.href}
            className={cn(
              "group glow-border relative flex flex-col overflow-hidden rounded-3xl bg-card/50 p-7 backdrop-blur-xl transition-all duration-300 hover:-translate-y-1 hover:bg-card/80 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
              f.className,
            )}
          >
            <div className="pointer-events-none absolute -right-20 -bottom-20 size-64 rounded-full bg-accent/10 blur-3xl transition-all duration-500 group-hover:bg-primary/20" />
            <div className="flex items-start justify-between">
              <span className="flex size-12 items-center justify-center rounded-2xl bg-linear-to-br from-primary/20 to-accent/20 text-primary ring-1 ring-foreground/10">
                <f.icon className="size-6" aria-hidden="true" />
              </span>
              <ArrowUpRightIcon
                className="size-5 text-muted-foreground transition-all group-hover:translate-x-0.5 group-hover:-translate-y-0.5 group-hover:text-primary"
                aria-hidden="true"
              />
            </div>
            <h3 className={cn("mt-6 font-bold tracking-tight", f.visual ? "text-3xl" : "text-xl")}>{f.title}</h3>
            <p className="mt-2 max-w-md leading-relaxed text-muted-foreground">{f.body}</p>
            {f.visual && <TrieVisual />}
            <span className="mt-auto pt-6 text-sm font-semibold text-primary">{f.cta} →</span>
          </Link>
        ))}
      </div>
    </section>
  )
}
