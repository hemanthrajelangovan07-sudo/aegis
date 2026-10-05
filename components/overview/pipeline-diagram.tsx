import { GlobeIcon, FilterIcon, ScanSearchIcon, DatabaseZapIcon, BellRingIcon } from "lucide-react"

import { SectionHeading } from "@/components/section-heading"

const TIERS = [
  {
    step: "00",
    icon: GlobeIcon,
    name: "HTTP extraction",
    module: "pipeline/http_extraction.py",
    body: "Per-5-tuple flow table lets scans resume across TCP packet boundaries.",
    tag: "Flow state",
  },
  {
    step: "01",
    icon: FilterIcon,
    name: "AC prefilter",
    module: "ac_prefilter/",
    body: "One Next-Move DFA over every fast-pattern. Exactly len(payload) transitions.",
    tag: "O(n)",
  },
  {
    step: "02",
    icon: ScanSearchIcon,
    name: "Verifier bank",
    module: "rule_compiler/",
    body: "Thompson → subset → Hopcroft. ReDoS-prone patterns rejected at compile time.",
    tag: "Min-DFA",
  },
  {
    step: "03",
    icon: DatabaseZapIcon,
    name: "SQLi DPDA",
    module: "sqli_engine/",
    body: "Taint-aware lexer + LALR(1) parser. Tainted tokens that shift structure latch an attack.",
    tag: "LALR(1)",
  },
  {
    step: "04",
    icon: BellRingIcon,
    name: "Alert emitter",
    module: "pipeline/alert_emitter.py",
    body: "Alerts carry rule id, tier, match span, and the full SQLi production trace.",
    tag: "Alerts",
  },
]

export function PipelineDiagram() {
  return (
    <section aria-labelledby="pipeline-title" className="flex flex-col gap-10">
      <SectionHeading
        id="pipeline-title"
        eyebrow="Architecture"
        title="A five-stage detection pipeline"
        description="Every packet takes the cheapest path possible. Only prefilter hits escalate to the verifier bank, and only tainted value slots reach the SQLi recognizer."
      />

      <div className="relative">
        <div
          className="absolute top-7 right-[10%] left-[10%] hidden h-px animate-flow bg-linear-to-r from-transparent via-primary to-transparent lg:block"
          aria-hidden="true"
        />
        <ol className="relative grid gap-4 lg:grid-cols-5">
          {TIERS.map((tier) => (
            <li key={tier.step} className="group flex flex-col items-start gap-5 lg:items-center">
              <span className="relative flex size-14 items-center justify-center rounded-2xl border border-primary/30 bg-background text-primary shadow-[0_0_30px_-4px_oklch(0.86_0.15_192/0.5)] transition-all group-hover:scale-110 group-hover:border-accent/60 group-hover:text-accent">
                <tier.icon className="size-6" aria-hidden="true" />
                <span className="absolute -top-2 -right-2 rounded-md bg-secondary px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground ring-1 ring-foreground/10">
                  {tier.step}
                </span>
              </span>
              <div className="flex h-full w-full flex-col gap-3 rounded-2xl border border-foreground/10 bg-card/50 p-5 backdrop-blur-xl transition-colors group-hover:border-primary/30 group-hover:bg-card/80">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="font-semibold">{tier.name}</h3>
                  <span className="rounded-full bg-primary/10 px-2 py-0.5 font-mono text-[10px] text-primary">
                    {tier.tag}
                  </span>
                </div>
                <p className="text-sm leading-relaxed text-muted-foreground">{tier.body}</p>
                <code className="mt-auto truncate font-mono text-xs text-accent">{tier.module}</code>
              </div>
            </li>
          ))}
        </ol>
      </div>
    </section>
  )
}
