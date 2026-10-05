import { ChevronRightIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge"

const TIERS = [
  {
    step: "00",
    name: "HTTP extraction",
    module: "pipeline/http_extraction.py",
    body: "Flow table tracks per-5-tuple state so scans resume across TCP packet boundaries.",
    tag: "Flow state",
  },
  {
    step: "01",
    name: "AC prefilter",
    module: "ac_prefilter/",
    body: "One Next-Move DFA over every fast-pattern. Exactly len(payload) transitions, independent of k.",
    tag: "O(n)",
  },
  {
    step: "02",
    name: "Verifier bank",
    module: "rule_compiler/",
    body: "Thompson → subset construction → Hopcroft. Unbounded patterns like (a+)+b are rejected at compile time.",
    tag: "Min-DFA",
  },
  {
    step: "03",
    name: "SQLi DPDA",
    module: "sqli_engine/",
    body: "Taint-aware lexer feeds an LALR(1) parser. Tainted tokens that shift structure latch an attack.",
    tag: "LALR(1)",
  },
  {
    step: "04",
    name: "Alert emitter",
    module: "pipeline/alert_emitter.py",
    body: "Alerts carry rule id, tier, match span and, for SQLi, the full production trace.",
    tag: "Alerts",
  },
]

export function PipelineDiagram() {
  return (
    <section aria-labelledby="pipeline-title" className="flex flex-col gap-6">
      <div className="flex flex-col gap-2">
        <h2 id="pipeline-title" className="text-2xl font-semibold tracking-tight">
          Detection pipeline
        </h2>
        <p className="max-w-2xl text-muted-foreground">
          Every packet takes the cheapest path possible. Only prefilter hits escalate to the
          verifier bank, and only tainted value slots reach the SQLi recognizer.
        </p>
      </div>
      <ol className="flex flex-col gap-3 lg:flex-row lg:items-stretch lg:gap-0">
        {TIERS.map((tier, i) => (
          <li key={tier.step} className="flex flex-col items-center lg:flex-1 lg:flex-row">
            <div className="flex h-full w-full flex-col gap-3 rounded-xl border bg-card p-4">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-muted-foreground">{tier.step}</span>
                <Badge variant="secondary" className="font-mono">
                  {tier.tag}
                </Badge>
              </div>
              <h3 className="font-medium">{tier.name}</h3>
              <p className="text-sm leading-relaxed text-muted-foreground">{tier.body}</p>
              <code className="mt-auto truncate font-mono text-xs text-primary">{tier.module}</code>
            </div>
            {i < TIERS.length - 1 && (
              <ChevronRightIcon
                className="my-1 size-4 shrink-0 rotate-90 text-muted-foreground lg:mx-1 lg:my-0 lg:rotate-0"
                aria-hidden="true"
              />
            )}
          </li>
        ))}
      </ol>
    </section>
  )
}
