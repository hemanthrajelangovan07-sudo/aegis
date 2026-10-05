const FACTS = [
  { value: "1,689", label: "Canonical LR(1) states" },
  { value: "179", label: "LALR(1) states after merge" },
  { value: "0", label: "Shift/reduce or reduce/reduce conflicts" },
  { value: "85,791", label: "Real attack payloads evaluated" },
]

export function ParserFacts() {
  return (
    <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border bg-border lg:grid-cols-4">
      {FACTS.map((f) => (
        <div key={f.label} className="flex flex-col gap-1 bg-card p-5">
          <dd className="font-mono text-2xl font-semibold tabular-nums text-primary">{f.value}</dd>
          <dt className="text-sm text-muted-foreground">{f.label}</dt>
        </div>
      ))}
    </dl>
  )
}
