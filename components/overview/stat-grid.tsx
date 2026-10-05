import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"

const STATS = [
  {
    value: "98,822",
    label: "Trie states at k = 10,000",
    detail: "0.697 states per pattern byte",
  },
  {
    value: "~200 μs",
    label: "Flat scan latency across k",
    detail: "Naive search grows 70 μs → 7.3 ms",
  },
  {
    value: "1,689",
    label: "Canonical LR(1) states",
    detail: "179-state LALR(1) core, 0 conflicts",
  },
  {
    value: "99.9%",
    label: "Lenient SQLi recall",
    detail: "85,791 real libinjection payloads",
  },
]

export function StatGrid() {
  return (
    <section aria-label="Headline measurements">
      <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {STATS.map((stat) => (
          <Card key={stat.label}>
            <CardHeader>
              <dt className="text-sm text-muted-foreground">{stat.label}</dt>
              <dd>
                <CardTitle className="font-mono text-3xl font-semibold tracking-tight text-primary">
                  {stat.value}
                </CardTitle>
              </dd>
              <CardDescription className="font-mono text-xs">{stat.detail}</CardDescription>
            </CardHeader>
          </Card>
        ))}
      </dl>
    </section>
  )
}
