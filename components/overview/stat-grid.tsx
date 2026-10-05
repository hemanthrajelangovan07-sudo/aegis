import { NetworkIcon, GaugeIcon, BracesIcon, CrosshairIcon } from "lucide-react"

const STATS = [
  {
    icon: NetworkIcon,
    value: "98,822",
    label: "Trie states at k = 10,000",
    detail: "0.697 states per pattern byte",
  },
  {
    icon: GaugeIcon,
    value: "~200μs",
    label: "Flat scan latency across k",
    detail: "Naive search: 70 μs → 7.3 ms",
  },
  {
    icon: BracesIcon,
    value: "1,689",
    label: "Canonical LR(1) states",
    detail: "179-state LALR(1) core, 0 conflicts",
  },
  {
    icon: CrosshairIcon,
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
          <div
            key={stat.label}
            className="group glow-border relative flex flex-col gap-4 overflow-hidden rounded-2xl bg-card/50 p-6 backdrop-blur-xl transition-transform duration-300 hover:-translate-y-1"
          >
            <div className="pointer-events-none absolute -top-16 -right-16 size-40 rounded-full bg-primary/10 blur-3xl transition-opacity group-hover:bg-accent/20" />
            <span className="flex size-10 items-center justify-center rounded-xl border border-foreground/10 bg-foreground/5 text-primary">
              <stat.icon className="size-5" aria-hidden="true" />
            </span>
            <div className="flex flex-col gap-1">
              <dd className="order-2 bg-linear-to-br from-foreground to-foreground/60 bg-clip-text font-mono text-4xl font-bold tracking-tight text-transparent">
                {stat.value}
              </dd>
              <dt className="order-1 text-sm font-medium text-muted-foreground">{stat.label}</dt>
            </div>
            <p className="border-t border-foreground/10 pt-3 font-mono text-xs text-muted-foreground">
              {stat.detail}
            </p>
          </div>
        ))}
      </dl>
    </section>
  )
}
