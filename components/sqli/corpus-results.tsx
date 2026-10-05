import { InfoIcon } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { sqliCorpus } from "@/lib/report"

function Segment({ label, count, total, tone }: { label: string; count: number; total: number; tone: string }) {
  const pct = (count / total) * 100
  return (
    <div className="flex items-center justify-between gap-3 text-sm">
      <span className="flex items-center gap-2">
        <span className={`size-2.5 rounded-sm ${tone}`} aria-hidden="true" />
        {label}
      </span>
      <span className="font-mono tabular-nums text-muted-foreground">
        {count.toLocaleString()} · {pct.toFixed(1)}%
      </span>
    </div>
  )
}

function StackedBar({ parts, total }: { parts: { count: number; tone: string }[]; total: number }) {
  return (
    <div className="flex h-3 w-full overflow-hidden rounded-full bg-muted" aria-hidden="true">
      {parts.map((p, i) => (
        <div key={i} className={p.tone} style={{ width: `${(p.count / total) * 100}%` }} />
      ))}
    </div>
  )
}

export function CorpusResults() {
  const { malicious: m, benign: b } = sqliCorpus

  const malParts = [
    { label: "Caught (strict)", count: m.strictCatch, tone: "bg-primary" },
    { label: "Unparseable → flagged", count: m.unparseable, tone: "bg-chart-2" },
    { label: "Missed", count: m.miss, tone: "bg-destructive" },
  ]
  const benParts = [
    { label: "Correctly benign", count: b.correct, tone: "bg-chart-5" },
    { label: "False positive", count: b.falsePositive, tone: "bg-destructive" },
    { label: "Unparseable", count: b.unparseable, tone: "bg-chart-4" },
  ]

  return (
    <section aria-labelledby="corpus-title" className="flex flex-col gap-4">
      <h2 id="corpus-title" className="text-2xl font-semibold tracking-tight">
        libinjection corpus evaluation
      </h2>
      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Malicious payloads</CardTitle>
            <CardDescription>
              {m.n.toLocaleString()} payloads · strict recall {(m.strictRecall * 100).toFixed(1)}% · lenient
              recall {(m.lenientRecall * 100).toFixed(1)}%
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <StackedBar parts={malParts} total={m.n} />
            <div className="flex flex-col gap-2">
              {malParts.map((p) => (
                <Segment key={p.label} {...p} total={m.n} />
              ))}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Benign inputs</CardTitle>
            <CardDescription>
              {b.n.toLocaleString()} inputs · false-positive rate {(b.fpRate * 100).toFixed(2)}%
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <StackedBar parts={benParts} total={b.n} />
            <div className="flex flex-col gap-2">
              {benParts.map((p) => (
                <Segment key={p.label} {...p} total={b.n} />
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
      <Alert>
        <InfoIcon />
        <AlertTitle>Read the unparseable bucket honestly</AlertTitle>
        <AlertDescription>
          89% of real payloads use SQL outside the implemented DML subset (functions, comments, dialect
          syntax). A parse failure on tainted input is treated as suspicious, which is where the 99.9% lenient
          recall comes from. Full corpus evaluated in {sqliCorpus.elapsedS}s.
        </AlertDescription>
      </Alert>
    </section>
  )
}
