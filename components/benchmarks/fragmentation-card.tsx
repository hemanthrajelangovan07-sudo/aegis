import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { fragmentation } from "@/lib/report"

export function FragmentationCard() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>TCP fragmentation</CardTitle>
        <CardDescription>
          Detection rate when payloads are split across packets. Persisting the AC state per flow makes
          fragmented and whole-payload detection identical.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {fragmentation.map((f) => (
          <div key={f.rate} className="flex items-center gap-4">
            <span className="w-24 shrink-0 font-mono text-xs text-muted-foreground">
              {Math.round(f.rate * 100)}% split
            </span>
            <Progress value={f.fragmented * 100} aria-label={`Detection rate at ${f.rate * 100}% fragmentation`} className="flex-1" />
            <span className="w-12 text-right font-mono text-sm tabular-nums">{(f.fragmented * 100).toFixed(0)}%</span>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
