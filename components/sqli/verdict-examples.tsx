import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { sqliVerdicts } from "@/lib/report"

export function VerdictExamples() {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>How verdicts are decided</CardTitle>
        <CardDescription>
          Highlighted text is the tainted (user-supplied) slot. Static query text is never suspect.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {sqliVerdicts.map((v, i) => (
          <div key={v.label} className="flex flex-col gap-4">
            {i > 0 && <Separator />}
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-sm font-medium">{v.label}</h3>
                <Badge variant={v.isAttack ? "destructive" : "secondary"} className="font-mono">
                  {v.isAttack ? "ATTACK" : "BENIGN"}
                </Badge>
              </div>
              <pre className="overflow-x-auto rounded-lg bg-muted/50 p-3 font-mono text-sm whitespace-pre-wrap">
                <span className="text-muted-foreground">{v.staticPart}</span>
                <mark className="rounded-sm bg-primary/20 px-0.5 text-primary">{v.tainted}</mark>
                <span className="text-muted-foreground">{v.suffix}</span>
              </pre>
              <p className="text-xs text-muted-foreground">
                {v.isAttack
                  ? "Tainted tokens were shifted as SQL keywords/operators — the tree shape changed."
                  : v.staticPart
                    ? "Tainted tokens reduce to a single literal — the tree shape is unchanged."
                    : "Parsed with no taint latch — a well-formed, side-effect-free expression."}
              </p>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
