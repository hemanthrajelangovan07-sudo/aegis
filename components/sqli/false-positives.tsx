import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { sqliCorpus } from "@/lib/report"

export function FalsePositives() {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Sample false positives</CardTitle>
        <CardDescription>
          Product-name strings that happen to form valid boolean SQL when tainted.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col gap-2">
          {sqliCorpus.falsePositives.map((fp) => (
            <li key={fp} className="rounded-md border bg-muted/30 px-3 py-2 font-mono text-sm">
              {fp}
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  )
}
