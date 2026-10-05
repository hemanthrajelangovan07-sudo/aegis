import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import type { Match } from "@/lib/aho-corasick"

export function MatchTable({
  matches,
  patterns,
  patternLengths,
}: {
  matches: Match[]
  patterns: string[]
  patternLengths: number[]
}) {
  return (
    <Card>
      <CardContent>
        {matches.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">
            No matches — this payload would not escalate past the prefilter.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>End pos</TableHead>
                <TableHead>Span</TableHead>
                <TableHead>out(s)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {matches.map((m) => (
                <TableRow key={m.endPosition}>
                  <TableCell className="font-mono tabular-nums">{m.endPosition}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground tabular-nums">
                    {m.ruleIds
                      .map((id) => `${m.endPosition - patternLengths[id] + 1}–${m.endPosition}`)
                      .join(", ")}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {m.ruleIds.map((id) => (
                        <Badge key={id} variant="secondary" className="font-mono">
                          #{id} {patterns[id]}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
