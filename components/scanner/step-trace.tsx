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
import { byteToChar, type ScanStep } from "@/lib/aho-corasick"

const MAX_ROWS = 256

export function StepTrace({ steps, patterns }: { steps: ScanStep[]; patterns: string[] }) {
  const rows = steps.slice(0, MAX_ROWS)

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <p className="text-sm text-muted-foreground">
          <code className="font-mono text-foreground">s = δ[s][byte]</code> — one lookup per byte,
          no failure-link chasing at scan time.
        </p>
        <div className="max-h-96 overflow-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>i</TableHead>
                <TableHead>Byte</TableHead>
                <TableHead>Transition</TableHead>
                <TableHead>Emit</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((step) => (
                <TableRow key={step.index}>
                  <TableCell className="font-mono tabular-nums">{step.index}</TableCell>
                  <TableCell className="font-mono">
                    {byteToChar(step.byte)}{" "}
                    <span className="text-xs text-muted-foreground">
                      0x{step.byte.toString(16).padStart(2, "0")}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono tabular-nums">
                    {step.from} → {step.to}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {step.hits.map((id) => (
                        <Badge key={id} className="font-mono">
                          {patterns[id]}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {steps.length > MAX_ROWS && (
          <p className="text-xs text-muted-foreground">
            Showing first {MAX_ROWS} of {steps.length.toLocaleString()} steps.
          </p>
        )}
      </CardContent>
    </Card>
  )
}
