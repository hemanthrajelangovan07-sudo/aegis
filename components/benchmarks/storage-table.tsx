import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { storageLayout } from "@/lib/report"

export function StorageTable() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Storage layout ablation</CardTitle>
        <CardDescription>Dense Σ=256 rows vs. byte-class-reduced rows.</CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>k</TableHead>
              <TableHead>Layout</TableHead>
              <TableHead className="text-right">Cols</TableHead>
              <TableHead className="text-right">MiB</TableHead>
              <TableHead className="text-right">ns/B</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {storageLayout.map((row) => (
              <TableRow key={`${row.k}-${row.layout}`}>
                <TableCell className="font-mono tabular-nums">{row.k.toLocaleString()}</TableCell>
                <TableCell>
                  <Badge variant={row.layout === "dense" ? "outline" : "secondary"} className="font-mono">
                    {row.layout}
                  </Badge>
                </TableCell>
                <TableCell className="text-right font-mono tabular-nums">{row.entries}</TableCell>
                <TableCell className="text-right font-mono tabular-nums">{row.memoryMiB.toFixed(2)}</TableCell>
                <TableCell className="text-right font-mono tabular-nums">{row.nsPerByte.toFixed(1)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
