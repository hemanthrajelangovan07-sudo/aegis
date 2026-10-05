import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableFooter,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { modules } from "@/lib/report"

export function ModuleTable() {
  const total = modules.reduce((sum, m) => sum + m.tests, 0)

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Modules</CardTitle>
        <CardDescription>All five spec modules are implemented and wired end to end.</CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-10">#</TableHead>
              <TableHead>Module</TableHead>
              <TableHead className="hidden sm:table-cell">Path</TableHead>
              <TableHead className="text-right">Tests</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {modules.map((m) => (
              <TableRow key={m.id}>
                <TableCell className="font-mono text-muted-foreground">{m.id}</TableCell>
                <TableCell>
                  <div className="flex flex-col">
                    <span className="font-medium">{m.name}</span>
                    <span className="text-xs text-muted-foreground">{m.owner}</span>
                  </div>
                </TableCell>
                <TableCell className="hidden font-mono text-xs sm:table-cell">{m.path}</TableCell>
                <TableCell className="text-right font-mono">{m.tests}</TableCell>
              </TableRow>
            ))}
          </TableBody>
          <TableFooter>
            <TableRow>
              <TableCell colSpan={2}>Total</TableCell>
              <TableCell className="hidden sm:table-cell" />
              <TableCell className="text-right font-mono">{total}/78</TableCell>
            </TableRow>
          </TableFooter>
        </Table>
      </CardContent>
    </Card>
  )
}
