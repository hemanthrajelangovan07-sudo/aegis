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
import { byteToChar, labelToString, type ACTrie } from "@/lib/aho-corasick"

const MAX_ROWS = 200

export function TrieTable({ trie, patterns }: { trie: ACTrie; patterns: string[] }) {
  const rows = trie.goto.slice(0, MAX_ROWS)

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <div className="max-h-96 overflow-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>State</TableHead>
                <TableHead>Label</TableHead>
                <TableHead>goto</TableHead>
                <TableHead>fail</TableHead>
                <TableHead>out</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((edges, s) => (
                <TableRow key={s}>
                  <TableCell className="font-mono tabular-nums">{s}</TableCell>
                  <TableCell className="font-mono">{labelToString(trie.label[s])}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {edges.size === 0
                      ? "—"
                      : [...edges].map(([b, t]) => `${byteToChar(b)}→${t}`).join("  ")}
                  </TableCell>
                  <TableCell className="font-mono tabular-nums">{s === 0 ? "—" : trie.fail[s]}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {[...trie.out[s]].sort((a, b) => a - b).map((id) => (
                        <Badge key={id} variant="outline" className="font-mono">
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
        {trie.goto.length > MAX_ROWS && (
          <p className="text-xs text-muted-foreground">
            Showing first {MAX_ROWS} of {trie.goto.length.toLocaleString()} states.
          </p>
        )}
      </CardContent>
    </Card>
  )
}
