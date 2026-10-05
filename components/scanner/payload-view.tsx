import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { byteToChar, type Match } from "@/lib/aho-corasick"
import { cn } from "@/lib/utils"

export function PayloadView({
  bytes,
  matches,
  patternLengths,
}: {
  bytes: Uint8Array
  matches: Match[]
  patternLengths: number[]
}) {
  const covered = new Uint8Array(bytes.length)
  const ends = new Set<number>()
  for (const m of matches) {
    ends.add(m.endPosition)
    for (const id of m.ruleIds) {
      const start = Math.max(0, m.endPosition - patternLengths[id] + 1)
      for (let i = start; i <= m.endPosition; i++) covered[i] = 1
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Payload</CardTitle>
        <CardDescription>
          Highlighted bytes fall inside a match. Solid cells mark the end position where{" "}
          <code className="font-mono">out(s)</code> fired.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {bytes.length === 0 ? (
          <p className="text-sm text-muted-foreground">Enter a payload to scan.</p>
        ) : (
          <div
            className="flex flex-wrap gap-y-1 rounded-lg bg-muted/40 p-3 font-mono text-sm"
            aria-label="Scanned payload with matches highlighted"
          >
            {Array.from(bytes, (byte, i) => (
              <span
                key={i}
                title={`byte ${i} · 0x${byte.toString(16).padStart(2, "0")}`}
                className={cn(
                  "inline-flex min-w-[1ch] justify-center px-px",
                  covered[i] && "bg-primary/20 text-primary",
                  ends.has(i) && "rounded-sm bg-primary text-primary-foreground",
                )}
              >
                {byteToChar(byte)}
              </span>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
