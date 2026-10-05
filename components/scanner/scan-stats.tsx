import type { compileAndScan } from "@/lib/aho-corasick"

type Result = ReturnType<typeof compileAndScan>

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / 1024 / 1024).toFixed(2)} MiB`
}

export function ScanStats({ result, matchCount }: { result: Result; matchCount: number }) {
  const stats = [
    { label: "Trie states", value: result.dfa.nStates.toLocaleString() },
    { label: "Transitions", value: result.transitions.toLocaleString(), hint: "= len(payload)" },
    { label: "Match events", value: matchCount.toLocaleString() },
    { label: "Byte classes", value: result.dfa.byteClasses.toLocaleString() },
    { label: "Dense table", value: formatBytes(result.denseBytes), hint: "int32 × 256" },
    {
      label: "Compile / scan",
      value: `${result.compileMs.toFixed(2)} / ${result.scanMs.toFixed(2)} ms`,
    },
  ]

  return (
    <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border bg-border sm:grid-cols-3">
      {stats.map((s) => (
        <div key={s.label} className="flex flex-col gap-1 bg-card p-4">
          <dt className="text-xs text-muted-foreground">{s.label}</dt>
          <dd className="font-mono text-lg font-semibold tabular-nums">{s.value}</dd>
          {s.hint && <dd className="font-mono text-xs text-muted-foreground">{s.hint}</dd>}
        </div>
      ))}
    </dl>
  )
}
