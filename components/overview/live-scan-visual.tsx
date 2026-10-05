import { ShieldAlertIcon, CheckCircle2Icon } from "lucide-react"

const LINES: { text: string; hit?: string; tone?: "danger" | "warn" }[] = [
  { text: "GET /api/users?id=42 HTTP/1.1" },
  { text: "Host: shop.example.com" },
  { text: "GET /search?q=1' UNION SELECT pass FROM users--", hit: "UNION SELECT", tone: "danger" },
  { text: "User-Agent: Mozilla/5.0 (X11; Linux)" },
  { text: "GET /../../etc/passwd HTTP/1.1", hit: "../../etc/passwd", tone: "warn" },
  { text: "Accept: text/html,application/xhtml+xml" },
  { text: "POST /login body=<script>alert(1)</script>", hit: "<script>", tone: "warn" },
]

function Line({ line, index }: { line: (typeof LINES)[number]; index: number }) {
  const parts = line.hit ? line.text.split(line.hit) : [line.text]
  return (
    <div className="flex gap-3">
      <span className="w-5 shrink-0 text-right text-muted-foreground/50 select-none">{index + 1}</span>
      <span className="truncate">
        {parts[0]}
        {line.hit && (
          <mark
            className={
              line.tone === "danger"
                ? "rounded bg-destructive/20 px-0.5 text-destructive ring-1 ring-destructive/40"
                : "rounded bg-accent/20 px-0.5 text-accent ring-1 ring-accent/40"
            }
          >
            {line.hit}
          </mark>
        )}
        {parts[1]}
      </span>
    </div>
  )
}

export function LiveScanVisual() {
  return (
    <div className="relative animate-float" aria-hidden="true">
      <div className="absolute -inset-10 -z-10 rounded-full bg-linear-to-tr from-primary/25 via-accent/20 to-transparent blur-3xl" />

      <div className="glow-border overflow-hidden rounded-3xl bg-card/70 shadow-[0_40px_120px_-30px_oklch(0_0_0/0.8)] backdrop-blur-2xl">
        <div className="flex items-center gap-2 border-b border-foreground/10 px-4 py-3">
          <span className="size-3 rounded-full bg-destructive/80" />
          <span className="size-3 rounded-full bg-chart-1/30" />
          <span className="size-3 rounded-full bg-chart-5/80" />
          <span className="ml-3 font-mono text-xs text-muted-foreground">aegis-ac · eth0 · live</span>
          <span className="ml-auto flex items-center gap-1.5 rounded-full bg-chart-5/15 px-2 py-0.5 font-mono text-[10px] text-chart-5">
            <span className="size-1.5 rounded-full bg-chart-5 animate-pulse-dot" />
            SCANNING
          </span>
        </div>

        <div className="relative overflow-hidden px-4 py-4 font-mono text-[12.5px] leading-7 text-foreground/80">
          <div className="pointer-events-none absolute inset-x-0 top-0 h-10 animate-scan-line bg-linear-to-b from-transparent via-primary/20 to-transparent">
            <div className="absolute inset-x-0 top-1/2 h-px bg-primary/70 shadow-[0_0_12px_oklch(0.86_0.15_192)]" />
          </div>
          {LINES.map((line, i) => (
            <Line key={i} line={line} index={i} />
          ))}
        </div>

        <div className="grid grid-cols-3 border-t border-foreground/10 font-mono">
          <div className="flex flex-col gap-0.5 border-r border-foreground/10 px-4 py-3">
            <span className="text-[10px] tracking-widest text-muted-foreground uppercase">Throughput</span>
            <span className="text-sm font-semibold text-primary">1.2 Gb/s</span>
          </div>
          <div className="flex flex-col gap-0.5 border-r border-foreground/10 px-4 py-3">
            <span className="text-[10px] tracking-widest text-muted-foreground uppercase">Latency</span>
            <span className="text-sm font-semibold">~200 μs</span>
          </div>
          <div className="flex flex-col gap-0.5 px-4 py-3">
            <span className="text-[10px] tracking-widest text-muted-foreground uppercase">Alerts</span>
            <span className="text-sm font-semibold text-destructive">3 blocked</span>
          </div>
        </div>
      </div>

      <div className="absolute -bottom-16 left-8 hidden items-center gap-3 rounded-2xl border border-destructive/30 bg-card/90 px-4 py-3 shadow-2xl backdrop-blur-xl sm:flex">
        <span className="flex size-9 items-center justify-center rounded-xl bg-destructive/15 text-destructive">
          <ShieldAlertIcon className="size-4" />
        </span>
        <div className="flex flex-col">
          <span className="text-sm font-semibold">SQLi blocked</span>
          <span className="font-mono text-[11px] text-muted-foreground">rule 1:942100 · DPDA</span>
        </div>
      </div>

      <div className="absolute -top-5 -right-3 hidden items-center gap-2 rounded-xl border border-chart-5/30 bg-card/90 px-3 py-2 shadow-2xl backdrop-blur-xl sm:flex">
        <CheckCircle2Icon className="size-4 text-chart-5" />
        <span className="font-mono text-xs">O(n) · k-independent</span>
      </div>
    </div>
  )
}
