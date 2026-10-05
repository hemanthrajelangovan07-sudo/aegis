"use client"

import { CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts"

import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import { redos } from "@/lib/report"

const chartConfig = {
  aegisMs: { label: "AEGIS-AC min-DFA", color: "var(--chart-1)" },
  backtrackMs: { label: "Backtracking (Python re)", color: "var(--chart-3)" },
} satisfies ChartConfig

const data = redos.map((r) => ({ n: r.n, aegisMs: +(r.aegisUs / 1000).toFixed(4), backtrackMs: r.backtrackMs }))

export function RedosChart() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>ReDoS resistance</CardTitle>
        <CardDescription>
          <code className="font-mono">(a+)+b</code> against <code className="font-mono">{"\"a\" * n"}</code>,
          milliseconds on a log scale.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ChartContainer config={chartConfig} className="aspect-auto h-72 w-full">
          <LineChart data={data} margin={{ left: 0, right: 16, top: 8 }}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="n" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => `n=${v}`} />
            <YAxis
              scale="log"
              domain={[0.01, 1000]}
              ticks={[0.01, 0.1, 1, 10, 100, 1000]}
              allowDataOverflow
              tickLine={false}
              axisLine={false}
              width={48}
            />
            <ChartTooltip content={<ChartTooltipContent indicator="line" />} />
            <ChartLegend content={<ChartLegendContent />} />
            <Line dataKey="aegisMs" stroke="var(--color-aegisMs)" strokeWidth={3} dot={{ r: 3 }} />
            <Line dataKey="backtrackMs" stroke="var(--color-backtrackMs)" strokeWidth={2} dot={{ r: 3 }} />
          </LineChart>
        </ChartContainer>
      </CardContent>
      <CardFooter className="font-mono text-xs text-muted-foreground">
        n = 22: 0.065 ms vs 310.6 ms — backtracking doubles per character.
      </CardFooter>
    </Card>
  )
}
