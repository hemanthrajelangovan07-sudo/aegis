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
import { baselines, SYSTEMS, type SystemKey } from "@/lib/report"

const chartConfig = {
  AEGIS_AC: { label: SYSTEMS.AEGIS_AC, color: "var(--chart-1)" },
  STANDARD_AC: { label: SYSTEMS.STANDARD_AC, color: "var(--chart-2)" },
  NAIVE_MULTIPATTERN: { label: SYSTEMS.NAIVE_MULTIPATTERN, color: "var(--chart-3)" },
  HYPERSCAN_SURICATA: { label: SYSTEMS.HYPERSCAN_SURICATA, color: "var(--chart-5)" },
} satisfies ChartConfig

const data = [100, 1000, 10000].map((k) => {
  const row: Record<string, number | string> = { k: k.toLocaleString() }
  for (const b of baselines.filter((x) => x.k === k)) row[b.system] = +(b.meanNs / 1000).toFixed(1)
  return row
})

export function LatencyChart() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Mean scan latency vs. ruleset size</CardTitle>
        <CardDescription>
          Microseconds per scan, log scale. The AEGIS-AC line stays flat; naive per-pattern search grows
          linearly with k.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ChartContainer config={chartConfig} className="aspect-auto h-80 w-full">
          <LineChart data={data} margin={{ left: 8, right: 16, top: 8 }}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="k" tickLine={false} axisLine={false} tickMargin={8} label={{ value: "k (rules)", position: "insideBottom", offset: -4 }} height={40} />
            <YAxis
              scale="log"
              domain={[1, 10000]}
              ticks={[1, 10, 100, 1000, 10000]}
              tickLine={false}
              axisLine={false}
              tickFormatter={(v: number) => `${v.toLocaleString()} μs`}
              width={72}
            />
            <ChartTooltip content={<ChartTooltipContent indicator="line" />} />
            <ChartLegend content={<ChartLegendContent />} />
            {(Object.keys(chartConfig) as SystemKey[]).map((key) => (
              <Line
                key={key}
                dataKey={key}
                type="monotone"
                stroke={`var(--color-${key})`}
                strokeWidth={key === "AEGIS_AC" ? 3 : 2}
                dot={{ r: 3 }}
              />
            ))}
          </LineChart>
        </ChartContainer>
      </CardContent>
      <CardFooter className="font-mono text-xs text-muted-foreground">
        AEGIS-AC: 246.6 μs → 227.7 μs → 201.9 μs · Naive: 69.5 μs → 718.9 μs → 7,262.6 μs
      </CardFooter>
    </Card>
  )
}
