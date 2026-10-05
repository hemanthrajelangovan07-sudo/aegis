"use client"

import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts"

import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { selectivity } from "@/lib/report"

const chartConfig = {
  ratePct: { label: "Escalation rate (%)", color: "var(--chart-2)" },
} satisfies ChartConfig

const data = selectivity.map((s) => ({
  anchor: `${s.anchorLen}B`,
  ratePct: +(s.rate * 100).toFixed(4),
}))

export function SelectivityChart() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Prefilter selectivity</CardTitle>
        <CardDescription>
          Share of 200,000 payloads escalated to the verifier, by fast-pattern anchor length (log scale).
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ChartContainer config={chartConfig} className="aspect-auto h-64 w-full">
          <BarChart data={data} margin={{ left: 0, right: 8, top: 8 }}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="anchor" tickLine={false} axisLine={false} tickMargin={8} />
            <YAxis
              scale="log"
              domain={[0.001, 100]}
              ticks={[0.01, 0.1, 1, 10, 100]}
              allowDataOverflow
              tickLine={false}
              axisLine={false}
              tickFormatter={(v: number) => `${v}%`}
              width={48}
            />
            <ChartTooltip content={<ChartTooltipContent hideLabel />} />
            <Bar dataKey="ratePct" fill="var(--color-ratePct)" radius={4} />
          </BarChart>
        </ChartContainer>
      </CardContent>
      <CardFooter className="font-mono text-xs text-muted-foreground">
        2-byte anchors escalate 83.5% of traffic; 4+ bytes drop below 0.09%.
      </CardFooter>
    </Card>
  )
}
