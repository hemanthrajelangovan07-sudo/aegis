"use client"

import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts"

import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import { memoryByK } from "@/lib/report"

const chartConfig = {
  denseMiB: { label: "Dense (Σ=256)", color: "var(--chart-4)" },
  classMiB: { label: "Byte-class reduced", color: "var(--chart-1)" },
} satisfies ChartConfig

const data = memoryByK.map((m) => ({ ...m, kLabel: m.k.toLocaleString() }))

export function MemoryChart() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Transition table memory</CardTitle>
        <CardDescription>MiB by layout. Trie states grow ~0.7× the total pattern bytes.</CardDescription>
      </CardHeader>
      <CardContent>
        <ChartContainer config={chartConfig} className="aspect-auto h-64 w-full">
          <BarChart data={data} margin={{ left: 0, right: 8, top: 8 }}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="kLabel" tickLine={false} axisLine={false} tickMargin={8} />
            <YAxis tickLine={false} axisLine={false} width={40} />
            <ChartTooltip content={<ChartTooltipContent />} />
            <ChartLegend content={<ChartLegendContent />} />
            <Bar dataKey="denseMiB" fill="var(--color-denseMiB)" radius={4} />
            <Bar dataKey="classMiB" fill="var(--color-classMiB)" radius={4} />
          </BarChart>
        </ChartContainer>
      </CardContent>
      <CardFooter className="font-mono text-xs text-muted-foreground">
        k = 10,000 → 98,822 states · 96.5 MiB dense · 43.5 MiB class-reduced
      </CardFooter>
    </Card>
  )
}
