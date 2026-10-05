import type { Metadata } from "next"

import { PageHeader } from "@/components/page-header"
import { LatencyChart } from "@/components/benchmarks/latency-chart"
import { MemoryChart } from "@/components/benchmarks/memory-chart"
import { SelectivityChart } from "@/components/benchmarks/selectivity-chart"
import { RedosChart } from "@/components/benchmarks/redos-chart"
import { StorageTable } from "@/components/benchmarks/storage-table"
import { FragmentationCard } from "@/components/benchmarks/fragmentation-card"

export const metadata: Metadata = {
  title: "Benchmarks",
  description: "Scan latency, memory, selectivity, ReDoS resistance and fragmentation results for AEGIS-AC.",
}

export default function BenchmarksPage() {
  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-8 px-4 py-10 md:px-6">
      <PageHeader
        eyebrow="Module 5 · Instrumentation"
        title="Benchmarks"
        description="Synthetic Snort-shaped rulesets at k ∈ {100, 300, 1000, 3000, 10000} against a 200,000-payload corpus. All values are from REPORT.md; the pure-Python engine is the reference, so compare shapes, not absolute throughput."
      />
      <LatencyChart />
      <div className="grid gap-6 lg:grid-cols-2">
        <MemoryChart />
        <SelectivityChart />
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <RedosChart />
        <div className="flex flex-col gap-6">
          <StorageTable />
          <FragmentationCard />
        </div>
      </div>
    </div>
  )
}
