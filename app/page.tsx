import { Hero } from "@/components/overview/hero"
import { StatGrid } from "@/components/overview/stat-grid"
import { PipelineDiagram } from "@/components/overview/pipeline-diagram"
import { ModuleTable } from "@/components/overview/module-table"
import { Limitations } from "@/components/overview/limitations"

export default function Page() {
  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-12 px-4 py-10 md:px-6 md:py-14">
      <Hero />
      <StatGrid />
      <PipelineDiagram />
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-3">
          <ModuleTable />
        </div>
        <div className="lg:col-span-2">
          <Limitations />
        </div>
      </div>
    </div>
  )
}
