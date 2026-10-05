import { Hero } from "@/components/overview/hero"
import { StatGrid } from "@/components/overview/stat-grid"
import { SignatureMarquee } from "@/components/overview/signature-marquee"
import { PipelineDiagram } from "@/components/overview/pipeline-diagram"
import { FeatureBento } from "@/components/overview/feature-bento"
import { ModuleTable } from "@/components/overview/module-table"
import { Limitations } from "@/components/overview/limitations"

export default function Page() {
  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-24 px-4 py-10 md:px-8 md:py-14">
      <Hero />
      <div className="flex flex-col gap-10">
        <SignatureMarquee />
        <StatGrid />
      </div>
      <PipelineDiagram />
      <FeatureBento />
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
