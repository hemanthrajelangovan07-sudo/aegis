import { cn } from "@/lib/utils"

export function SectionHeading({
  id,
  eyebrow,
  title,
  description,
  align = "left",
}: {
  id?: string
  eyebrow: string
  title: string
  description?: string
  align?: "left" | "center"
}) {
  return (
    <div className={cn("flex flex-col gap-3", align === "center" && "items-center text-center")}>
      <p className="flex items-center gap-2 font-mono text-xs font-semibold tracking-[0.25em] text-primary uppercase">
        <span className="h-px w-6 bg-primary" aria-hidden="true" />
        {eyebrow}
      </p>
      <h2 id={id} className="text-3xl font-bold tracking-tight text-balance md:text-4xl">
        {title}
      </h2>
      {description && (
        <p className="max-w-2xl leading-relaxed text-pretty text-muted-foreground">{description}</p>
      )}
    </div>
  )
}
