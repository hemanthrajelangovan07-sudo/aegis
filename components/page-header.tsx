export function PageHeader({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string
  title: string
  description: string
}) {
  return (
    <header className="relative flex flex-col gap-4 overflow-hidden rounded-2xl border border-border/70 bg-card/35 p-6 panel-glow md:p-8">
      <div className="pointer-events-none absolute -right-12 -top-16 size-48 rounded-full bg-primary/10 blur-3xl" />
      <p className="relative font-mono text-[11px] font-semibold tracking-[0.2em] text-primary uppercase">{eyebrow}</p>
      <h1 className="relative text-3xl font-semibold tracking-tight text-balance md:text-5xl">{title}</h1>
      <p className="relative max-w-3xl leading-relaxed text-pretty text-muted-foreground">{description}</p>
    </header>
  )
}
