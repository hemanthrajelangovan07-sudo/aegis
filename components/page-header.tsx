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
    <header className="glow-border relative flex flex-col gap-5 overflow-hidden rounded-3xl bg-card/50 p-8 backdrop-blur-xl md:p-12">
      <div className="pointer-events-none absolute -top-24 -right-16 size-72 rounded-full bg-accent/20 blur-3xl" aria-hidden="true" />
      <div className="pointer-events-none absolute -bottom-32 left-1/4 size-72 rounded-full bg-primary/15 blur-3xl" aria-hidden="true" />
      <p className="relative flex w-fit items-center gap-2 rounded-full border border-primary/25 bg-primary/10 px-3 py-1 font-mono text-[11px] font-semibold tracking-[0.2em] text-primary uppercase">
        <span className="size-1.5 rounded-full bg-primary animate-pulse-dot" aria-hidden="true" />
        {eyebrow}
      </p>
      <h1 className="relative text-4xl font-bold tracking-tight text-balance md:text-6xl">
        <span className="text-gradient">{title}</span>
      </h1>
      <p className="relative max-w-3xl text-lg leading-relaxed text-pretty text-muted-foreground">{description}</p>
    </header>
  )
}
