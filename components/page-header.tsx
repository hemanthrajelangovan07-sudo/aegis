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
    <header className="flex flex-col gap-3">
      <p className="font-mono text-xs tracking-wider text-primary uppercase">{eyebrow}</p>
      <h1 className="text-3xl font-semibold tracking-tight text-balance md:text-4xl">{title}</h1>
      <p className="max-w-3xl leading-relaxed text-pretty text-muted-foreground">{description}</p>
    </header>
  )
}
