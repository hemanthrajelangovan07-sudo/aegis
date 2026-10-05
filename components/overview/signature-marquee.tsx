const SIGNATURES = [
  "UNION SELECT",
  "<script>",
  "../../etc/passwd",
  "OR 1=1--",
  "cmd.exe",
  "/bin/sh",
  "eval(base64_decode",
  "xp_cmdshell",
  "onerror=",
  "DROP TABLE",
  "wget http://",
  "${jndi:ldap",
]

export function SignatureMarquee() {
  const items = [...SIGNATURES, ...SIGNATURES]
  return (
    <section
      aria-label="Example signatures detected"
      className="relative -mx-4 overflow-hidden border-y border-foreground/10 bg-foreground/[0.02] py-5 md:-mx-8 [mask-image:linear-gradient(90deg,transparent,black_12%,black_88%,transparent)]"
    >
      <ul className="flex w-max animate-marquee gap-3">
        {items.map((sig, i) => (
          <li
            key={i}
            aria-hidden={i >= SIGNATURES.length}
            className="flex items-center gap-2 rounded-full border border-foreground/10 bg-card/60 px-4 py-2 font-mono text-sm whitespace-nowrap text-muted-foreground"
          >
            <span className="size-1.5 rounded-full bg-destructive" aria-hidden="true" />
            {sig}
          </li>
        ))}
      </ul>
    </section>
  )
}
