"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { ShieldCheckIcon } from "lucide-react"

import { cn } from "@/lib/utils"

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/playground", label: "Scanner" },
  { href: "/benchmarks", label: "Benchmarks" },
  { href: "/sqli", label: "SQLi Engine" },
]

export function SiteHeader() {
  const pathname = usePathname()

  return (
    <header className="sticky top-0 z-40 px-3 pt-3 md:px-6 md:pt-4">
      <div className="mx-auto flex h-14 max-w-7xl items-center gap-3 rounded-2xl border border-foreground/10 bg-background/60 px-3 shadow-[0_20px_50px_-20px_oklch(0_0_0/0.7)] backdrop-blur-2xl md:px-4">
        <Link href="/" className="group flex shrink-0 items-center gap-2.5" aria-label="AEGIS-AC home">
          <span className="relative flex size-9 items-center justify-center rounded-xl bg-linear-to-br from-primary to-accent text-primary-foreground shadow-[0_0_30px_oklch(0.86_0.15_192/0.35)] transition-transform group-hover:rotate-6 group-hover:scale-105">
            <ShieldCheckIcon className="size-[18px]" aria-hidden="true" />
          </span>
          <span className="hidden font-mono text-sm font-bold tracking-[0.18em] sm:block">AEGIS-AC</span>
        </Link>

        <nav
          aria-label="Primary"
          className="mx-auto flex items-center gap-0.5 overflow-x-auto rounded-xl bg-foreground/[0.04] p-1"
        >
          {NAV.map((item) => {
            const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href)
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "rounded-lg px-3 py-1.5 text-sm font-medium whitespace-nowrap text-muted-foreground transition-all hover:text-foreground",
                  active && "bg-foreground/10 text-foreground shadow-[inset_0_1px_0_oklch(1_0_0/0.08)]",
                )}
              >
                {item.label}
              </Link>
            )
          })}
        </nav>

        <div className="hidden shrink-0 items-center gap-2 rounded-full border border-foreground/10 bg-foreground/[0.03] px-3 py-1.5 font-mono text-xs text-muted-foreground lg:flex">
          <span className="size-2 rounded-full bg-chart-5 animate-pulse-dot" aria-hidden="true" />
          78/78 tests passing
        </div>
      </div>
    </header>
  )
}
