"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { ShieldIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge"
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
    <header className="sticky top-0 z-40 border-b border-border/70 bg-background/75 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-7xl items-center gap-4 px-4 md:px-8">
        <Link href="/" className="group flex items-center gap-3" aria-label="AEGIS-AC home">
          <span className="relative flex size-9 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-[0_0_24px_oklch(0.82_0.16_78_/_0.24)] transition-transform group-hover:scale-105">
            <ShieldIcon className="size-[18px]" aria-hidden="true" />
          </span>
          <span className="flex flex-col leading-none">
            <span className="font-mono text-sm font-bold tracking-[0.16em]">AEGIS-AC</span>
            <span className="mt-1 hidden font-mono text-[9px] tracking-[0.18em] text-muted-foreground uppercase sm:block">Intrusion intelligence</span>
          </span>
        </Link>
        <nav aria-label="Primary" className="ml-auto flex flex-1 items-center justify-end gap-1 overflow-x-auto md:ml-8 md:justify-start">
          {NAV.map((item) => {
            const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href)
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "rounded-md px-3 py-1.5 text-sm whitespace-nowrap text-muted-foreground transition-colors hover:text-foreground",
                  active && "bg-secondary text-foreground",
                )}
              >
                {item.label}
              </Link>
            )
          })}
        </nav>
        <Badge variant="outline" className="hidden font-mono sm:inline-flex">
          78/78 tests passing
        </Badge>
      </div>
    </header>
  )
}
