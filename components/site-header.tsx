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
    <header className="sticky top-0 z-40 border-b bg-background/85 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-6xl items-center gap-6 px-4 md:px-6">
        <Link href="/" className="flex items-center gap-2" aria-label="AEGIS-AC home">
          <span className="flex size-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <ShieldIcon className="size-4" aria-hidden="true" />
          </span>
          <span className="font-mono text-sm font-semibold tracking-tight">AEGIS-AC</span>
        </Link>
        <nav aria-label="Primary" className="flex flex-1 items-center gap-1 overflow-x-auto">
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
