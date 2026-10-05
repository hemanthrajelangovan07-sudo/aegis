import type { Metadata, Viewport } from "next"
import { Space_Grotesk, JetBrains_Mono } from "next/font/google"

import "./globals.css"
import { ThemeProvider } from "@/components/theme-provider"
import { TooltipProvider } from "@/components/ui/tooltip"
import { SiteHeader } from "@/components/site-header"
import { SiteFooter } from "@/components/site-footer"
import { cn } from "@/lib/utils"

const geist = Space_Grotesk({ subsets: ["latin"], variable: "--font-sans" })

const fontMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
})

export const metadata: Metadata = {
  title: {
    default: "AEGIS-AC — Aho-Corasick IDS Engine",
    template: "%s · AEGIS-AC",
  },
  description:
    "Console for AEGIS-AC: a k-independent Aho-Corasick prefilter, regex DFA verifier bank, and SQLi DPDA recognizer for network intrusion detection.",
}

export const viewport: Viewport = {
  themeColor: "#0d0e1a",
  colorScheme: "dark",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={cn("antialiased", fontMono.variable, "font-sans", geist.variable)}
    >
      <body className="min-h-svh">
        <ThemeProvider defaultTheme="dark" enableSystem={false} forcedTheme="dark">
          <TooltipProvider>
            <div className="relative z-10 flex min-h-svh flex-col">
              <SiteHeader />
              <main className="flex-1">{children}</main>
              <SiteFooter />
            </div>
          </TooltipProvider>
        </ThemeProvider>
      </body>
    </html>
  )
}
