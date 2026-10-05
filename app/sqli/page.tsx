import type { Metadata } from "next"

import { PageHeader } from "@/components/page-header"
import { CorpusResults } from "@/components/sqli/corpus-results"
import { VerdictExamples } from "@/components/sqli/verdict-examples"
import { FalsePositives } from "@/components/sqli/false-positives"
import { ParserFacts } from "@/components/sqli/parser-facts"

export const metadata: Metadata = {
  title: "SQLi Engine",
  description: "Taint-aware LALR(1) DPDA recognizer for SQL injection, evaluated on the libinjection corpus.",
}

export default function SqliPage() {
  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-8 px-4 py-10 md:px-6">
      <PageHeader
        eyebrow="Module 3 · SQLi Lexer & DPDA"
        title="Structural SQL injection detection"
        description="Instead of matching keywords, the recognizer parses the full query and asks one question: did a byte the attacker controlled change the shape of the parse tree? If a tainted token is shifted as structure rather than a literal, the parse latches an attack verdict."
      />
      <ParserFacts />
      <CorpusResults />
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="lg:col-span-3">
          <VerdictExamples />
        </div>
        <div className="lg:col-span-2">
          <FalsePositives />
        </div>
      </div>
    </div>
  )
}
