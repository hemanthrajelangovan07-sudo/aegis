"use client"

import { useDeferredValue, useMemo, useState } from "react"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Textarea } from "@/components/ui/textarea"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Toggle } from "@/components/ui/toggle"
import { compileAndScan } from "@/lib/aho-corasick"
import { PayloadView } from "./payload-view"
import { ScanStats } from "./scan-stats"
import { MatchTable } from "./match-table"
import { TrieTable } from "./trie-table"
import { StepTrace } from "./step-trace"

const PRESETS = {
  classic: {
    label: "Classic",
    patterns: "he\nshe\nhis\nhers",
    payload: "ushers",
    nocase: false,
  },
  backdoor: {
    label: "Backdoor",
    patterns: "backdoor\nkeylogger",
    payload: "installed backdoor and keylogger on target machine silently today",
    nocase: false,
  },
  sqli: {
    label: "SQLi",
    patterns: "union\nselect\nor 1=1\ndrop table\ninformation_schema",
    payload: "GET /item?id=1 UNION SELECT password FROM users WHERE 1 OR 1=1",
    nocase: true,
  },
  http: {
    label: "HTTP",
    patterns: "GET\n/index.html\n/admin\ncmd.exe\n../",
    payload: "GET /index.html HTTP/1.1\r\nHost: target\r\n\r\nGET /../../cmd.exe",
    nocase: false,
  },
} as const

type PresetKey = keyof typeof PRESETS

export function ScannerPlayground() {
  const [preset, setPreset] = useState<PresetKey | null>("classic")
  const [patternText, setPatternText] = useState<string>(PRESETS.classic.patterns)
  const [payload, setPayload] = useState<string>(PRESETS.classic.payload)
  const [nocase, setNocase] = useState<boolean>(PRESETS.classic.nocase)

  const deferredPatterns = useDeferredValue(patternText)
  const deferredPayload = useDeferredValue(payload)

  const patterns = useMemo(
    () =>
      deferredPatterns
        .split("\n")
        .map((p) => p.replace(/\r$/, ""))
        .filter((p) => p.length > 0)
        .slice(0, 500),
    [deferredPatterns],
  )

  const result = useMemo(
    () => compileAndScan(patterns, deferredPayload.slice(0, 4096), nocase),
    [patterns, deferredPayload, nocase],
  )

  function applyPreset(key: PresetKey) {
    const p = PRESETS[key]
    setPreset(key)
    setPatternText(p.patterns)
    setPayload(p.payload)
    setNocase(p.nocase)
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
      <Card className="h-fit">
        <CardHeader>
          <CardTitle>Ruleset &amp; payload</CardTitle>
          <CardDescription>Edit freely — the automaton recompiles on every keystroke.</CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <Field>
              <FieldLabel>Preset</FieldLabel>
              <ToggleGroup
                variant="outline"
                size="sm"
                value={preset ? [preset] : []}
                onValueChange={(value) => {
                  const next = value[0] as PresetKey | undefined
                  if (next) applyPreset(next)
                }}
                aria-label="Example presets"
              >
                {(Object.keys(PRESETS) as PresetKey[]).map((key) => (
                  <ToggleGroupItem key={key} value={key}>
                    {PRESETS[key].label}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
            </Field>
            <Field>
              <FieldLabel htmlFor="patterns">Fast-patterns (one per line)</FieldLabel>
              <Textarea
                id="patterns"
                value={patternText}
                onChange={(e) => {
                  setPreset(null)
                  setPatternText(e.target.value)
                }}
                rows={6}
                spellCheck={false}
                className="font-mono text-sm"
              />
              <FieldDescription>
                {patterns.length} pattern{patterns.length === 1 ? "" : "s"} · rule_id = line index
              </FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="payload">Payload</FieldLabel>
              <Textarea
                id="payload"
                value={payload}
                onChange={(e) => {
                  setPreset(null)
                  setPayload(e.target.value)
                }}
                rows={4}
                spellCheck={false}
                className="font-mono text-sm"
              />
              <FieldDescription>{result.payloadBytes.length} bytes (max 4096)</FieldDescription>
            </Field>
            <Field orientation="horizontal">
              <Toggle
                variant="outline"
                size="sm"
                pressed={nocase}
                onPressedChange={(pressed) => {
                  setPreset(null)
                  setNocase(pressed)
                }}
                aria-label="Toggle case-insensitive matching"
              >
                nocase
              </Toggle>
              <FieldDescription>Fold patterns and payload to lowercase before scanning.</FieldDescription>
            </Field>
          </FieldGroup>
        </CardContent>
      </Card>

      <div className="flex min-w-0 flex-col gap-6">
        <ScanStats result={result} matchCount={result.matches.length} />
        <PayloadView
          bytes={result.payloadBytes}
          matches={result.matches}
          patternLengths={result.patternLengths}
        />
        <Tabs defaultValue="matches">
          <TabsList>
            <TabsTrigger value="matches">Matches</TabsTrigger>
            <TabsTrigger value="trie">Trie &amp; failure links</TabsTrigger>
            <TabsTrigger value="trace">Scan trace</TabsTrigger>
          </TabsList>
          <TabsContent value="matches">
            <MatchTable
              matches={result.matches}
              patterns={patterns}
              patternLengths={result.patternLengths}
            />
          </TabsContent>
          <TabsContent value="trie">
            <TrieTable trie={result.trie} patterns={patterns} />
          </TabsContent>
          <TabsContent value="trace">
            <StepTrace steps={result.steps} patterns={patterns} />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
