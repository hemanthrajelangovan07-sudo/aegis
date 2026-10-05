import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"

const ITEMS = [
  {
    title: "Real Snort / ET Open / CIC-IDS2017",
    body: "Not reachable from the build sandbox. Download commands live in bench/harness.py.",
  },
  {
    title: "Suricata mpm-algo=hs vs ac",
    body: "Requires a full Suricata source build; Hyperscan-the-library is compared directly instead.",
  },
  {
    title: "byte_test, byte_jump, flowbits",
    body: "Parsed by the loader so real rule files don't crash it, but not acted on for detection.",
  },
  {
    title: "Full ANSI SQL grammar",
    body: "Deliberately scoped to a defensible DML subset — 89% of the libinjection corpus falls outside it.",
  },
]

export function Limitations() {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Not wired up, on purpose</CardTitle>
        <CardDescription>Documented scope limits from the README.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {ITEMS.map((item, i) => (
          <div key={item.title} className="flex flex-col gap-4">
            {i > 0 && <Separator />}
            <div className="flex flex-col gap-1">
              <h3 className="text-sm font-medium">{item.title}</h3>
              <p className="text-sm leading-relaxed text-muted-foreground">{item.body}</p>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
