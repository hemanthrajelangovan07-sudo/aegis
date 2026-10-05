// TypeScript port of ac_prefilter/{trie,failure,nextmove,scan}.py, kept structurally identical
// so the browser scanner reports the same state counts and match positions as the Python engine.

const ALPHABET_SIZE = 256

export type ACTrie = {
  goto: Map<number, number>[]
  out: Set<number>[]
  fail: number[]
  label: Uint8Array[]
}

export type NextMoveDFA = {
  nStates: number
  delta: Int32Array
  out: Set<number>[]
  byteClasses: number
}

export type Match = { endPosition: number; ruleIds: number[] }

export type ScanStep = { index: number; byte: number; from: number; to: number; hits: number[] }

export function buildTrie(patterns: Uint8Array[]): ACTrie {
  const trie: ACTrie = { goto: [new Map()], out: [new Set()], fail: [0], label: [new Uint8Array()] }
  patterns.forEach((pattern, ruleId) => {
    let state = 0
    for (const byte of pattern) {
      let next = trie.goto[state].get(byte)
      if (next === undefined) {
        trie.goto.push(new Map())
        trie.out.push(new Set())
        trie.fail.push(0)
        const prev = trie.label[state]
        const label = new Uint8Array(prev.length + 1)
        label.set(prev)
        label[prev.length] = byte
        trie.label.push(label)
        next = trie.goto.length - 1
        trie.goto[state].set(byte, next)
      }
      state = next
    }
    trie.out[state].add(ruleId)
  })
  return trie
}

export function buildFailureLinks(trie: ACTrie): void {
  const root = 0
  const queue: number[] = []
  for (const s of trie.goto[root].values()) {
    trie.fail[s] = root
    queue.push(s)
  }
  let head = 0
  while (head < queue.length) {
    const r = queue[head++]
    for (const [byte, s] of trie.goto[r]) {
      queue.push(s)
      let t = trie.fail[r]
      while (t !== root && !trie.goto[t].has(byte)) t = trie.fail[t]
      const next = trie.goto[t].get(byte) ?? root
      trie.fail[s] = next !== s ? next : root
      for (const id of trie.out[trie.fail[s]]) trie.out[s].add(id)
    }
  }
}

function countByteClasses(trie: ACTrie): number {
  const signatures = new Set<string>()
  for (let byte = 0; byte < ALPHABET_SIZE; byte++) {
    const states: number[] = []
    trie.goto.forEach((edges, s) => {
      if (edges.has(byte)) states.push(s)
    })
    signatures.add(states.join(","))
  }
  return signatures.size
}

export function buildNextMove(trie: ACTrie): NextMoveDFA {
  const n = trie.goto.length
  const delta = new Int32Array(n * ALPHABET_SIZE)
  for (let b = 0; b < ALPHABET_SIZE; b++) delta[b] = trie.goto[0].get(b) ?? 0

  const queue = [...trie.goto[0].values()]
  let head = 0
  while (head < queue.length) {
    const r = queue[head++]
    for (let b = 0; b < ALPHABET_SIZE; b++) {
      const child = trie.goto[r].get(b)
      if (child !== undefined) {
        delta[r * ALPHABET_SIZE + b] = child
        queue.push(child)
      } else {
        delta[r * ALPHABET_SIZE + b] = delta[trie.fail[r] * ALPHABET_SIZE + b]
      }
    }
  }
  return { nStates: n, delta, out: trie.out, byteClasses: countByteClasses(trie) }
}

export function scan(dfa: NextMoveDFA, payload: Uint8Array, startState = 0) {
  let state = startState
  const matches: Match[] = []
  const steps: ScanStep[] = []
  for (let i = 0; i < payload.length; i++) {
    const from = state
    state = dfa.delta[state * ALPHABET_SIZE + payload[i]]
    const hits = dfa.out[state]
    const ids = hits.size ? [...hits].sort((a, b) => a - b) : []
    if (ids.length) matches.push({ endPosition: i, ruleIds: ids })
    steps.push({ index: i, byte: payload[i], from, to: state, hits: ids })
  }
  return { finalState: state, matches, steps, transitions: payload.length }
}

export function compileAndScan(patterns: string[], payload: string, nocase: boolean) {
  const encoder = new TextEncoder()
  const fold = (s: string) => (nocase ? s.toLowerCase() : s)
  const patternBytes = patterns.map((p) => encoder.encode(fold(p)))
  const payloadBytes = encoder.encode(payload)
  const scanBytes = nocase ? encoder.encode(payload.toLowerCase()) : payloadBytes

  const t0 = performance.now()
  const trie = buildTrie(patternBytes)
  buildFailureLinks(trie)
  const dfa = buildNextMove(trie)
  const t1 = performance.now()
  const result = scan(dfa, scanBytes)
  const t2 = performance.now()

  return {
    trie,
    dfa,
    payloadBytes,
    patternLengths: patternBytes.map((p) => p.length),
    ...result,
    compileMs: t1 - t0,
    scanMs: t2 - t1,
    denseBytes: dfa.nStates * ALPHABET_SIZE * 4,
  }
}

export function byteToChar(byte: number) {
  if (byte === 32) return "\u00a0"
  if (byte >= 33 && byte <= 126) return String.fromCharCode(byte)
  return "·"
}

export function labelToString(label: Uint8Array) {
  return label.length === 0 ? "ε" : Array.from(label, byteToChar).join("")
}
