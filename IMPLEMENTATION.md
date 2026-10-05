# AEGIS-AC — IMPLEMENTATION.md
### Automata-Theoretic Intrusion Detection Engine — Build Specification

This document is the authoritative build specification for AEGIS-AC. It reconciles the team's
original project design against the independently-verified **research dossier**
(`AEGIS-AC__Automata-Theoretic_Intrusion_Detection_Engine_Project_Proposal.pdf`, hereafter
**"the dossier"**) that was produced to fact-check the original proposal, poster, slide deck and
viva materials. The dossier's own `REFUTED OR UNVERIFIABLE CLAIMS` section is the authoritative
record of what the original design got wrong; every correction in that section is treated here as
binding. **No code is written in this document** — only formal specification, interface contracts,
data schemas and pseudocode that the team will implement from.

**Conventions used throughout this document:**

| Marker | Meaning |
|---|---|
| `[Dossier §X]` | Fact or number taken directly from the dossier's `VERIFIED FACTS`, `REFUTED OR UNVERIFIABLE CLAIMS`, or numbered supplementary sections. Safe to state as established. |
| `[Dossier→Author Year]` | A citation the dossier itself sources to a named paper/standard; traceable through the dossier's bibliography. |
| `[Verified in this doc]` | A number independently recomputed for this specification (Aho–Corasick trie/DFA construction, LR(1)/LALR(1) grammar tables, subset-construction/Hopcroft state counts, download URLs/package names) by machine, not lifted from the dossier or invented. Reproducible from the worked examples in §5. |
| `[Illustrative — not a cited measurement]` | A self-constructed example used only to make an abstract bound concrete (e.g. for a whiteboard viva walkthrough). **Must never be cited as a published or dossier figure.** |
| `TODO(open-gap): ...` | The dossier explicitly marks this as an open literature gap (`Verification Flag`) or `[Unconfirmed]`. No answer is invented here; the gap is carried forward as an explicit task. |

---

## REMAINING DESIGN PROBLEMS

The dossier's eight corrections (see `REFUTED OR UNVERIFIABLE CLAIMS`, items 1–8) are applied
throughout this document. After applying them, the following problems **remain** and must be
actively managed by the team — they are not fixed simply by rewording the proposal.

**RDP-1. The architecture fix is necessary but not sufficient — regex rules with no extractable
literal anchor break the prefilter model.**
Dossier Refuted Claim #1 replaces "merge everything into one AC trie" with "AC literal prefilter +
per-rule DFA verifier" (see §3 ARCHITECTURE). But the dossier's own "Fast-pattern prefilter
mechanics" note states that a PCRE-only rule with no statically extractable literal **cannot
participate in prefiltering** and must be evaluated on every packet after header filtering
`[Dossier §7]`. If this is not designed for explicitly, the team's claimed `O(n+z)`
scan-time-independent-of-k result silently degrades to `O(n·k')` for the subset of rules with no
anchor (`k'` = count of anchor-less rules), and nobody will notice until an examiner asks. §3 and
§5 (Module 2: Regex Compiler) specify a mandatory **"no-anchor" rule class** with its own
accounted-for cost, so this can be reported honestly rather than discovered live.

**RDP-2. The PDA/succinctness argument is a proof obligation for the team, not a wording fix.**
The corrected wording for Refuted Claim #2 (bounded nesting is *regular but not succinctly
DFA-representable*) is easy to recite and easy to be cross-examined out of. An examiner can, and
per the dossier's own "Major peer-review criticisms" checklist `[Dossier §4]` almost certainly
will, raise exactly the **Bounded-Length Objection** (`[Dossier §27]`): *"packets have a finite MTU,
so the language is regular — why do you need a stack at all?"* The team must be able to reproduce,
on a whiteboard, the state-complexity argument (`Θ(depth)` DFA states per nesting level vs `O(1)`
PDA control states + `O(log depth)` stack bits) from first principles, not just quote the corrected
sentence. §7 (Threats to Validity) stages this as a rehearsed Q&A item with the full derivation.

**RDP-3. The dossier's own self-citation is circular and must not appear in the paper's
bibliography.** Dossier bibliography item 7 is "AEGIS-AC Team, Internal Project Documentation,
2026" — i.e. the team's own (flawed) original proposal, cited as if it were external supporting
literature. Carrying this citation into the paper would mean citing the document this very
specification exists to correct. **Action:** drop it from the paper's related-work / bibliography
entirely; if the original design rationale needs to be referenced (e.g. "our original design
merged regex into the AC trie, which the literature does not support"), describe it in prose as
the team's own prior design, not as a numbered citation.

**RDP-4. The "8.7× vs PCRE" figure must be hunted down and purged from *all* existing materials,
not just avoided going forward.** The dossier is explicit that this number is unverifiable/
misattributed and does not exist in Intel's primary source; Chi Xu's actual single-regex benchmark
showed **no** Hyperscan benefit over libpcre `[Dossier §23]`. **Action (before any further work):**
grep every existing slide, poster, and draft the team has for "8.7" and remove/replace any such
claim. Do not carry it into this document's PAPER SKELETON's Related Work draft.

**RDP-5. Both original documents were wrong about Suricata's default MPM engine, in opposite
directions — one correction is not enough.** The A0 poster claimed "Hyperscan by default"; the
proposal claimed "AC by default" `[Dossier, Refuted Claim #5]`. The corrected fact — `mpm-algo:
auto`, which uses Hyperscan only if compiled in **and** the CPU supports it, else falls back to AC
`[Dossier §11]` — must replace **both** statements everywhere they occur, not just be added as a
third data point alongside the other two.

**RDP-6. The garbled citation must be replaced, not deleted.** "Sapats et al., *Comparison of
Snort and Suricata MPM performance*, AICT 2013" is unverifiable as stated. The dossier's replacement
is White, Fitzsimmons & Matthews, *"Quantitative Analysis of Intrusion Detection Systems: Snort and
Suricata,"* SPIE 2013 `[Dossier, Refuted Claim #6]`. Any slide/poster still carrying the old
citation string must be corrected to this reference, not simply have the citation removed (the
underlying performance comparison claim itself is retained, just correctly attributed).

**RDP-7. The concrete SQLi grammar in this document is original specification work by necessity,
not a dossier fact, and needs team sign-off.** The dossier fixes the SQLi language *class*
(DCFL / LR(1) / LL(1), recognized by an explicit shift-reduce DPDA, **not** recursive descent
`[Dossier §5, §31]`) and gives the formal succinctness/regularity arguments, but it does not supply
a concrete grammar with productions — none exists in the source material. §2.5 below defines one
(machine-verified: canonical LR(1) with 1,689 states and **zero** conflicts; LALR(1) core with 179
states and zero conflicts — see Module 5 worked example in §5) `[Verified in this doc]`. This is a
reasonable engineering default consistent with every dossier constraint, but the team must review
it against their actual target rule surface before building against it — it is not itself a
dossier-sourced requirement.

**RDP-8. Several load-bearing numbers are explicit open questions in the dossier and cannot be
answered here.** Per `[Dossier §7 OPEN QUESTIONS]`:
- `TODO(open-gap)`: the exact signature count `k` at which pure-Python AC loses to a native
  `str.find()` / `pyahocorasick` crossover — resolved only by running §6 EVALUATION HARNESS.
- `TODO(open-gap)`: how fast-pattern anchor length (5 vs 8 vs 20 bytes) affects false-positive
  escalation rate to secondary per-rule DFA verification on real HTTP traffic — resolved only by
  running the prefilter-selectivity experiment in §6.
- `TODO(open-gap)`: the exact memory footprint of a 10,000-rule AC Next-Move DFA in Python over a
  256-byte alphabet, and what compression is needed to stay under 100MB — resolved only by
  measuring §5 Module 1's three storage layouts directly.
- `TODO(open-gap)`: a full Chomsky-hierarchy census (Type 1/2/3 breakdown, not just the back-
  reference subset) of production rulesets (ET Pro, ModSecurity CRS) beyond the 543/120/111
  back-reference figures Namjoshi & Narlikar already published `[Dossier §2, item 9]` remains an
  open literature gap; this document does not claim to have performed that census.
- `TODO(open-gap)`: conference submission windows quoted anywhere in team planning materials
  (e.g. EuroSec, ANCS) were marked `[Unconfirmed]` in the dossier's own venue table `[Dossier §39]`
  and must be re-verified against the live CFP before any submission-date commitment is made; see
  §9 PAPER SKELETON.

None of the above blocks starting implementation — they are scoped, owned TODOs, tracked again at
their point of relevance in §5–§9 below, and are carried into §8 BUILD ORDER as explicit tasks.

---

## 1. CONTRIBUTION STATEMENT

**Paper claim (one sentence).**
A multi-tiered NIDS engine that combines an Aho–Corasick literal fast-pattern prefilter, per-rule
minimal DFAs for regex verification, and a linear-time deterministic pushdown automaton (DPDA) for
structural/nested SQL-injection recognition achieves deterministic `O(n)` payload scanning while
eliminating both ReDoS (catastrophic regex backtracking) and DFA state-space explosion — a
combination that, per the dossier's literature survey, no published peer-reviewed system
2015–2026 demonstrates together on raw streaming packets `[Dossier §3 THE NOVELTY GAP; §1
Systems Combining Multi-Pattern + CFG/PDA]`.

**Supporting experiment.**
Measure throughput (Gbps and bytes/cycle) and P99 tail latency for AEGIS-AC versus four required
baselines (naive multi-pattern search, standard C Aho–Corasick, Intel Hyperscan/Suricata
`mpm-algo`, backtracking PCRE) across synthetic rulesets scaled `k = 100 → 10,000` and three PCAP
classes (benign, regular-expression-heavy, nested-SQLi), including adversarial ReDoS and
cache-thrashing streams. Full protocol in §6 EVALUATION HARNESS.

**Falsification condition.**
The claim is falsified if **either**:
1. AEGIS-AC's measured per-byte transition count (not wall-clock — see §6's honest
   Python-vs-production treatment) grows super-linearly in `n` or depends on `k` for the
   AC-prefilter-covered rule subset, contradicting the `O(n+z)` bound `[Dossier §1, §13]`; **or**
2. AEGIS-AC's P99 tail latency under the ReDoS-adversarial stream collapses by more than one order
   of magnitude relative to its own benign-traffic P99 — the exact failure mode measured in
   Namjoshi & Narlikar's Trace7 result, where a single pathological Snort rule collapsed
   multi-Gbps throughput to ~1 packet/second `[Dossier §10]` — showing the architecture did not, in
   fact, eliminate backtracking-class blowup for the covered rule subset.

Two secondary claims (used only if the primary claim needs to be descoped under time pressure —
see §8 BUILD ORDER for the ranked fallback order):

**Secondary claim 1.** A formal prefilter contract that extracts literal anchors into an AC trie
guarantees bounded average-case `O(n+z)` scanning across rulesets containing complex regex, subject
to per-rule verifier escalation rate; falsified if escalation rate does not stay bounded as
`k` scales `[Dossier §4]`.

**Secondary claim 2.** Cross-packet automaton state persistence across TCP segment boundaries
(AC state + DPDA stack snapshot carried in a per-flow control block) enables correct streaming
detection without full flow reassembly; falsified if detection accuracy drops materially under
fragmented/out-of-order packets relative to a full-reassembly baseline, or if per-flow memory
overhead is unbounded in flow count `[Dossier §4, item Secondary 2; §18]`.


## 2. FORMAL SPECIFICATION

### 2.1 Deterministic Finite Automaton (DFA) — 5-tuple

`M = (Q, Σ, δ, q₀, F)` where:
- `Q` — finite set of states.
- `Σ` — input alphabet; AEGIS-AC operates byte-oriented, so `Σ = {0,...,255}`, `|Σ| = 256`, unless
  a module explicitly restricts to a smaller alphabet (e.g. the whiteboard examples in §5 restrict
  to the literal characters in play, for hand-traceability).
- `δ : Q × Σ → Q` — **total** transition function (every state has an outgoing edge for every
  symbol; this totality is what makes per-byte processing exactly one transition, no backtracking).
- `q₀ ∈ Q` — start state.
- `F ⊆ Q` — accepting states.

Every regex-derived per-rule verifier automaton in AEGIS-AC (§3 Module: Regex Compiler) is,
after minimization, an instance of this 5-tuple. Scan of an input `T` with `|T| = n` costs exactly
`n` applications of `δ` — one transition per byte, independent of `|Q|` — because `δ` is total.

### 2.2 Non-deterministic Finite Automaton with ε-moves (NFA) — 5-tuple, and Thompson's construction

`N = (Q, Σ, Δ, q₀, F)` where `Δ : Q × (Σ ∪ {ε}) → 2^Q` (transition **relation**, not function:
zero, one, or many next states per symbol, plus silent `ε`-transitions).

**Thompson's construction** `[Dossier→Thompson; Dossier §1 Regex-to-Automata Compilation]`
builds `N` from a regex of length `r` (`r` = number of regex symbols/operators) inductively over
the regex syntax tree, so that:
- `|Q_N| ≤ 2r` states,
- every state has in-degree ≤ 2 and out-degree ≤ 2,
- construction time and space are `O(r)`.

`[Illustrative — not a cited measurement]` As a hand-checkable sanity example: the regex `abc`
(three literal-byte concatenations) yields a 4-state Thompson NFA under the "concatenation merges
accept-of-left with start-of-right" construction variant `[Verified in this doc]`; this is included
only to demonstrate `|Q_N| ≤ 2r` is tight-ish for trivial regexes, not as a published figure.

### 2.3 Subset construction and Hopcroft minimization

**Subset construction** (`NFA → DFA`) computes `Q_D = 2^{Q_N}` in the worst case via `ε`-closure:
each DFA state is a *set* of NFA states reachable via the same input prefix modulo `ε`-moves.
Worst case: `|Q_D| = 2^{|Q_N|}` `[Dossier §1 Regex-to-Automata Compilation]`. This worst case is not
academic for NIDS rulesets: Yu et al. (SIGCOMM 2006) and Becchi & Crowley (ANCS 2007), compiling a
few hundred real Snort regexes into a single consolidated DFA, measured explosion **exceeding
10⁶–10⁹ states**, consuming gigabytes-to-terabytes of RAM and failing offline compilation entirely
`[Dossier §19]`. This is the dossier's own citable empirical grounding for "DFA compilation can
explode" and is preferred over any self-constructed example for that specific claim.

`[Illustrative — not a cited measurement, for building intuition only]` A closed-form family that
demonstrates the same phenomenon on paper: for the search-mode ("match anywhere in a byte stream,
absorb after a match") automaton of `a.{n}b` (literal `a`, exactly `n` wildcard bytes, literal
`b`), the *minimized* DFA has exactly `2^{n+1}+1` states — `n=2 → 9`, `n=4 → 33`, `n=6 → 129`,
`n=8 → 513`, `n=10 → 2049`, `n=11 → 4097`, `n=12 → 8193` `[Verified in this doc]`. This is included
purely to make the abstract `2^{|Q_N|}` bound concrete on a whiteboard; the Snort-regex figures
above are the citable claim.

**Hopcroft minimization** operates on the DFA's state graph, not on the regex string — a regex
string has no direct bearing on the minimization algorithm's complexity once the DFA already
exists. The dossier explicitly flags the original draft's claim of `O(r log r)` (`r` = regex
length) as **wrong for this reason** and gives the corrected bound:

> **`O(|Σ|·n log n)`**, where `n = |Q|` is the *unminimized* DFA's state count and `|Σ|` is the
> alphabet size (256 for byte-oriented matching) `[Dossier §20, citing Hopcroft 1971; Aho, Hopcroft
> & Ullman 1974]`.

### 2.4 Aho–Corasick automaton — goto/failure/output functions, and the precomputed Next-Move DFA

Two related but distinct formal models are both "Aho–Corasick"; AEGIS-AC uses **both**, at
different stages, and the dossier is explicit that conflating them is a common reviewer-flagged
error `[Dossier §4, item "conflating goto/failure AC vs next-move DFA models"]`.

**(a) Goto/failure/output machine** (Aho & Corasick 1975, Algorithms 1–3):
`AC = (S, Σ, g, f, out, s₀)` where:
- `S` — trie states, one per distinct prefix of the pattern set `{p₁,...,p_k}`; `|S| ≤ Σ|pᵢ| + 1`.
- `Σ` — byte alphabet, `|Σ| = 256`.
- `g : S × Σ → S ∪ {fail}` — the **goto** function (trie edges; `fail` for missing edges except at
  the root, where `g(s₀,·)` defaults to `s₀`).
- `f : S → S` — the **failure** function, `f(s)` = the state reached by the longest proper
  suffix of the string labeling `s` that is itself a prefix of some pattern. Built by breadth-first
  search over the trie, one level at a time, so that every `f(s)` is fully known before it is used
  to compute deeper failure links.
- `out : S → 2^{\{p_1,...,p_k\}}`, extended at BFS time by **`out(s) := out(s) ∪ out(f(s))`** — this
  is exactly how AEGIS-AC gets *overlap semantics* (e.g. a match on `"backdoor"` also reporting
  `"door"` if both are in the dictionary) essentially free during construction `[Dossier §1;
  Verified in this doc — see worked example below]`.
- `s₀` — root state.

Scanning text `T`, `|T| = n`, using `g` and `f` together costs **fewer than `2n`** total
transitions: exactly `n` forward/`goto` moves plus at most `n − 1` fallback/`failure` moves
`[Dossier §12 comparison table]`.

**(b) Precomputed Next-Move DFA** (Aho & Corasick 1975, Algorithm 4) eliminates failure
transitions entirely by precomputing, for every state and every byte, the single next state that
`g`+`f` would eventually settle on:

`δ(s,a) = g(s,a)` if `g(s,a) ≠ fail`, else `δ(f(s),a)` — resolved once, offline, for all
`(s,a) ∈ S × Σ`, giving a **total** function `δ : S × Σ → S` exactly matching the DFA 5-tuple of
§2.1. Scanning `T` then costs **exactly `n`** transitions — one per byte, no fallback loop
`[Dossier §1, §12]`.

**Complexity, symbols defined exactly as the dossier requires `[Dossier §13, canonical]`:**

| Symbol | Meaning |
|---|---|
| `n = |T|` | input payload/text length in bytes |
| `m = Σᵢ |pᵢ|` | total length of all patterns (build-time size) |
| `k = |{p₁,...,p_k}|` | number of patterns/signatures |
| `z` | total number of pattern-match occurrences reported |
| `Σ` | byte alphabet, `|Σ| = 256` |

- **Construction:** `O(m)` — one pass to build the trie, one BFS pass for failure links; a **one-
  time, static, offline** cost `[Dossier, Refuted Claim #3]`.
- **Scan (goto/failure machine):** `< 2n` transitions total.
- **Scan (Next-Move DFA):** exactly `n` transitions.
- **Match reporting:** `O(z)` amortized via the `out(s) = out(s) ∪ out(f(s))` inheritance, so the
  total scan cost is **`O(n+z)`**, independent of `k` — **not** `O(n+m)`, which the dossier flags
  as confusing build-time cost with scan-time cost `[Dossier, Refuted Claim #4]`.
- **Space:** `O(|S|·|Σ|)` for the dense Next-Move table, `|S| ≤ m+1`; sparse/banded/bitmapped
  encodings reduce this toward `O(m)` — concrete figures in §4 DATA CONTRACTS and §5 Module 1.
- **Insertion is NOT `O(1)` amortized.** Standard (1975) AC has no incremental insertion at all: a
  new pattern of length `L` costs `O(L)` for the trie edges, and — because failure links can change
  for existing states — a **full BFS re-run at cost `O(m)`** in the standard algorithm. True
  incremental algorithms exist (Meyer 1985; Idury & Schäffer 1994) but are **not** what a "build
  once offline, scan forever" NIDS engine needs, and are out of scope `[Dossier, Refuted Claim #3;
  Dossier §15]`.

**Verified worked example (classic dictionary, to be reproduced by hand for the viva — full
δ-table and state path in §5 Module 1):** dictionary `{he, she, his, hers}` scanned over `"ushers"`
(`n=6`). Goto-trie has **10 states**. Non-root failure links: `f(sh)=h`, `f(she)=he`, `f(his)=s`
(root's child), `f(hers)=s`. Output sets after BFS union: `out(he)={he}`,
`out(she)={he,she}` (inherited via `f(she)=he`), `out(his)={his}`, `out(hers)={hers}`. Scanning
`"ushers"` with the failure machine reports matches ending at positions `(3,"she")`, `(3,"he")`,
`(5,"hers")` (0-indexed) using **7** transitions (1 of which is a failure transition); the
Next-Move DFA reports the identical matches using **exactly 6** transitions (`=n`) — the
`<2n`-vs-`exactly-n` distinction from `[Dossier §12]`, confirmed to the transition `[Verified in
this doc]`.

### 2.5 Pushdown Automaton (PDA) — 7-tuple, instantiated for nested SQL-structure recognition

`P = (Q, Σ, Γ, δ, q₀, Z₀, F)` where:
- `Q` — finite control states.
- `Σ` — input alphabet: SQL tokens as produced by the lexer (see §4 DATA CONTRACTS), **not** raw
  bytes — the PDA operates on the tokenized stream, one layer above the byte-level AC/DFA tier.
- `Γ` — stack alphabet: `{ Z₀ } ∪ { N : N is a grammar nonterminal that can appear on the parse
  stack }` (see §2.6's grammar for the concrete nonterminal set).
- `δ : Q × (Σ ∪ {ε}) × Γ → 2^{Q × Γ*}` — transition relation: on seeing input symbol (or `ε`) and
  the top-of-stack symbol, move to a new state and replace the top-of-stack symbol with zero or
  more stack symbols. AEGIS-AC's instantiation is **deterministic** (a DPDA): `δ` never offers more
  than one legal move for any `(q, a, X)`, which is exactly what "restrict the grammar to `LR(1)`"
  buys — see §2.6.
- `q₀ ∈ Q` — start state.
- `Z₀ ∈ Γ` — initial stack symbol (bottom-of-stack marker).
- `F ⊆ Q` — accepting states (acceptance by final state; AEGIS-AC does not rely on empty-stack
  acceptance, since streaming operation means the "input" never formally ends within one packet).

**Why a stack at all, precisely (this is the corrected, defensible version of the original
design's PDA justification — see RDP-2 above and full rebuttal staging in §7):**

1. **Quote parity does *not* need a stack.** Matching balanced/escaped SQL string-literal quotes is
   provably finite-state: a 2-state DFA (outside-string / inside-string) toggling on an unescaped
   `'`, extended to at most 4 states to also absorb `''`/`\'` escape sequences, suffices, because
   SQL string literals cannot contain recursive unescaped literals inside themselves — there is no
   self-embedding recursion to track `[Dossier §29]`. AEGIS-AC's lexer (§4, §5 Module 4) implements
   quote-parity as exactly this small DFA, **not** as part of the PDA.
2. **Nested parenthesised structure (subqueries, grouped expressions) is where the stack earns its
   keep — but only as a succinctness argument, not a decidability one.** For any *fixed* MTU bound
   `N`, the set of balanced-paren strings of length `≤ N` is finite, hence Type-3 regular
   `[Dossier §27]`. But recognizing nesting depth `d` with a DFA costs `Θ(d)` states *per nesting
   level, per delimiter type*, and for `k` distinct nested structure types the bound is
   `Ω(dᵏ)` `[Dossier §27]`; `[Verified in this doc]`, the *exact* minimal-DFA state count for
   depth-bounded, single-delimiter-type Dyck language up to depth `d` is `d+2` states, and for
   `t` independent delimiter types it is `(tᵈ⁺¹−1)/(t−1) + 1` states (confirmed by direct DFA
   minimization for `t∈{1,2,3}`, `d` up to 6). A DPDA instead needs **`O(1)` control states** plus
   **`O(log d)` stack bits** to track the same depth `d` — an unbounded state-complexity gap as `d`
   grows, which is the real, defensible justification (Meyer & Fischer 1971; Holzer & Salomaa 2021
   `[Dossier §27]`), **not** "nesting isn't regular" (it is, for any fixed bound) and **not**
   "matched quotes require a stack" (they don't — see point 1) `[Dossier, Refuted Claim #2]`.
3. **Balanced parens alone are not an attack signal.** Benign nested SQL (subqueries in `IN`
   clauses, etc.) is common; a detector that fires on "any nested parens" saturates toward a ~100%
   false-positive rate on real enterprise traffic `[Dossier §28]`. The actual decision predicate is
   structural-template comparison — see §2.6 and §5 Module 5.

### 2.6 SQLi grammar — complete, unambiguous context-free grammar

**Status:** the dossier fixes the *language class* the grammar must belong to (`DCFL`, recognized
in `O(n)` by an explicit shift-reduce `LR(1)`/`LALR(1)` table-driven DPDA, never recursive descent
and never general `CYK`/`Earley` which are `O(n³)` and unsuitable for a line-rate pipeline
`[Dossier §31]`) but supplies no concrete productions. The grammar below is **original
specification work for this document** (see RDP-7) — constructed to satisfy every dossier
constraint and machine-verified (§5 Module 5 gives the full verification method): parsed with a
canonical-`LR(1)` item-set construction, **1,689 states, zero shift/reduce and zero reduce/reduce
conflicts**; its `LALR(1)` core collapses to **179 states, also zero conflicts**; no unit-production
cycles `[Verified in this doc]`. It is intentionally a *representative, defensible subset* of SQL
DML (not full ANSI SQL) — sized for an 8–12 week undergraduate build, covering exactly the
constructs needed to demonstrate the union/nested-subquery/boolean-injection attack classes in
§4 DATA CONTRACTS' worked examples.

**Terminals (56):** produced by the tokenizer in §5 Module 4. Keywords (case-insensitive, folded
to upper during lexing): `SELECT FROM WHERE GROUP BY HAVING ORDER LIMIT OFFSET AS ASC DESC UNION
ALL AND OR NOT IN LIKE IS NULL EXISTS CASE WHEN THEN ELSE END INSERT INTO VALUES UPDATE SET DELETE
DROP TABLE`. Operators/punctuation: `EQ NE LT GT LE GE PLUS MINUS STAR SLASH PCT CONCAT LPAREN
RPAREN COMMA SEMI DOT`. Literals/structural: `IDENT NUM STR TAIL_COMMENT` (a trailing `--`/`#`
comment, which is itself part of many injection payloads and must be a first-class token, not
stripped by the lexer).

**Nonterminals (37):** `Script StmtList Stmt SetList SetItem QueryExpr SelectCore SelectHead
SelList SelItem FromClause TableList TableRef ClauseList Clause WhereClause GroupClause
HavingClause OrderClause OrderList OrderItem LimitClause Expr OrExpr AndExpr NotExpr CmpExpr CmpOp
AddExpr AddOp MulExpr MulOp UnExpr Primary WhenList ExprList QName`. Start symbol: `Script`.

**Productions** (104 total; `|` separates alternatives for a left-hand side):

`Script`
    ::= StmtList
      | StmtList TAIL_COMMENT
`StmtList`
    ::= Stmt
      | StmtList SEMI Stmt
      | StmtList SEMI
`Stmt`
    ::= QueryExpr
      | DROP TABLE IDENT
      | DELETE FROM QName
      | DELETE FROM QName WhereClause
      | INSERT INTO QName VALUES LPAREN ExprList RPAREN
      | UPDATE QName SET SetList
      | UPDATE QName SET SetList WhereClause
`SetList`
    ::= SetItem
      | SetList COMMA SetItem
`SetItem`
    ::= QName EQ Expr
`QueryExpr`
    ::= SelectCore
      | QueryExpr UNION SelectCore
      | QueryExpr UNION ALL SelectCore
`SelectCore`
    ::= SelectHead
      | SelectHead ClauseList
`SelectHead`
    ::= SELECT SelList
      | SELECT SelList FromClause
`SelList`
    ::= SelItem
      | SelList COMMA SelItem
`SelItem`
    ::= STAR
      | Expr
      | Expr AS IDENT
`FromClause`
    ::= FROM TableList
`TableList`
    ::= TableRef
      | TableList COMMA TableRef
`TableRef`
    ::= QName
      | QName IDENT
      | QName AS IDENT
      | LPAREN QueryExpr RPAREN IDENT
      | LPAREN QueryExpr RPAREN AS IDENT
`ClauseList`
    ::= Clause
      | ClauseList Clause
`Clause`
    ::= WhereClause
      | GroupClause
      | HavingClause
      | OrderClause
      | LimitClause
`WhereClause`
    ::= WHERE Expr
`GroupClause`
    ::= GROUP BY ExprList
`HavingClause`
    ::= HAVING Expr
`OrderClause`
    ::= ORDER BY OrderList
`OrderList`
    ::= OrderItem
      | OrderList COMMA OrderItem
`OrderItem`
    ::= Expr
      | Expr ASC
      | Expr DESC
`LimitClause`
    ::= LIMIT NUM
      | LIMIT NUM COMMA NUM
      | LIMIT NUM OFFSET NUM
`Expr`
    ::= OrExpr
`OrExpr`
    ::= AndExpr
      | OrExpr OR AndExpr
`AndExpr`
    ::= NotExpr
      | AndExpr AND NotExpr
`NotExpr`
    ::= CmpExpr
      | NOT NotExpr
`CmpExpr`
    ::= AddExpr
      | AddExpr CmpOp AddExpr
      | AddExpr IN LPAREN ExprList RPAREN
      | AddExpr IN LPAREN QueryExpr RPAREN
      | AddExpr LIKE AddExpr
      | AddExpr IS NULL
      | AddExpr IS NOT NULL
`CmpOp`
    ::= EQ
      | NE
      | LT
      | GT
      | LE
      | GE
`AddExpr`
    ::= MulExpr
      | AddExpr AddOp MulExpr
`AddOp`
    ::= PLUS
      | MINUS
      | CONCAT
`MulExpr`
    ::= UnExpr
      | MulExpr MulOp UnExpr
`MulOp`
    ::= STAR
      | SLASH
      | PCT
`UnExpr`
    ::= Primary
      | MINUS UnExpr
`Primary`
    ::= NUM
      | STR
      | NULL
      | QName
      | QName LPAREN RPAREN
      | QName LPAREN STAR RPAREN
      | QName LPAREN ExprList RPAREN
      | LPAREN Expr RPAREN
      | LPAREN QueryExpr RPAREN
      | EXISTS LPAREN QueryExpr RPAREN
      | CASE WhenList END
      | CASE WhenList ELSE Expr END
`WhenList`
    ::= WHEN Expr THEN Expr
      | WhenList WHEN Expr THEN Expr
`ExprList`
    ::= Expr
      | ExprList COMMA Expr
`QName`
    ::= IDENT
      | QName DOT IDENT
**Grammar notes:**
- Unambiguity follows from the machine-verified zero-conflict LR(1) table, not from inspection —
  this is the standard, defensible way to claim "unambiguous" for a grammar this size; see §5
  Module 5 for how to regenerate/re-check the table.
- `TableRef → LPAREN QueryExpr RPAREN IDENT | LPAREN QueryExpr RPAREN AS IDENT` and
  `Primary → LPAREN QueryExpr RPAREN` are exactly the two productions that introduce a nested
  subquery — these are the **stack-requiring** productions the PDA of §2.5 exists for.
  `Primary → LPAREN Expr RPAREN` (a parenthesised *scalar* expression) also pushes/pops but never
  nests a `QueryExpr`, so it does not itself demonstrate unbounded nesting depth.
- `OrExpr → OrExpr OR AndExpr` and `AndExpr → AndExpr AND NotExpr` are the productions that
  demonstrate boolean-injection (`' OR '1'='1`); `QueryExpr → QueryExpr UNION SelectCore` is the
  production for UNION-based injection; `StmtList → StmtList SEMI Stmt` is the production for
  stacked-query injection (`; DROP TABLE ...`); `Script → StmtList TAIL_COMMENT` is the production
  for comment-truncation injection (`admin'--`).

**Decision predicate — what actually counts as an attack (specification, not code):**
Per `[Dossier §28]`, balanced nesting alone is not an attack indicator. AEGIS-AC's predicate is:

> **Attack ⟺ a user-controlled (tainted) byte range participates, as a terminal, in the reduction
> of a *structural* production — one of the productions listed just above — that was not already
> satisfied entirely by static (non-tainted) rule/template bytes.**

Operationally: every token produced by the lexer carries a 1-bit taint flag (was any byte of this
token inside a designated "value slot" — e.g. a URL query-parameter value, a POST body field —
rather than static surrounding SQL). During LR-parsing, each time the shift-reduce automaton
performs a **reduce** action on a *structural* production, check whether any symbol just popped
off the stack carries the taint bit ("tainted pivot"). If so, latch a hit. This directly
operationalizes the dossier's `AST(Query_executed) ≠ AST(Query_template)` predicate `[Dossier
§28]` without needing to construct and diff two full parse trees at line rate: the *template*
grammar only reduces structural productions from **static** tokens; a tainted token reaching a
structural reduction **is** the divergence. `[Verified in this doc]` — traced by hand for a
representative minimal sub-grammar (query, union, parenthesised subquery) in §5 Module 5, showing
the exact stack states, shift/reduce sequence, and the taint-latch firing on the `UNION` reduction.

### 2.7 Language-class and complexity summary

| Component | Formal model | Language class | Complexity (symbols as defined above) |
|---|---|---|---|
| Regex literal fast-pattern prefilter | Aho–Corasick Next-Move DFA (§2.1, §2.4b) | Regular (Type 3) | Build `O(m)`; scan `O(n+z)`, independent of `k` |
| Per-rule regex verifier | Minimal DFA via Thompson→subset→Hopcroft (§2.1–2.3) | Regular (Type 3), excluding back-references and unbounded recursive quantifiers | Build: subset construction worst-case `O(2^{|Q_N|})`, `|Q_N| ≤ 2r`; minimization `O(|Σ|·n log n)`; scan `O(n)` per rule, one transition/byte |
| Back-reference rules (deterministic subset) | Extended NFA + static liveness analysis (Namjoshi & Narlikar 2010) | Context-sensitive (Type 1) in general; decidable in the deterministic-back-reference subset | `O(m·K·m^{2L})` where `K` = live-back-reference count bound, `L` = max simultaneously-live back-references; on the Snort ruleset, 111/120 unique back-ref expressions have `L=1` `[Dossier §1, §2 item 3]` |
| SQLi structural recognizer | DPDA over the §2.6 grammar (§2.5) | Deterministic context-free (DCFL), `LR(1)`/`LALR(1)` | Parse `O(n)` strict linear time via bounded shift-reduce stack — **not** `O(n³)` CYK/Earley `[Dossier §31]` |
| SQL string-literal quote parity | 2–4 state DFA (§2.5 point 1) | Regular (Type 3) | `O(n)`, folded into the lexer pass |

---

## 3. SYSTEM ARCHITECTURE

### 3.1 Component diagram (text)

The single most important architectural fact in this document, correcting the original design's
core error (`[Dossier, Refuted Claim #1]`, RDP-1): **the regex compiler's output is never merged
into the Aho–Corasick trie.** AC only ever holds a *finite dictionary of literal byte strings*
(the extracted "fast patterns"); every rule that needs regex power gets its **own, separate,
minimal per-rule DFA**, invoked only after its fast-pattern literal has already matched. The two
automaton families never share states.

```
                              ┌───────────────────────────┐
   Rule files (Snort/         │  1. RULE / SIGNATURE       │
   Suricata syntax, see       │     LOADER                 │
   §4 DATA CONTRACTS) ───────▶│  parses content:/pcre:/     │
                              │  offset/depth/distance/    │
                              │  within/fast_pattern        │
                              └──────────┬────────┬────────┘
                     literal fast-pattern│        │full regex body (pcre:"...")
                     (+ rule_id, mods)   │        │+ rule_id
                                         ▼        ▼
                    ┌────────────────────┐   ┌─────────────────────────┐
                    │ 2. AC PREFILTER    │   │ 3. REGEX COMPILER        │
                    │    ENGINE          │   │  Thompson → subset →     │
                    │  Next-Move DFA     │   │  Hopcroft minimization   │
                    │  over all literal  │   │  → per-rule minimal DFA  │
                    │  fast-patterns     │   │  (or extended-NFA+       │
                    │  §2.4b             │   │  liveness for det.       │
                    │                    │   │  back-ref rules, §2.7)   │
                    └─────────┬──────────┘   └────────────┬─────────────┘
                              │ candidate rule_id                       │ compiled per-rule
                              │ + match end-position                    │ verifier DFA/NFA,
                              │ (avg < 5 candidates/packet,              │ keyed by rule_id
                              │  [Dossier §7])                          │
                              ▼                                         ▼
                    ┌─────────────────────────────────────────────────────┐
                    │ 4. VERIFIER DISPATCH                                 │
                    │  on AC hit for rule_id: check positional modifiers   │
                    │  (offset/depth/distance/within) against payload,     │
                    │  then invoke rule_id's compiled DFA/NFA from (3) on  │
                    │  the relevant window. Also runs the "no-anchor       │
                    │  fallback" set (RDP-1): rules with no extractable    │
                    │  literal, evaluated on every packet post header-    │
                    │  filter, accounted separately in §6 metrics.        │
                    └───────────────────────────┬───────────────────────┘
                                                  │ verified byte-level hits
                                                  │ (rule_id, span)
                                                  ▼
     tokenized SQL-bearing         ┌─────────────────────────┐
     fields (from HTTP/DB          │ 5. SQLi LEXER +          │
     parameter extraction,         │    TAINT TRACKER         │
     out of scope — see §4) ──────▶│  quote-parity 2–4 state  │
                                   │  DFA + token stream with │
                                   │  taint bits, §2.5 pt.1   │
                                   └────────────┬─────────────┘
                                                 │ tagged token stream
                                                 ▼
                                   ┌─────────────────────────┐
                                   │ 6. SQLi DPDA             │
                                   │    STRUCTURAL RECOGNIZER │
                                   │  LR(1) shift-reduce,     │
                                   │  §2.6 grammar, decision  │
                                   │  predicate on structural │
                                   │  reduction + taint       │
                                   └────────────┬─────────────┘
                                                 │ SQLi verdicts
                                                 ▼
     ┌─────────────────────────────────────────────────────────────────┐
     │ 7. FLOW / STREAM STATE MANAGER                                    │
     │  per-TCP-flow control block: AC state s_t + DPDA stack snapshot   │
     │  at packet-boundary k; packet k+1 resumes at s_t, no reassembly   │
     │  §2.5, §4, [Dossier §18 Option A]                                 │
     └───────────────────────────────────┬───────────────────────────────┘
                                          │ resumed state in / out per packet
                                          ▼
     ┌─────────────────────────────────────────────────────────────────┐
     │ 8. ALERT EMITTER / RESULT AGGREGATOR                              │
     │  merges byte-level (AC+DFA) and structural (DPDA) verdicts into   │
     │  the alert record schema (§4), assigns FP/GB-normalized severity  │
     └─────────────────────────────────────────────────────────────────┘

     (cross-cutting, attaches to every numbered box above via lightweight
      counters, not a data-plane dependency)
     ┌─────────────────────────────────────────────────────────────────┐
     │ 9. INSTRUMENTATION & METRICS COLLECTOR                            │
     │  per-tier transition/op counters, cycle timers, memory probes;    │
     │  feeds §6 EVALUATION HARNESS directly                             │
     └─────────────────────────────────────────────────────────────────┘
```

### 3.2 Per-component contract

| # | Component | Responsibility | Inputs | Outputs | Interface contract with neighbors | Owner |
|---|---|---|---|---|---|---|
| 1 | Rule/Signature Loader | Parse rule files into structured records; classify each rule as **literal-anchored** (has a usable fast pattern), **deterministic-back-ref** (≤`L` live back-refs, §2.7), or **no-anchor-fallback** (RDP-1) | Rule file text (§4 grammar) | `(rule_id, fast_pattern_literal, positional_mods)` per anchored rule → AC Prefilter; `(rule_id, regex_body)` per rule → Regex Compiler; `(rule_id)` set → Verifier Dispatch's fallback list | Emits one `FastPatternRecord` (§4) per anchored rule and one `RegexCompileJob` per regex-bearing rule; never emits merged automata | Compiler Lead |
| 2 | AC Prefilter Engine | Build+hold the single Next-Move DFA (§2.4b) over **all** extracted literal fast-patterns; scan every payload byte once | Byte stream (payload), `FastPatternRecord`s at build time | `(rule_id, end_position)` hits, streamed as found | Build-time: consumes Loader output only, never regex bodies. Runtime: one call per byte, `O(1)` per call; hands hits to Verifier Dispatch, never directly to the alert path | Core Automaton Lead |
| 3 | Verifier Dispatch | On each AC hit, check `offset/depth/distance/within` positional constraints (§4); if satisfied, look up rule_id's compiled verifier and invoke it on the bounded window; separately, run the no-anchor-fallback rule set every packet | AC hits, compiled verifier handles (from Regex Compiler), payload window, no-anchor rule list | Verified `(rule_id, span)` hits | Never invokes a verifier for a rule whose positional constraints failed — this is what keeps the average candidate count under 5/packet meaningful rather than illusory `[Dossier §7]` | Core Automaton Lead |
| 4 | Regex Compiler | Offline: Thompson → subset construction → Hopcroft minimization per literal-anchored/no-anchor regex rule; extended-NFA + static liveness analysis for deterministic-back-ref rules (§2.7); reject (flag, don't silently accept) any rule requiring unbounded back-reference liveness or non-regular unresolvable constructs, routing those to the "delegate to library" path noted in §5 Module 2 | `RegexCompileJob`s from Loader | Compiled per-rule DFA/NFA, keyed by `rule_id`, handed to Verifier Dispatch's lookup table | Pure function of one rule at a time — **never** reads or writes AC trie state; this separation is the direct fix for Refuted Claim #1 | Compiler Lead |
| 5 | SQLi Lexer + Taint Tracker | Tokenize a designated value-bearing field (already extracted by upstream HTTP/DB-param handling, out of scope per §4) into the §2.6 terminal alphabet, tagging each token with a taint bit; run the quote-parity DFA inline | Raw bytes of one value-bearing field, plus a taint mask marking which byte ranges are user-controlled | Tagged token stream | Emits one token stream per field per request; a lex error (unrecognized byte sequence) is itself a signal, logged, not silently dropped | Scanner/Demo Lead |
| 6 | SQLi DPDA Structural Recognizer | Run the LR(1)/LALR(1) shift-reduce table (§2.6) over the tagged token stream; apply the decision predicate (§2.6) on every structural-production reduce | Tagged token stream | SQLi verdict record (matched production trace, taint-latch position) | Deterministic, one token consumed or one reduce per step, `O(n)` total; never backtracks | Scanner/Demo Lead |
| 7 | Flow/Stream State Manager | Own the per-TCP-flow control block holding `(AC state s_t, DPDA stack snapshot)`; on packet boundary, save state out / restore state in so scanning resumes without reassembly | Packet boundary events, current AC/DPDA state | Resumed state handed back into components 2 and 6 for the next packet in the flow | One control block per flow; bounded memory per flow is an explicit acceptance criterion (§6 Secondary Claim 2) | Integration Lead |
| 8 | Alert Emitter / Result Aggregator | Merge AC+DFA byte-level hits and DPDA structural verdicts into the alert record schema (§4); compute FP/GB-normalized severity | Verified hits (3), SQLi verdicts (6) | `AlertRecord` (§4) stream | Sole writer of the alert schema; downstream consumers (logging, demo UI) never see raw component output | Integration Lead |
| 9 | Instrumentation & Metrics Collector | Attach lightweight counters/timers at every component boundary; expose both algorithmic op-counts and wall-clock, per `[Dossier §35, §36]`'s honest-treatment requirement | Hooks into 1–8 | Metrics stream consumed directly by §6 EVALUATION HARNESS | Read-only observer; must have zero effect on the data-plane control flow (no counter update may branch on payload content) | Benchmarking Lead |

---

## 4. DATA CONTRACTS

### 4.1 Signature rule file grammar

AEGIS-AC's rule loader accepts the same surface syntax as Snort 2.x/Snort 3/Suricata rules
`[Dossier §6]`, restricted to the keyword subset the engine actually consumes:

```
Rule        ::= Header LPAREN Options RPAREN
Header      ::= Action Protocol SrcAddr SrcPort Direction DstAddr DstPort
Action      ::= "alert" | "log" | "pass" | "drop"
Protocol    ::= "tcp" | "udp" | "http" | "ip"
Direction   ::= "->" | "<>"
Options     ::= Option (";" Option)* ";"?
Option      ::= "msg" ":" QuotedString
              | "content" ":" QuotedString | "content" ":" HexBytes
              | "nocase"
              | "offset" ":" Integer
              | "depth" ":" Integer
              | "distance" ":" Integer
              | "within" ":" Integer
              | "fast_pattern" | "fast_pattern" ":" "only"
              | "pcre" ":" "/" RegexBody "/" Flags
              | "sid" ":" Integer
              | "rev" ":" Integer
              | "classtype" ":" IDENT
QuotedString ::= '"' (any char except unescaped '"') '"'
HexBytes     ::= "|" (HexPair " "?)+ "|"
```

**Fast-pattern selection (loader responsibility — §3 Component 1):** among a rule's `content`
options, the **longest** one is chosen automatically as the fast pattern unless a `content` is
explicitly marked `fast_pattern` (override) or `fast_pattern:only` (participates in AC prefilter
only, skipped in post-prefilter verification) `[Dossier §6, §7]`. A rule with **no** `content`
option at all — pure `pcre` — cannot participate in prefiltering and is routed to the no-anchor
fallback set (RDP-1).

**Worked examples (hand-traceable, reused in §5 module tests):**

```
alert tcp any any -> any 80 (msg:"HTTP GET to admin panel";
    content:"GET"; offset:0; depth:3;
    content:"/index.html"; distance:1; within:20; sid:1000001;)
```
→ Loader emits fast pattern `"/index.html"` (longer of the two `content`s, so auto-selected) with
positional modifiers `distance:1, within:20` relative to the first content match, plus a secondary
positional check on `"GET"` at `offset:0, depth:3`. No `pcre`, so no Regex Compiler job.

```
alert tcp any any -> any 80 (msg:"SQLi UNION probe"; content:"UNION"; nocase;
    fast_pattern; pcre:"/UNION\s+SELECT/i"; sid:1000002;)
```
→ Fast pattern `"UNION"` (case-folded at AC build time, per `nocase`) drives the AC prefilter;
on hit, Verifier Dispatch invokes the compiled DFA for `/UNION\s+SELECT/i`. This is the canonical
two-stage example: **note it is exactly the pattern the original design's Refuted-Claim-#1 error
would have merged into the AC trie itself — it cannot be, because `\s+` is unbounded repetition.**

```
alert tcp any any -> any 80 (msg:"pathological nested quantifier";
    pcre:"/(a+)+b/"; sid:1000003;)
```
→ No `content` at all: routed to the no-anchor fallback set (RDP-1), evaluated every packet
post-header-filter, and flagged by the Regex Compiler (§3 Component 4) as a ReDoS-risk pattern
per `[Dossier §10]` rather than compiled into a DFA that would itself explode (§2.3).

### 4.2 Alert record schema

```
AlertRecord ::= {
  alert_id        : UUID,
  timestamp_ns    : uint64,          -- packet arrival time, nanosecond epoch
  flow_id         : (src_ip, src_port, dst_ip, dst_port, proto),
  rule_id         : uint32,          -- sid from the triggering rule, or 0 for SQLi-structural
  tier            : enum { AC_ONLY, AC_PLUS_DFA, BACKREF_VERIFIED, NO_ANCHOR_FALLBACK,
                            SQLI_STRUCTURAL },
  match_span      : (start_byte: uint32, end_byte: uint32),  -- within the reassembly-free
                                                               -- per-packet payload; see §3
                                                               -- Component 7
  matched_pattern : string | null,   -- the fast-pattern literal or rule_id label; null for
                                      -- SQLI_STRUCTURAL, which instead populates production_trace
  production_trace: [string] | null, -- ordered list of grammar productions reduced through the
                                      -- taint-latch point (§2.6); populated only for
                                      -- SQLI_STRUCTURAL
  severity        : enum { LOW, MEDIUM, HIGH, CRITICAL },
  msg             : string,          -- from the rule's msg field, or a generated description
                                      -- for SQLI_STRUCTURAL
}
```

### 4.3 Benchmark result schema

One record per `(system, dataset, k, run_index)` — required so that §6's ≥100-run statistical
reporting `[Dossier §35]` can be computed without re-running anything:

```
BenchResultRecord ::= {
  system          : enum { AEGIS_AC, NAIVE_MULTIPATTERN, STANDARD_AC, HYPERSCAN_SURICATA,
                            PCRE_BACKTRACKING },
  dataset         : string,          -- e.g. "synthetic_k3000_seed20260920", "cic-ids2017-day3"
  k               : uint32,          -- signature-set size used for this run
  run_index       : uint32,          -- 0..N-1, N >= 100 per [Dossier §35]
  op_count        : {
      transitions   : uint64,        -- exact automaton transitions (algorithmic, HW-independent)
      failure_moves : uint64,        -- 0 for Next-Move DFA runs; >0 only for goto/failure-machine
                                       -- runs kept for the §2.4 <2n-vs-n comparison
      mem_refs      : uint64
  },
  wall_clock_ns   : { total: uint64, per_byte_ns: float64 },
  throughput      : { gbps: float64, bytes_per_cycle: float64 },
  latency_ns      : { mean: float64, p50: float64, p95: float64, p99: float64, max: float64 },
  memory_bytes    : { resident: uint64, automaton_bytes: uint64 },
  correctness     : { true_positives: uint32, false_positives: uint32, false_negatives: uint32,
                       fp_per_gb: float64 },
  cache           : enum { COLD, WARM },   -- [Dossier §35] mandatory both-conditions reporting
  env             : { cpu: string, compiler_flags: string, python_impl: string | null,
                       git_commit: string }
}
```

### 4.4 Synthetic signature generator spec

**Purpose:** produce reproducible signature sets of size `k ∈ [100, 10000]` with realistic length
and shared-prefix distributions, since the dossier requires scaling experiments across exactly
this range `[Dossier §6, §32]` and real rulesets (Snort Community ~9–10k, ET Open ~40–60k) are
either too large to iterate on quickly or licensed such that a fully reproducible, seedable
synthetic generator is needed alongside them for the artifact-evaluation requirements of
`[Dossier §38]`.

**Parameters (all seedable; default seed `20260920` reproduces every number below):**
- `k` — signature count, swept over `{100, 300, 1000, 3000, 10000}`.
- Length distribution: log-normal, `μ = ln(12)`, `σ = 0.55`, clipped to `[4, 64]` bytes — chosen so
  the mean length sits near typical Snort `content` literal lengths (single-digit-to-20s bytes)
  while still producing a long tail up to 64 bytes.
- Byte-class mixture per generated character: 55% lowercase letters, 10% uppercase, 8% digits, 17%
  punctuation/structural bytes (`/.-_=:;%&?+()[]{}<>'"\,@!#$*`), 5% space, 5% arbitrary byte
  (`0–255`) — approximates the mix of URL-path-like, keyword-like, and binary-signature-like
  content actually seen in NIDS rulesets.
- Shared-prefix control: a small pool of `F = max(8, round(0.05·k))` "family" seed strings; each
  new signature independently has a 15% chance of extending a **previously generated** signature's
  prefix (`p_deep`, modeling deep prefix chains that stress the AC trie/failure-link structure) and
  a 40% chance of extending one of the `F` family seeds with Zipf-weighted family selection
  (`p_fam`, modeling the real-world clustering of rules around a small number of common keyword
  families such as `UNION`, `/etc/passwd`, `cmd.exe`); the remaining ~45% are drawn fresh.
- Exact duplicates are rejected and redrawn (a fresh signature set has no repeated literal).

**Verified output characteristics `[Verified in this doc]` (reproduces to the state count with the
default seed — use these exact numbers as the expected values in the Module 1 unit test, §5):**

| `k` | `Σ|pᵢ|` (m) | mean length | trie states `|S|` | `|S|` / `m` | byte classes (case-folded) | dense `Σ=256`, int32 table | class-reduced, int16 table |
|---|---|---|---|---|---|---|---|
| 100 | 1,401 | 14.0 | 1,079 | 0.770 | 89 | 1.1 MiB | 0.2 MiB |
| 300 | 4,188 | 14.0 | 3,066 | 0.732 | 148 | 3.0 MiB | 0.9 MiB |
| 1,000 | 13,660 | 13.7 | 9,639 | 0.706 | 202 | 9.4 MiB | 3.7 MiB |
| 3,000 | 41,860 | 14.0 | 29,444 | 0.703 | 231 | 28.8 MiB | 13.0 MiB |
| 10,000 | 141,730 | 14.2 | 98,822 | 0.697 | 231 | 96.5 MiB | 43.5 MiB |

This table is itself the first answer to RDP-8's memory-footprint open question — for a **dense**
`Σ=256` `int32` Next-Move table at `k=10,000` the engine needs **~96.5 MiB**, already close to the
dossier's `<100MB` target `[Dossier §7 OPEN QUESTIONS, item 3]`; the class-reduced `int16` layout
(§5 Module 1) cuts this to **~43.5 MiB**. The remaining gap between this synthetic estimate and a
real-ruleset measurement is exactly what the `TODO(open-gap)` in RDP-8 still needs the real-data
run of §6 to close — the synthetic number is a design target, not a substitute for the measurement.

---

## 5. MODULE-BY-MODULE IMPLEMENTATION PLAN

Reference language for signatures below is Python with type hints (per `[Dossier §35, §36]`'s own
framing of a Python research prototype with an optional C/Cython inner loop); this is a
specification convention, not a mandate — any team member may implement in another language as
long as the signatures' contracts and the stated complexity bounds are preserved. **No function
bodies are written here — only signatures, pseudocode, and expected test values.**

### Module 1 — AC Prefilter Engine (Owner: Core Automaton Lead)

**File layout**
```
ac_prefilter/
  __init__.py
  trie.py          # ACTrie construction (goto function)
  failure.py       # BFS failure-link + output-inheritance construction
  nextmove.py      # precomputed Next-Move DFA construction, dense + class-reduced layouts
  scan.py          # streaming scan over the Next-Move DFA
  types.py         # Match, ACTrie, NextMoveDFA dataclasses
tests/
  test_ac_prefilter.py
```

**Class / function signatures**
```python
@dataclass
class ACTrie:
    goto: list[dict[int, int]]      # goto[state][byte] -> state
    out: list[frozenset[int]]       # out[state] -> set of rule_ids accepted at this state
    fail: list[int]                 # fail[state] -> state, filled in by build_failure_links

def build_trie(patterns: list[tuple[int, bytes]]) -> ACTrie:
    """patterns: list of (rule_id, literal_bytes). O(Σ|p_i|) time/space. [Dossier §1]"""

def build_failure_links(trie: ACTrie) -> None:
    """In-place BFS fill of trie.fail and out-inheritance out[s] |= out[fail[s]].
    O(Σ|p_i|) total work across all states. [Dossier §1, §4a]"""

@dataclass
class NextMoveDFA:
    delta: "np.ndarray[int32]"      # shape (|S|, 256) dense, OR
    delta_classes: "np.ndarray[int16] | None"  # shape (|S|, |byte-classes|) class-reduced
    class_of: "np.ndarray[uint8] | None"       # byte -> class id, only set if class-reduced
    out: list[frozenset[int]]

def build_nextmove(trie: ACTrie, layout: Literal["dense", "class_reduced"] = "dense") -> NextMoveDFA:
    """Precompute δ per Algorithm 4. O(|S|·|Σ|) time regardless of layout (layout only changes
    the *storage* constant, per §4.4's table). [Dossier §1, §12]"""

class Match(NamedTuple):
    end_position: int
    rule_ids: frozenset[int]

def scan(dfa: NextMoveDFA, payload: bytes, start_state: int = 0) -> Iterator[Match]:
    """Exactly len(payload) transitions; yields a Match only when out[s] is non-empty.
    Accepts start_state for cross-packet resumption (§3 Component 7). [Dossier §1, §13]"""
```

**Algorithm pseudocode**

```
TRIE-BUILD(patterns):
    root = new state 0
    for (rule_id, p) in patterns:
        s = root
        for byte in p:
            if goto[s][byte] undefined: goto[s][byte] = new state
            s = goto[s][byte]
        out[s] = out[s] ∪ {rule_id}
    return trie

FAILURE-BUILD(trie):                                  # Algorithm 2/3 of [Dossier→Aho&Corasick 1975]
    queue = []
    for byte, s in trie.goto[root]:
        fail[s] = root; queue.push(s)
    while queue not empty:
        r = queue.pop()
        for byte, s in trie.goto[r]:
            queue.push(s)
            t = fail[r]
            while t != root and goto[t][byte] undefined: t = fail[t]
            fail[s] = goto[t][byte] if defined else root
            out[s] = out[s] ∪ out[fail[s]]              # inheritance — [Dossier §1]

NEXTMOVE-BUILD(trie, Σ):                               # Algorithm 4
    for byte in Σ: delta[root][byte] = goto[root][byte] if defined else root
    queue = children of root
    while queue not empty:
        r = queue.pop()
        for byte in Σ:
            if goto[r][byte] defined: delta[r][byte] = goto[r][byte]; queue.push(goto[r][byte])
            else: delta[r][byte] = delta[fail[r]][byte]
    return delta

SCAN(delta, out, payload, s = start_state):
    for i, byte in enumerate(payload):
        s = delta[s][byte]                              # exactly 1 transition/byte — [Dossier §1]
        if out[s] not empty: yield Match(i, out[s])
    return s                                             # returned for flow-state persistence
```

**Edge cases** (each must have a unit test): empty pattern set (DFA of 1 state, all self-loops to
root, never matches); a pattern that is a proper prefix of another (e.g. `{"he","her"}` — the
shorter pattern's accepting state must still be visited and reported mid-scan of the longer);
duplicate patterns with different `rule_id`s mapping to the same literal (both `rule_id`s must
appear in `out` of the shared accepting state); single-byte patterns; payload shorter than the
longest pattern (must not crash, must not spuriously match); non-`nocase` vs `nocase` literal
(case folding happens at `build_trie` time, not at scan time, so scan stays branch-free);
byte values `≥128` (must not be treated as multi-byte text — AEGIS-AC is byte-oriented, not
Unicode-aware, per `Σ=256` in §2.1).

**Unit tests with expected values (all `[Verified in this doc]`, reproducible from `ac_check.py`
described in this plan's viva example below)**

| Test | Input | Expected |
|---|---|---|
| `test_trie_size_classic` | `build_trie({he,she,his,hers})` | `len(trie.goto) == 10` |
| `test_failure_links_classic` | same trie | `fail[state("sh")] == state("h")`, `fail[state("she")] == state("he")`, `fail[state("his")] == state("s")`, `fail[state("hers")] == state("s")`, all other non-root states `fail == root` |
| `test_output_inheritance` | same trie | `out[state("she")] == {"he","she"}` (inherited via `fail`) |
| `test_scan_ushers_nextmove` | `scan(nextmove_dfa, b"ushers")` | hits `[(3,"she"),(3,"he"),(5,"hers")]` (0-indexed end position), exactly **6** transitions |
| `test_scan_ushers_failure_machine` | same payload, goto+failure machine | same hit set, **7** transitions total, of which **1** is a failure transition — confirms the `<2n` (goto/failure) vs exactly-`n` (Next-Move) distinction from `[Dossier §12]` |
| `test_scan_independent_of_k` | dictionaries `{backdoor,keylogger}` vs `{backdoor,keylogger,door,log}` scanned over the 65-byte demo payload (below) | Next-Move transition count is **exactly 65 in both cases** — direct test of Refuted Claim #4 (`[Dossier, Refuted Claim #4]`): scan cost independent of dictionary size `k` |
| `test_synth_generator_state_count` | `build_trie(gen_signatures(k=1000, seed=20260920))` | `len(trie.goto) == 9639` (§4.4 table) |

**Whiteboard-reproducible worked example for the viva**

Dictionary `{he, she, his, hers}`. Trie has states `0`(root), `1`("h"), `2`("he"), `3`("s"),
`4`("sh"), `5`("she"), `6`("hi"), `7`("his"), `8`("her"), `9`("hers"). Non-root failure links:
`fail(4)=1, fail(5)=2, fail(7)=3, fail(9)=3` (all other states fail to root `0`).
Output sets: `out(2)={he}`, `out(5)={he,she}`, `out(7)={his}`, `out(9)={hers}`.

Full Next-Move `δ`-table (columns `h,e,s,i,r`; all other bytes, including `u`, go to state `0`
from every state — omitted for brevity):

| state | h | e | s | i | r |
|---|---|---|---|---|---|
| 0 | 1 | 0 | 3 | 0 | 0 |
| 1 | 1 | 2 | 3 | 6 | 0 |
| 2 | 1 | 0 | 3 | 0 | 8 |
| 3 | 4 | 0 | 3 | 0 | 0 |
| 4 | 1 | 5 | 3 | 6 | 0 |
| 5 | 1 | 0 | 3 | 0 | 8 |
| 6 | 1 | 0 | 7 | 0 | 0 |
| 7 | 4 | 0 | 3 | 0 | 0 |
| 8 | 1 | 0 | 9 | 0 | 0 |
| 9 | 4 | 0 | 3 | 0 | 0 |

Scanning `"ushers"` byte by byte from state `0`, the state path is
**`0 → 0 → 3 → 4 → 5 → 8 → 9`** (after `u,s,h,e,r,s` respectively) — 6 transitions, matches
reported when entering states `5` (`out={he,she}`, at position 3) and `9` (`out={hers}`, at
position 5). This exact table and path should be reproduced on the whiteboard from the two BFS
pseudocode blocks above, not memorized.

**Second worked example (ties to the dossier's own corrected demo claim, Refuted Claim #7):**
payload `T = "installed backdoor and keylogger on target machine silently today"`, `len(T) = 65`.
With dictionary `{backdoor, keylogger}`: trie has 18 states, only non-root failure link is
`fail(state("back")) = state("k")` (because `"k"` is a suffix-prefix of `"back"`). Next-Move scan
reports `[(17,"backdoor"), (31,"keylogger")]` using **exactly 65** transitions — reproducing the
dossier's corrected wording *"the 65-character payload executes 65 state transitions in a
Next-Move DFA, detecting backdoor at positions 10–17 and keylogger at positions 23–31"*
`[Dossier, Refuted Claim #7; Verified in this doc]`. Extending the dictionary to
`{backdoor, keylogger, door, log}` (25 states, 8 non-root failure links chained through
`back→k→...→door` and `keyl→l→...→log`) changes the hit set to
`[(17,"backdoor"), (17,"door"), (28,"log"), (31,"keylogger")]` (demonstrating `out`-inheritance
overlap semantics, §2.4) while the Next-Move transition count **stays exactly 65** — the
hand-traceable proof of Refuted-Claim-#4's "independent of `k`" property.


### Module 2 — Rule Loader & Regex Compiler (Owner: Compiler Lead)

**File layout**
```
rule_compiler/
  __init__.py
  loader.py         # §4.1 grammar parser, fast-pattern auto-selection
  regex_ast.py       # regex subset parser -> AST (§2.6 excluded-construct detection lives here)
  thompson.py         # AST -> ε-NFA (§2.2)
  subset_construct.py # ε-NFA -> DFA (§2.3)
  hopcroft.py          # DFA minimization (§2.3)
  backref.py            # extended-NFA + static liveness analysis for deterministic back-ref rules
  verifier_bank.py       # keyed storage of compiled per-rule DFA/NFA, looked up by rule_id
tests/
  test_loader.py
  test_regex_pipeline.py
  test_backref_liveness.py
```

**Class / function signatures**
```python
@dataclass
class ParsedRule:
    rule_id: int
    fast_pattern: bytes | None       # None => no-anchor fallback (RDP-1)
    positional_mods: PositionalMods  # offset/depth/distance/within, possibly all-default
    regex_body: str | None           # the pcre:"..." body, if any
    nocase: bool

def load_rules(rule_file_text: str) -> list[ParsedRule]:
    """Parses §4.1 grammar. Auto-selects fast_pattern per the longest-content-wins rule unless
    fast_pattern/fast_pattern:only override present. [Dossier §6, §7]"""

RegexClass = Literal["REGULAR_ANCHORED", "REGULAR_NO_ANCHOR", "DET_BACKREF", "REJECTED_UNBOUNDED"]

def classify_regex(body: str) -> RegexClass:
    """REJECTED_UNBOUNDED = recursive quantifier over a group containing another quantifier
    (e.g. (a+)+), flagged not compiled — delegated to the no-anchor fallback path with a
    ReDoS-risk flag, never fed to subset_construct. [Dossier §10]"""

def thompson_construct(ast: RegexAST) -> NFA:
    """|Q| <= 2r, r = len(regex source). O(r) time/space. [Dossier §1]"""

def subset_construct(nfa: NFA, mode: Literal["anchored","search_sticky"]) -> DFA:
    """search_sticky mode adds an implicit '.*' prefix and treats the accept state as absorbing,
    modeling MPM-style 'match anywhere, then done' verifier semantics. Worst case |Q_D| = 2^|Q_N|.
    [Dossier §1]"""

def hopcroft_minimize(dfa: DFA) -> DFA:
    """O(|Σ|·n log n), n = |dfa.states| (unminimized), NOT a function of regex length r.
    [Dossier §20]"""

def compile_backref_rule(body: str, K_bound: int) -> DetBackrefNFA | None:
    """Extended-NFA + static liveness analysis (Namjoshi & Narlikar 2010). Returns None if the
    rule's live-back-reference count exceeds K_bound (caller routes to no-anchor fallback +
    libpcre delegation instead). O(m·K·m^{2L}) construction, L = max simultaneously-live
    back-refs. [Dossier §1, §2 item 3]"""

class VerifierBank:
    def register(self, rule_id: int, verifier: DFA | DetBackrefNFA) -> None: ...
    def get(self, rule_id: int) -> DFA | DetBackrefNFA | None: ...
```

**Algorithm pseudocode**

```
COMPILE-RULESET(rules):
    for rule in rules:
        if rule.regex_body is None: continue                  # pure content rule, nothing to compile
        cls = CLASSIFY-REGEX(rule.regex_body)
        if cls == REJECTED_UNBOUNDED:
            flag_for_fallback(rule.rule_id, reason="redos-risk"); continue
        if cls == DET_BACKREF:
            v = COMPILE-BACKREF(rule.regex_body, K_bound)
            if v is None: flag_for_fallback(rule.rule_id, reason="backref-K-exceeded"); continue
            bank.register(rule.rule_id, v); continue
        ast = PARSE-REGEX(rule.regex_body)
        nfa = THOMPSON(ast)
        mode = "anchored" if rule.fast_pattern is not None else "search_sticky"
        dfa = SUBSET-CONSTRUCT(nfa, mode)
        dfa = HOPCROFT-MINIMIZE(dfa)
        bank.register(rule.rule_id, dfa)

CLASSIFY-REGEX(body):
    ast = PARSE(body)
    if contains_backreference(ast): return DET_BACKREF
    if contains_nested_unbounded_quantifier(ast): return REJECTED_UNBOUNDED   # (a+)+, ((a|b)*)*
    return REGULAR_ANCHORED or REGULAR_NO_ANCHOR   # per whether a fast_pattern exists
```

**Edge cases:** regex with zero literal content and a nested unbounded quantifier simultaneously
(must be both no-anchor-flagged **and** ReDoS-flagged, not just one); back-reference count exactly
at `K_bound`; regex referencing a back-reference to a group that itself contains a quantifier
(ambiguous liveness — must be conservatively rejected, not guessed); empty regex body (malformed
rule, must error at load time, not at compile time); regex whose Thompson NFA has `> cap` states
in `search_sticky` mode before subset construction even starts (must fail fast with a clear
"would-explode" diagnostic rather than hanging — this is precisely the failure mode Yu et al. and
Becchi & Crowley observed `[Dossier §19]`); case-insensitive (`/i`) flag folding applied before
Thompson construction, not after (folding after would double DFA size unnecessarily).

**Unit tests with expected values (all `[Verified in this doc]`)**

| Test | Input | Expected |
|---|---|---|
| `test_thompson_bound` | `thompson_construct("abc")` | `len(nfa.states) <= 2*3` (regex length 3) |
| `test_subset_textbook` | `subset_construct(thompson("(a|b)*abb"), "anchored")` then `hopcroft_minimize` | canonical numbering: 5-state subset DFA over `{a,b}`, minimizes to **4** states (the `A` and `C` states of the standard textbook construction merge) — reproduces the standard Thompson→subset→Hopcroft textbook result for this regex |
| `test_backref_liveness_bound` | Snort ruleset back-ref census (real data, §6) | 111/120 unique back-reference expressions have `L=1` live back-reference `[Dossier §1, §2 item 3]` — regression-tested against the fixture in `tests/fixtures/backref_census.json` |
| `test_hopcroft_bound_not_regex_length` | two regexes of equal source length `r` but very different unminimized DFA size `n` | minimization wall-clock/op-count tracks `n`, not `r` — asserts the corrected bound `[Dossier §20]` empirically, guarding against silently reintroducing the original draft's wrong `O(r log r)` framing |
| `test_state_explosion_family` | `subset_construct(thompson("a.{%d}" % n), "search_sticky")` then minimize, `n∈{2,4,6,8,10,11,12}` | minimized sizes **9, 33, 129, 513, 2049, 4097, 8193** — matches the closed form `2^(n+1)+1` (`[Illustrative — not a cited measurement]`, used only as a regression fixture to prove the pipeline reproduces exponential-ish blowup on a bounded-gap wildcard construct, not cited as a published number) |
| `test_gap_family_distance_within` | `A.{d,w}B` chained-content style gap patterns, `(d,w) ∈ {(0,8),(4,12),(8,12),(8,16),(12,16)}` | minimized sizes **11, 35, 141, 139, 635** (`[Illustrative — not a cited measurement]`) — regression fixture only; the citable claim for "NIDS regex compilation explodes in practice" in §7 THREATS remains Yu et al. SIGCOMM 2006 / Becchi & Crowley ANCS 2007's **10⁶–10⁹ states** on real Snort regex sets `[Dossier §19]` |

**Whiteboard-reproducible worked example for the viva**

Regex `(a|b)*abb` over `Σ={a,b}` — the standard textbook running example for Thompson/subset/
Hopcroft. Canonical subset-construction states (BFS order) `A,B,C,D,E`:

| state | on `a` | on `b` | accepting? |
|---|---|---|---|
| A (start) | B | C | no |
| B | B | D | no |
| C | B | C | no |
| D | B | E | no |
| E | B | C | **yes** |

Hopcroft partition refinement: initial split `{A,B,C,D}` (non-accepting) vs `{E}` (accepting);
`A` and `C` have identical `(a,b)`-transition signatures into the *current* partition on every
refinement round (`A: B,C`; `C: B,C`), so they merge; `B` and `D` are each distinguishable from
everything else (their `b`-transitions land in different partition classes) and remain singleton
classes. Final minimal DFA: **4 states** `{AC, B, D, E}`. This is exactly the result to reproduce
step-by-step on the whiteboard — the algorithm block `HOPCROFT-MINIMIZE` above is the pseudocode
to walk through live.


### Module 3 — SQLi Lexer, Taint Tracker & DPDA Structural Recognizer (Owner: Scanner/Demo Lead)

**File layout**
```
sqli_engine/
  __init__.py
  quote_dfa.py        # 2-4 state quote-parity DFA (§2.5 point 1)
  lexer.py              # tokenizer over §2.6 terminal alphabet, taint-bit propagation
  grammar_tables.py       # generated LR(1)/LALR(1) ACTION/GOTO tables for §2.6's grammar
  parser.py                 # shift-reduce DPDA driver + decision predicate (§2.6)
  gen_tables.py               # offline table generator (canonical LR(1) -> LALR(1) core),
                               # NOT run at scan time; run once at build time, tables checked in
tests/
  test_quote_dfa.py
  test_lexer_taint.py
  test_grammar_tables_conflict_free.py
  test_decision_predicate.py
```

**Class / function signatures**
```python
class QuoteState(IntEnum):
    OUTSIDE = 0; INSIDE = 1; INSIDE_SAW_QUOTE = 2; INSIDE_ESCAPE = 3   # 4-state, escape-aware

def quote_step(state: QuoteState, byte: int) -> QuoteState:
    """Pure transition function, O(1). Folded into the lexer's main byte loop, never a
    separate pass. [Dossier §29]"""

@dataclass
class Token:
    kind: str            # terminal name from §2.6, e.g. "SELECT", "IDENT", "STR"
    text: bytes
    tainted: bool         # True iff any source byte of this token was inside a designated
                            # user-controlled value slot

def lex(field_bytes: bytes, taint_mask: list[bool]) -> list[Token]:
    """taint_mask[i] = True iff field_bytes[i] came from a user-controlled slot (set by the
    upstream HTTP/DB-param extraction layer, out of scope here — see §4). Returns None-safe
    token list; raises LexError (logged, not silently dropped) on unrecognized byte sequences."""

STRUCTURAL_PRODUCTIONS: frozenset[int]   # production indices for QueryExpr->QueryExpr UNION
                                          # SelectCore, StmtList->StmtList SEMI Stmt,
                                          # TableRef/Primary -> LPAREN QueryExpr RPAREN,
                                          # OrExpr->OrExpr OR AndExpr, AndExpr->AndExpr AND NotExpr,
                                          # Script->StmtList TAIL_COMMENT   (§2.6)

@dataclass
class SqliVerdict:
    is_attack: bool
    production_trace: list[str]
    taint_latch_position: int | None

def parse(tokens: list[Token]) -> SqliVerdict:
    """Table-driven shift-reduce over grammar_tables. O(n) in token count. Latches is_attack=True
    the first time a STRUCTURAL_PRODUCTIONS reduce pops a tainted symbol off the stack; does not
    stop parsing early (continues to build the full production_trace for the alert record, §4.2).
    [Dossier §28]"""
```

**Algorithm pseudocode**

```
LEX(field_bytes, taint_mask):
    q = OUTSIDE; tokens = []; i = 0
    while i < len(field_bytes):
        q' = QUOTE-STEP(q, field_bytes[i])
        # ... standard maximal-munch tokenization, folding QUOTE-STEP into the STR-token branch;
        # every emitted token's `tainted` = OR of taint_mask over its source byte range
        q = q'; i += advance
    return tokens

PARSE(tokens):
    stack = [(state=0, tainted=False)]
    trace = []; latch = None
    tokens = tokens + [EOF]
    i = 0
    loop:
        s = stack[-1].state; a = tokens[i].kind
        action = ACTION[s][a]
        if action == SHIFT(t):
            stack.push((t, tokens[i].tainted)); i += 1
        elif action == REDUCE(prod):
            l, r = PRODUCTIONS[prod]; m = len(r)
            popped = stack[-m:]; pivot_tainted = OR(entry.tainted for entry in popped)
            del stack[-m:]
            trace.append(f"{l} -> {' '.join(r)}")
            if prod in STRUCTURAL_PRODUCTIONS and pivot_tainted and latch is None:
                latch = current_input_position
            stack.push((GOTO[stack[-1].state][l], tainted=False))   # nonterminals carry no taint
        elif action == ACCEPT:
            return SqliVerdict(is_attack=(latch is not None), production_trace=trace,
                                taint_latch_position=latch)
        else:
            return LEX_OR_SYNTAX_ERROR   # malformed input is itself logged, not silently ignored
```

**Edge cases:** a syntax error partway through a stream that *already* latched a hit before the
error (must still report the hit — the parser does not discard `trace`/`latch` on later failure);
a tainted token that only ever appears inside a **non**-structural reduction (e.g. a tainted
numeric literal used only as `Primary → NUM`, never touching `UNION`/`OR`/parenthesised-subquery
productions) — correctly **not** an attack, this is the case that must not false-positive; nested
tainted parens that never actually reduce through `LPAREN QueryExpr RPAREN` (e.g. a merely
parenthesised scalar expression, `Primary → LPAREN Expr RPAREN`) — also correctly not latched,
since that production is not in `STRUCTURAL_PRODUCTIONS`; a value slot that is **entirely**
tainted (the whole field is user input, e.g. a raw POST body) — taint bits still need per-token
granularity because static keywords typed *by the attacker* (e.g. literally typing `UNION`) are
just as tainted as anything else, which is correct — the predicate does not try to distinguish
"attacker typed a keyword" from "attacker typed a value," only whether a structural reduction
pivoted on a byte the template did not control.

**Unit tests with expected values (`[Verified in this doc]`, generated by `gen_tables.py` and
checked into `tests/fixtures/`)**

| Test | Input | Expected |
|---|---|---|
| `test_grammar_conflict_free_lr1` | canonical LR(1) construction over the full §2.6 grammar | **1,689 states, 0 shift/reduce conflicts, 0 reduce/reduce conflicts** |
| `test_grammar_conflict_free_lalr1` | LALR(1) core-merge over the same construction | **179 states, 0 conflicts** |
| `test_no_unit_cycles` | unit-production reachability closure over all nonterminals | empty cycle set |
| `test_quote_dfa_escape` | `quote_step` walked over `O'Brien`, `it''s`, `it\'s` | correctly returns to `OUTSIDE` after each escaped/doubled quote, never mis-toggles into treating the rest of the field as "inside a string" |
| `test_decision_predicate_union_injection` | value slot containing `1 UNION SELECT a FROM b` inside a numeric context | `is_attack == True`, latch fires on the `QueryExpr → QueryExpr UNION SelectCore` reduce |
| `test_decision_predicate_or_injection` | value slot containing `' OR '1'='1` inside a string context | `is_attack == True`, latch fires on `OrExpr → OrExpr OR AndExpr` |
| `test_decision_predicate_benign_parens` | value slot containing an ordinary parenthesised arithmetic expression, e.g. `(1+2)*3`, in a numeric context | `is_attack == False` — `Primary → LPAREN Expr RPAREN` is not in `STRUCTURAL_PRODUCTIONS` |
| `test_decision_predicate_benign_nested_subquery_static` | a `WHERE ... IN (SELECT ...)` clause where the entire subquery is **static** template SQL and only a leaf numeric literal deep inside is tainted, and that literal never itself touches a structural production | `is_attack == False` — this is the explicit guard against the "any nested parens = alert" false-positive failure mode the dossier warns saturates toward 100% FP on benign traffic `[Dossier §28]` |

**Whiteboard-reproducible worked example for the viva**

A reduced grammar `G_mini` that abstracts exactly the two attack-relevant productions of the full
§2.6 grammar (`QueryExpr → QueryExpr UNION SelectCore` and `Primary/TableRef → LPAREN QueryExpr
RPAREN`) down to whiteboard size, using `s n` to stand in for one minimal "select a value" unit:

```
S' -> Q
Q  -> Q u S | S
S  -> s n | ( Q )
```

SLR(1) states (10 total, item sets shown with `•` marking the parse position), verified
conflict-free:

```
0: S'->•Q, Q->•Qu S, Q->•S, S->•s n, S->•( Q )
1: S'->Q•, Q->Q•u S
2: Q->S•
3: S->s•n
4: Q->•Qu S, Q->•S, S->•s n, S->•( Q ), S->(•Q )
5: Q->Qu•S, S->•s n, S->•( Q )
6: S->s n•
7: Q->Q•u S, S->( Q•)
8: Q->Qu S•
9: S->( Q )•
```

ACTION/GOTO table:

| state | `s` | `n` | `u` | `(` | `)` | `$` | GOTO `Q` | GOTO `S` |
|---|---|---|---|---|---|---|---|---|
| 0 | s3 | | | s4 | | | 1 | 2 |
| 1 | | | s5 | | | acc | | |
| 2 | | r2 | r2 | | r2 | r2 | | |
| 3 | | s6 | | | | | | |
| 4 | s3 | | | s4 | | | 7 | 2 |
| 5 | s3 | | | s4 | | | | 8 |
| 6 | | r3 | r3 | | r3 | r3 | | |
| 7 | | | s5 | | s9 | | | |
| 8 | | r1 | r1 | | r1 | r1 | | |
| 9 | | r4 | r4 | | r4 | r4 | | |

(`r1`=`Q→Qu S`, `r2`=`Q→S`, `r3`=`S→s n`, `r4`=`S→(Q)`.)

**Trace** parsing the tainted token stream `s n u( s n )$`, where the tokens from `u` through `)`
inclusive are attacker-controlled (bit shown as `*`) — modeling a value slot containing a static
`s n` (the template's own query) followed by attacker-injected `UNION (subquery)`:

```
stack                         input   action
[0]                            s       shift 3
[0,3]                          n       shift 6
[0,3,6]                        u       reduce S->s n
[0,2]                          u       reduce Q->S
[0,1]                          u       shift 5
[0,1,5*]                       (       shift 4
[0,1,5*,4*]                    s       shift 3
[0,1,5*,4*,3*]                 n       shift 6
[0,1,5*,4*,3*,6*]              )       reduce S->s n
[0,1,5*,4*,2]                  )       reduce Q->S
[0,1,5*,4*,7]                  )       shift 9
[0,1,5*,4*,7,9*]               $       reduce S->(Q)
[0,1,5*,8]                     $       reduce Q->Qu S   <-- structural production, tainted
                                                              pivot 'u' on the stack => LATCH
[0,1]                          $       accept
```

The latch fires exactly once, on the `Q → Q u S` reduction, because the popped symbols include the
tainted `u` (the injected `UNION`). This is the minimal, hand-traceable instance of the full
decision predicate from §2.6 and should be walked on the whiteboard exactly as shown, then
connected verbally to the corresponding full-grammar production
`QueryExpr → QueryExpr UNION SelectCore`.


### Module 4 — Flow/Stream State Manager, Alert Emitter & Pipeline Orchestrator (Owner: Integration Lead)

**File layout**
```
pipeline/
  __init__.py
  flow_table.py        # per-flow control block storage, LRU/TTL eviction
  orchestrator.py        # top-level per-packet driver wiring Modules 1-3 together
  alert_emitter.py         # §4.2 schema construction, FP/GB severity assignment
  sqli_token_buffer.py      # cross-packet partial-token carry for the lexer (Module 3 input)
tests/
  test_flow_state_resumption.py
  test_flow_eviction_bounded_memory.py
  test_alert_emitter_schema.py
```

**Class / function signatures**
```python
FlowKey = tuple[str, int, str, int, str]   # (src_ip, src_port, dst_ip, dst_port, proto)

@dataclass
class FlowControlBlock:
    ac_state: int = 0                       # Module 1 Next-Move DFA state, resumed each packet
    dpda_stack: list[tuple[int, bool]] = field(default_factory=lambda: [(0, False)])
    sqli_partial_token: bytes = b""          # bytes of an in-progress token split across packets
    last_seen_ns: int = 0
    byte_count: int = 0

class FlowTable:
    def get_or_create(self, key: FlowKey) -> FlowControlBlock: ...
    def evict_stale(self, now_ns: int, ttl_ns: int) -> int:
        """Removes flows idle longer than ttl_ns. Returns count evicted. Bounded-memory
        acceptance criterion for Secondary Claim 2 (§1, §6) depends on this running regularly."""

def process_packet(flow_key: FlowKey, payload: bytes, value_slots: list[TaintedSlot]) -> list[AlertRecord]:
    """Top-level per-packet entry point. See pseudocode below. value_slots are already-extracted
    (out of scope, §4) user-controlled fields for the SQLi path."""

def emit_alert(hit: Match | SqliVerdict, flow_key: FlowKey, rule_id: int | None) -> AlertRecord:
    """Pure function: builds one §4.2 AlertRecord. fp_per_gb computed by Module 5's running
    volume counter, injected here, not recomputed per-alert."""
```

**Algorithm pseudocode**

```
PROCESS-PACKET(flow_key, payload, value_slots):
    fcb = flow_table.get_or_create(flow_key)
    alerts = []

    # --- byte-level tier: AC prefilter + verifier dispatch (Modules 1-2) ---
    final_state = fcb.ac_state
    for match in AC-SCAN(nextmove_dfa, payload, start_state=fcb.ac_state):
        final_state = ... # updated incrementally inside AC-SCAN, see Module 1
        for rule_id in match.rule_ids:
            if POSITIONAL-CHECK(rule_id, match, payload):           # Module 3 of §3 diagram
                verifier = verifier_bank.get(rule_id)
                if verifier is not None and VERIFY(verifier, payload, match.end_position):
                    alerts.append(EMIT-ALERT(match, flow_key, rule_id))
    fcb.ac_state = final_state
    for rule_id in no_anchor_fallback_rules:                         # RDP-1
        if VERIFY(verifier_bank.get(rule_id), payload, span=(0, len(payload))):
            alerts.append(EMIT-ALERT(..., flow_key, rule_id))

    # --- structural tier: SQLi lexer + DPDA (Module 3), cross-packet-safe ---
    for slot in value_slots:
        raw = fcb.sqli_partial_token + slot.bytes
        tokens, remainder = LEX-WITH-CARRY(raw, slot.taint_mask)      # remainder = incomplete
                                                                        # trailing token, if any
        fcb.sqli_partial_token = remainder
        verdict = PARSE-RESUMABLE(tokens, resume_stack=fcb.dpda_stack)
        fcb.dpda_stack = verdict.stack_snapshot
        if verdict.is_attack:
            alerts.append(EMIT-ALERT(verdict, flow_key, rule_id=None))

    fcb.last_seen_ns = now_ns(); fcb.byte_count += len(payload)
    return alerts
```

**Edge cases:** a fast-pattern literal, or a SQLi keyword token, split exactly across a packet
boundary (the flagship test below); a flow that never completes (must still be evicted by TTL, not
leak forever — direct requirement of Secondary Claim 2's bounded-memory acceptance criterion,
§1); out-of-order packet delivery within a flow (explicitly **not** handled by AEGIS-AC's
lightweight per-flow state — out of scope, flagged as a limitation in §7, not silently assumed
away); a `value_slot` whose bytes span two packets such that the *first* packet ends mid-quoted-
string (the quote-parity DFA's state, not just the DPDA stack, must also be part of what's carried
in `sqli_partial_token`'s associated lexer state — implementation must persist `QuoteState`
alongside the partial token bytes, not just the raw bytes); duplicate/retransmitted TCP segments
(out of scope — assumed handled upstream by whatever supplies `payload`, explicitly noted as a
non-goal in §7).

**Unit tests with expected values (`[Verified in this doc]`)**

| Test | Input | Expected |
|---|---|---|
| `test_ac_state_resumption_mid_pattern` | 65-byte demo payload (§5 Module 1) split into two packets at byte offset **14** (inside `"backdoor"`, which spans bytes 10–17) | state after packet 1 = **4**; combined hits across both packets = `[(17,["backdoor"]),(31,["keylogger"])]`, **identical** to scanning the full 65 bytes in one call — proves cross-packet resumption is lossless even when a match literally straddles the boundary |
| `test_ac_state_resumption_arbitrary_splits` | same payload split at offsets `{0, 30, 65}` | combined hits identical to single-pass scan in every case |
| `test_flow_eviction_bounds_memory` | 100,000 synthetic flows, TTL = 60s, 1000 flows/s arrival, no traffic for 61s | `len(flow_table)` converges to 0 within one eviction sweep after the idle period; peak memory bounded by `flows_per_second × ttl_seconds`, not by total flows ever seen |
| `test_alert_schema_roundtrip` | one `Match` and one `SqliVerdict` | both produce a schema-valid `AlertRecord` per §4.2, with `tier` set to `AC_PLUS_DFA` and `SQLI_STRUCTURAL` respectively |

**Whiteboard-reproducible worked example for the viva**

Reuse the 65-byte demo payload. Split it after byte 14: packet 1 = `"installed ba"` +
`"ckdoor and k"`... — concretely, `T[:14] = "installed ba"[:14]` (i.e. `"installed ba"` is 12
chars; byte 14 lands two bytes into `"ckdoor"`, so packet 1 = `"installed back"`, packet 2 =
`"door and keylogger on target machine silently today"`). Scanning packet 1 alone with the
`{backdoor, keylogger}` Next-Move DFA from state `0` ends at **state 4** (the trie state
reached after consuming the 4-byte prefix `"back"` — a real, non-accepting mid-pattern state, not
state `0`). Handing state `4` as the start state into the Module 1 `scan` function for packet 2
correctly reports `"backdoor"` ending at global position 17 (position 3 *within packet 2*, plus
the 14-byte offset already consumed) — reproduce this on the whiteboard by walking the Module 1
`δ`-table for `{backdoor, keylogger}` (not reproduced in full above for space; regenerate via the
`FAILURE-BUILD`/`NEXTMOVE-BUILD` pseudocode of Module 1) starting from state `4` on the bytes of
`"door..."` and showing it lands on the accepting state for `"backdoor"` after exactly 4 more
transitions.


### Module 5 — Instrumentation, Synthetic Data Generator & Evaluation Harness Driver (Owner: Benchmarking Lead)

**File layout**
```
bench/
  __init__.py
  metrics.py            # per-tier counters/timers, zero data-plane branching (§3 Component 9)
  sig_generator.py         # §4.4 synthetic signature generator
  baselines.py               # thin adapters over the four required baselines (§6)
  harness.py                   # experiment driver: runs N>=100 trials, writes §4.3 schema
  report.py                      # figures/tables generation from harness output
tests/
  test_metrics_zero_overhead_branching.py
  test_sig_generator_reproducibility.py
  test_harness_statistics.py
```

**Class / function signatures**
```python
class Counters:
    transitions: int = 0
    failure_moves: int = 0
    mem_refs: int = 0
    def snapshot(self) -> dict[str, int]: ...

def instrument(component_fn: Callable, counters: Counters) -> Callable:
    """Wraps a Module 1-4 function with counter increments only; must never read payload
    *content* to decide whether to increment — only control-flow position, so the instrumentation
    itself cannot introduce a timing side-channel or, more importantly for correctness, a
    content-dependent branch that would contaminate the [Dossier §36] op-count-vs-wall-clock
    separation."""

def gen_signatures(k: int, seed: int = 20260920, **dist_params) -> list[bytes]:
    """Implements §4.4 exactly; MUST be seed-reproducible bit-for-bit (regression-tested against
    the §4.4 table's exact state counts)."""

@dataclass
class TrialConfig:
    system: Literal["AEGIS_AC","NAIVE_MULTIPATTERN","STANDARD_AC","HYPERSCAN_SURICATA",
                     "PCRE_BACKTRACKING"]
    dataset: str
    k: int
    n_runs: int = 100          # [Dossier §35] floor
    cache_condition: Literal["COLD","WARM"]

def run_trial(cfg: TrialConfig) -> list[BenchResultRecord]:
    """One record per run per §4.3 schema. WARM runs include >=1 untimed warmup pass first;
    COLD runs flush relevant caches (or use a freshly-forked process) before each timed run."""

def summarize(records: list[BenchResultRecord]) -> dict:
    """mean, stddev, 95% CI, P50/P95/P99 per (system,dataset,k); runs a Mann-Whitney U test when
    comparing two systems' distributions before any 'X is faster than Y' claim is written up.
    [Dossier §35]"""
```

**Algorithm pseudocode**

```
GEN-SIGNATURES(k, seed):
    rng = SEEDED-RNG(seed)
    F = max(8, round(0.05*k)); family_seeds = [RANDOM-BYTES(rng, 3..12) for _ in range(F)]
    weights = ZIPF-WEIGHTS(F)
    sigs = {}
    while len(sigs) < k:
        L = CLIP(LOGNORMAL(rng, mu=ln(12), sigma=0.55), 4, 64)
        u = rng.random()
        if sigs and u < 0.15: base = RANDOM-EXISTING-PREFIX(rng, sigs, L)
        elif u < 0.15+0.40: base = ZIPF-PICK(rng, family_seeds, weights)[:L-1]
        else: base = b""
        s = base + RANDOM-BYTES(rng, mixture=BYTE_CLASS_MIXTURE, count=L-len(base))
        if s not in sigs: sigs.add(s)
    return sigs

RUN-TRIAL(cfg):
    records = []
    sigs = GEN-SIGNATURES(cfg.k) if cfg.dataset.startswith("synthetic") else LOAD-REAL(cfg.dataset)
    system = BUILD-SYSTEM(cfg.system, sigs)                    # compiles/loads once, outside timing
    for run in range(cfg.n_runs):
        if cfg.cache_condition == "WARM": WARMUP(system)
        else: FLUSH-CACHES-OR-FORK()
        counters.reset(); t0 = clock()
        results = SCAN-DATASET(system, cfg.dataset)
        t1 = clock()
        records.append(BUILD-RECORD(cfg, run, counters.snapshot(), t1-t0, results))
    return records
```

**Edge cases:** a baseline system (e.g. real Suricata/Hyperscan) that reports throughput in a unit
AEGIS-AC's own instrumentation cannot directly instrument (must normalize via its own external
timing harness, not by modifying the baseline's internals — otherwise the comparison stops being
fair); `k=100,000`+ real-ruleset runs (ET Pro) that exceed reasonable CI runtime — must be
explicitly out-of-band, not silently skipped (flag in the report, don't just omit the row);
generator determinism across different machine architectures/Python versions (the RNG algorithm
choice, e.g. NumPy's `default_rng` PCG64, must itself be pinned, not just the seed, since different
RNG algorithms with the "same seed" produce different sequences — this is exactly the kind of
reproducibility gap `[Dossier §38]`'s artifact-evaluation requirements exist to catch); COLD-cache
measurement contaminated by OS-level page-cache warmup from a *previous* trial in the same process
— requires either process-per-trial isolation or an explicit cache-flush step, and the harness must
assert which strategy is in effect rather than leaving it ambiguous.

**Unit tests with expected values (`[Verified in this doc]`)**

| Test | Input | Expected |
|---|---|---|
| `test_sig_generator_reproducible_k1000` | `gen_signatures(k=1000, seed=20260920)` | `sum(len(s) for s in sigs) == 13660`, mean length `≈13.7`, and feeding the result into Module 1's `build_trie` yields exactly **9,639** trie states (§4.4 table) |
| `test_sig_generator_scaling_table` | `k ∈ {100,300,1000,3000,10000}` | matches every cell of the §4.4 table exactly, byte-for-byte reproducible from `seed=20260920` |
| `test_metrics_no_content_branch` | static analysis / fuzz test over `instrument()`-wrapped functions with randomized payloads | counter values are a pure function of `(control-flow path taken, payload length)`, never of specific payload byte values holding everything else fixed |
| `test_harness_min_runs_enforced` | `TrialConfig(n_runs=10)` | harness raises/warns: below the `[Dossier §35]` floor of ≥100 (or explicitly ≥30 with a documented justification) — the harness must not silently accept an underpowered run count |

**Whiteboard-reproducible worked example for the viva**

Walk the `k=1000` row of the §4.4 table live: seed `20260920`, log-normal length draw with
`μ=ln(12)≈2.485, σ=0.55`, clipped to `[4,64]`. Show that `Σ|pᵢ| = 13{,}660` for `k=1000` implies a
mean pattern length of `13.7` bytes (`13660/1000`), consistent with the target distribution's mean
(log-normal mean `= e^{μ+σ²/2} ≈ 12·e^{0.151} ≈ 14.0`, close to but not identical to the *empirical*
clipped-sample mean of `13.7` — the clipping at `[4,64]` slightly pulls the empirical mean down
from the unclipped theoretical mean, which is exactly the kind of distributional sanity-check a
reviewer may ask for live). Then show the derived trie-state count `9,639` is **not** simply
`Σ|pᵢ| + 1 = 13{,}661` — the shortfall (`13,660 − 9,639 = 4,021` "saved" states) is exactly the
shared-prefix compression coming from the generator's `p_deep`/`p_fam` parameters, i.e. the
`|S|/Σ|pᵢ| = 0.706` ratio in the table **is** the trie's prefix-sharing signal, and it should
visibly *decrease* as `k` grows (`0.770 → 0.697` from `k=100` to `k=10,000`) because the fixed-size
family pool gets reused more as more signatures are drawn — this trend is itself a talking point
for "does our synthetic generator produce realistic prefix-sharing at scale."

---

## 6. EVALUATION HARNESS

### 6.1 Datasets and verified download commands

`[Verified in this doc]` — every URL and package name below was checked live (package index
lookup, `git ls-remote`, or a direct page fetch) at specification time; re-verify before the
harness actually runs, since rulesets update daily and package versions drift.

**Rule/signature corpora:**
```bash
# Snort Community Ruleset — GPLv2, no registration required (confirmed against Snort's own FAQ,
# which explicitly states "available for download without registration")
curl -L -o community-rules.tar.gz \
  https://www.snort.org/downloads/community/community-rules.tar.gz

# Emerging Threats Open (Suricata format) — pin an exact Suricata version string in the URL,
# e.g. 7.0.0, per OISF's own suricata-update source index (license recorded there as MIT)
curl -L -o emerging.rules.tar.gz \
  https://rules.emergingthreats.net/open/suricata-7.0.0/emerging.rules.tar.gz
# NOTE: [Dossier §8] records ET Open's license as BSD-2-Clause; OISF's own suricata-update
# index.yaml (github.com/OISF/suricata-update) records it as MIT. Use the MIT determination
# (directly sourced from the ruleset maintainer's own tooling) in the paper, and flag the
# discrepancy with the dossier as a minor correction, not silently pick one.

# Synthetic signatures — no download; regenerate deterministically, §4.4/§5 Module 5:
python -m bench.sig_generator --k 100 300 1000 3000 10000 --seed 20260920 \
  --out data/synthetic/
```

**Attack-traffic / PCAP corpora:**
```bash
# CIC-IDS2017 — Canadian Institute for Cybersecurity, UNB; Open Academic License; page requires
# a download-request form (no anonymous direct-link), so this step is manual, not scriptable:
#   1. Visit https://www.unb.ca/cic/datasets/ids-2017.html and submit the access request form.
#   2. Download GeneratedLabelledFlows.zip (CSV) and the per-day PCAPs, e.g.
#      Monday-WorkingHours.pcap ... Thursday-WorkingHours-Morning-WebAttacks.pcap (SQLi/XSS day).
# TODO(open-gap): confirm at run time whether the request form still gates raw PCAP access or
# only the CSVs — this has changed across the dataset's lifetime and is not something this
# document can verify statically.

# SQLi-specific corpora (all directly downloadable, license-verified):
kaggle datasets download -d syedsaqlainhussain/sql-injection-dataset  # ODC-By / CC-BY-4.0
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git     # MIT
git clone https://github.com/client9/libinjection.git                # BSD-3-Clause; test corpus
                                                                        # lives under data/
```

**Reference implementations checked out as build/compare targets, not vendored:**
```bash
git clone https://github.com/farhiongit/aho-corasick-1975.git   # reference C AC (build baseline)
pip install pyahocorasick==2.3.1 --break-system-packages         # C-accelerated AC baseline
pip install hyperscan==0.8.2 --break-system-packages             # Python bindings to Hyperscan
pip install google-re2==1.1.20251105 --break-system-packages     # linear-time regex baseline
pip install libinjection-python==1.1.6 --break-system-packages   # SQLi tokenizer/fingerprint baseline
pip install dpkt==1.9.8 --break-system-packages                  # PCAP parsing for the harness itself
git clone https://github.com/coreruleset/coreruleset.git         # ModSecurity CRS ruleset (WAF baseline)
```
`[Dossier §30, §32, §34]` for dataset/baseline selection rationale.

### 6.2 Required baselines (do not compare against naive search alone)

Per `[Dossier §34]`, comparing AEGIS-AC only to a naive `O(N·m)` unindexed search **will be
rejected as a strawman** — automata prefiltering has been standard practice since 1975. The four
baselines below are mandatory, not optional:

| Baseline | Role | Package/build |
|---|---|---|
| Naive multi-pattern search | Lower-bound sanity check only, never the headline comparison | in-repo, `bench/baselines.py` |
| Standard C Aho–Corasick | Direct AC-vs-AC comparison, isolates AEGIS-AC's architectural contribution from raw AC performance | `pyahocorasick==2.3.1` |
| Intel Hyperscan / Suricata `mpm-algo` | Production SOTA SIMD engine | `hyperscan==0.8.2` bindings, or a built Suricata with `mpm-algo: hs` |
| Backtracking PCRE / `libpcre` | Demonstrates the ReDoS vulnerability AEGIS-AC is architected to avoid | Python `re` (backtracking) as a stand-in, cross-checked against `libpcre` directly for the adversarial tests |

Secondary/domain baselines: `libinjection-python==1.1.6` and ModSecurity CRS (via `coreruleset`)
for the SQLi-specific accuracy comparison; `google-re2==1.1.20251105` as a linear-time-regex
reference point (RE2 explicitly cannot express back-references, which is itself a useful
data point for the back-reference-handling comparison) `[Dossier §34]`.

### 6.3 Experiments

**E1 — Throughput and tail latency vs `k` (primary claim, §1).** Sweep
`k ∈ {100, 300, 1000, 3000, 10000}` synthetic signatures (§4.4) plus the full Snort Community
Ruleset (~9,000+ real signatures) as an upper anchor point. For each `(system, k)`: measure
`Gbps`, `bytes/cycle`, and latency `{mean, P50, P95, P99}` over benign, regex-heavy, and
nested-SQLi PCAP classes. ≥100 independent runs each (§6.5). **Figure F1:** throughput (y, Gbps)
vs `k` (x, log scale), one line per system, benign traffic — caption: *"AEGIS-AC's Next-Move-DFA
scan cost is architecturally independent of k (§2.4); this figure tests whether that holds in
measured throughput once verifier-dispatch and Python-interpreter overhead are included."*
**Figure F2:** same axes, P99 latency instead of mean throughput — caption notes this is the
security-relevant metric per `[Dossier §33]`, not mean throughput.

**E2 — Prefilter selectivity (secondary claim 1, §1).** For `k ∈ {100,...,10000}`, sweep the
fast-pattern anchor-length distribution (force literals to 5, 8, and 20 bytes) and measure the
secondary-verifier escalation rate on real HTTP traffic (CIC-IDS2017 benign day) — this is the
direct experiment resolving RDP-8/`[Dossier §7 OPEN QUESTIONS item 2]`. **Table T1:** rows = anchor
length, columns = `k`, cells = escalation rate (%) — caption: *"Escalation rate is the fraction of
AC prefilter hits that reach secondary-DFA verification; a rate approaching 100% indicates the
literal anchor is not selective, degrading toward full per-rule regex evaluation."*

**E3 — Cross-packet fragmentation (secondary claim 2, §1).** Replay CIC-IDS2017 PCAPs with
synthetic packet fragmentation/reordering injected at controlled rates (0%, 10%, 30%, 50% of
flows fragmented at a random byte offset). Measure detection accuracy (recall on planted
signatures) and per-flow memory overhead (§3 Component 7 / §5 Module 4's flow table), against a
full-TCP-reassembly baseline. **Figure F3:** recall (y) vs fragmentation rate (x) —
caption notes any recall drop directly falsifies secondary claim 2.

**E4 — Adversarial ReDoS.** Construct `(a+)+b`-class patterns and adversarial inputs `aⁿX`
(`[Dossier §10]`); replay against AEGIS-AC's regex compiler (which must have **already** rejected
these at compile time into the no-anchor-ReDoS-flagged fallback path, §5 Module 2) versus raw
backtracking PCRE. **Figure F4:** per-packet processing time (y, log scale) over a stream mixing
"good" and adversarial packets (x = packet index) for both systems — caption: *"PCRE's
per-packet time diverges exponentially at the adversarial packets (reproducing the Trace7 collapse
from multi-Gbps to ~1 pkt/sec, [Dossier §10]); AEGIS-AC's flagged-fallback path stays flat because
the compiler never attempted to build an exploding DFA for this pattern class in the first place."*

**E5 — AC cache-thrashing.** Construct payloads that force maximal failure-link traversal /
maximal disjoint-memory trie access at `k=10,000`; measure L1/L2 miss rate and memory-bus
saturation, both `COLD` and `WARM` cache conditions (§6.5). Compares dense-`Σ256` vs class-reduced
vs sparse/banded table layouts (§4.4, §5 Module 1) directly against each other, not just against
baselines — this experiment's real output is *which storage layout AEGIS-AC should ship with*.

### 6.4 Metrics (mandatory suite, per `[Dossier §33]`)

| Category | Metric | Why mandatory |
|---|---|---|
| Systems | Throughput (Gbps, bytes/cycle) | Standard headline number, but must be paired with... |
| Systems | Tail latency (P99, worst-case) | ...this — a single adversarial packet must not be able to paralyze the engine; mandatory for security-venue review |
| Systems | Memory footprint (MB, bytes/state) | Directly resolves RDP-8's memory open question |
| Systems | Preprocessing/build time | Separates one-time compile cost from per-packet scan cost — a live confusion source in the original draft (Refuted Claims #3, #4) |
| Detection | Precision/Recall/F1 | Standard |
| Detection | **False Positive Rate per Gigabyte (FP/GB)** | A raw "1% FP rate" at 10–100Gbps means millions of false alarms/hour; `[Dossier §33]` is explicit this must be volume-normalized, not reported as a bare percentage |

### 6.5 Run counts, variance reporting, and cache/interpreter honesty

- **≥100 independent runs** per `(system, dataset, k)` cell `[Dossier §35]`; report mean, standard
  deviation, 95% CI, and the P50/P95/P99 distribution, not just a mean.
- Apply a **Mann-Whitney U test** (non-parametric, since latency distributions are not assumed
  Gaussian) before writing any "AEGIS-AC is faster than X" sentence; report the p-value alongside
  the effect size, not just significance `[Dossier §35]`.
- **Both COLD and WARM cache conditions must be reported**, never just one `[Dossier §35]`. WARM
  runs include an untimed warmup pass; COLD runs isolate each timed run in a fresh process (or
  explicitly flush the relevant cache levels) — the harness must declare which strategy is active
  (§5 Module 5 edge cases) rather than leaving cache state ambiguous.
- **Honest Python-vs-production throughput treatment `[Dossier §36]`:** if AEGIS-AC's absolute
  Gbps trails Hyperscan's (it almost certainly will — Hyperscan's SIMD-decomposed engines exceed
  100Gbps for single literals `[Dossier §23]`), the writeup must not bury this. Required framing,
  in order: (1) report **algorithmic op-counts** (exact transitions/byte) alongside wall-clock, and
  show the op-count stays flat `O(n+z)` as `k` scales 100→10,000, reproducing the theoretical
  asymptotic independent of language overhead; (2) show **state-space parity** — AEGIS-AC executes
  the same number of transitions/char as the production engines it's compared against, so any
  wall-clock gap is attributable to implementation layer (interpreted Python vs compiled SIMD), not
  to a worse algorithm; (3) frame the contribution as validating the **architectural mechanism**
  (prefilter+per-rule-DFA+DPDA composition), not as claiming line-rate production throughput; (4)
  normalize hardware-neutral: cycles-per-byte (cpb), not just Gbps. Where the Python interpreter
  loop itself dominates (expected for `k` below the crossover point — RDP-8's first open question),
  report the crossover `k` explicitly as a finding, don't hide it in an appendix.

### 6.6 Figures/tables summary (captions above; consolidated list for the paper draft, §9)

`F1` throughput vs `k` · `F2` P99 latency vs `k` · `T1` prefilter escalation rate ·
`F3` fragmentation recall · `F4` ReDoS adversarial timeline · `T2` memory footprint by storage
layout (dense/class-reduced/sparse, from §4.4's table, extended with the `k=9,000` Snort Community
Ruleset measurement) · `T3` baseline comparison table (all four required baselines × all metrics,
§6.4) · `T4` FP/GB across the three SQLi baselines (AEGIS-AC DPDA, libinjection, ModSecurity CRS).

---

## 7. THREATS TO VALIDITY

This section is organized as a rehearsed Q&A: every attack a reviewer or viva examiner is likely
to raise, paired with the prepared response. Category groupings follow the dossier's own
"Major peer-review criticisms" checklist and "Accepted vs rejected paper flaws" table
`[Dossier §4, item 4; item 42]`, which the team should treat as a direct index into this section
when preparing for the viva.

### 7.1 Architectural attacks

| Attack | Prepared response |
|---|---|
| *"Why not just merge the regex-derived automata into the AC trie — wouldn't one unified automaton be faster?"* | Because AC only holds a finite dictionary; a regex with unbounded repetition (`\s+`, `*`, `+`) defines an infinite language that cannot be trie-expanded at all, let alone merged — this is exactly the original design's Refuted Claim #1 error. The two-stage prefilter (§3) is not a performance compromise, it is the only architecture that is *well-defined* for this rule class. |
| *"Doesn't the two-stage model just move the cost to the verifier — isn't `O(n)` prefilter + `O(rule-length)` verifier per hit actually worse in the worst case?"* | Only if the prefilter is not selective; that is precisely why E2 (§6.3) measures escalation rate directly rather than assuming it away, and why the fast-pattern auto-selection (§4.1, longest-literal-wins) is a deliberate selectivity-maximizing default, not an arbitrary choice. |
| *"What about rules with no usable literal at all — doesn't your `O(n+z)`-independent-of-`k` claim quietly break?"* | Yes, and this is disclosed up front, not discovered under cross-examination — see RDP-1. The no-anchor fallback set is accounted for as its own tier (`NO_ANCHOR_FALLBACK` in the alert schema, §4.2) with its own separately-reported cost in the evaluation (§6), not folded into the headline number. |

### 7.2 Formal / proof attacks

| Attack | Prepared response — full derivation to reproduce live |
|---|---|
| **The Bounded-Length Objection** (`[Dossier §27]`, RDP-2): *"Any packet has a finite MTU bound `N`. For fixed `N`, nested-parenthesis strings of length ≤ `N` form a finite set, hence a regular (Type-3) language. So your claim that a PDA is 'required' is simply false — a DFA suffices."* | **Correct that the language is regular — the claim was never language-membership, it's succinctness.** A DFA recognizing nesting depth up to `d` needs `Θ(d)` states *per delimiter type*, and for `t` independent delimiter types the bound is `Ω(dᵗ)`; `[Verified in this doc]`, the exact minimal-DFA size for `t=1` is `d+2`, and for general `t` it is `(tᵈ⁺¹−1)/(t−1)+1` (confirmed by direct minimization, §2.5). A DPDA tracks the identical depth `d` with `O(1)` control states and `O(log d)` stack bits. As `d` grows toward `N/2`, the DFA-vs-PDA state-complexity **gap is unbounded**, even though both automata recognize the same finite language for any fixed `N` — this is a standard descriptional-complexity result (Meyer & Fischer 1971; Holzer & Salomaa 2021, `[Dossier §27]`), not a claim about decidability. State this distinction explicitly and immediately if asked — conflating succinctness with decidability is exactly the "formalism/proof error" category the dossier's criticism checklist warns is a common rejection reason `[Dossier §4]`. |
| *"Don't matched quotes require a stack too, since strings can be arbitrarily long?"* | No — length is not depth. A 2–4 state DFA suffices for quote parity (§2.5 point 1) because SQL string literals cannot contain unescaped, recursively-nested literals inside themselves; there is no self-embedding structure to track, only a toggle plus escape-handling. This is proved, not asserted: the automaton is given explicitly in §5 Module 3, and its correctness is exactly what `test_quote_dfa_escape` checks. |
| *"Isn't 'flag any nested parens' a reasonable-enough heuristic?"* | No — it saturates toward ~100% false positives on benign enterprise SQL containing ordinary nested subqueries (`IN (SELECT ...)`) `[Dossier §28]`. AEGIS-AC's actual predicate is structural-template divergence (§2.6): a reduction through a *structural* production is only a signal when it pivots on a **tainted** (user-controlled) token, not merely when nesting is present at all — demonstrated end-to-end in `test_decision_predicate_benign_nested_subquery_static` (§5 Module 3). |
| *"Your Hopcroft-minimization complexity bound looks wrong — regex length should matter."* | It's `O(|Σ|·n log n)` where `n` is the **unminimized DFA's state count**, not the regex source length `r` — minimization operates on the automaton, which already exists by the time minimization runs; `r` has no direct role. `test_hopcroft_bound_not_regex_length` (§5 Module 2) is a regression test specifically guarding against silently reintroducing the original draft's incorrect `O(r log r)` framing. |
| *"Why LR(1)/table-driven parsing instead of simple recursive descent for the SQLi grammar?"* | Recursive-descent parsers for ambiguous or left-recursive grammar fragments can require backtracking, which reintroduces exactly the non-deterministic, potentially-exponential behavior AEGIS-AC exists to eliminate at the byte layer. A table-driven shift-reduce `LR(1)`/`LALR(1)` parser is deterministic by construction and guarantees strict `O(n)` time (§2.6) — and, machine-verified, the §2.6 grammar has zero conflicts, so the deterministic table actually exists for this grammar (many grammars are not `LR(1)`; this one is checked, not assumed). |

### 7.3 Empirical / statistical attacks

| Attack | Prepared response |
|---|---|
| *"You're comparing a Python prototype to Hyperscan's hand-tuned SIMD engine — of course you lose on raw Gbps. What does that prove?"* | Nothing about production readiness, and the paper says so explicitly (§6.5's honest-treatment protocol, `[Dossier §36]`): the claim under test is that the **op-count stays `O(n+z)` and state-space matches production engines transition-for-transition** as `k` scales, isolating the algorithmic/architectural contribution from the implementation-layer gap. Absolute Gbps is reported, but framed as a proof-of-concept measurement, not a production benchmark. |
| *"Single-run benchmark numbers, cherry-picked hardware."* | Not present in this design: ≥100 runs per cell, mean/stddev/95% CI/P50/P95/P99 reported, Mann-Whitney U test before any comparative claim, both `COLD` and `WARM` cache conditions reported (§6.5). |
| *"Why should I believe your synthetic signature generator is realistic?"* | It isn't offered as a substitute for real data — E1 anchors the synthetic sweep with the real ~9,000-signature Snort Community Ruleset as an upper data point, and the generator's parameters (length distribution, shared-prefix clustering) are stated and justified in §4.4, with the resulting trie-compression ratio (`|S|/Σ|pᵢ|` shrinking from 0.770 to 0.697 as `k` grows, §5 Module 5) reported as a falsifiable, inspectable property rather than an assumed one. |
| *"Only comparing against a naive loop is a strawman."* | Not done here — four required baselines (§6.2), explicitly including production SOTA (Hyperscan/Suricata) and the exact vulnerability class AEGIS-AC targets (backtracking PCRE), per `[Dossier §34]`'s explicit rejection warning. |
| *"Raw false-positive percentage sounds low — why should I care?"* | Because a "low" FP rate at 10–100 Gbps is millions of false alarms per hour; every FP number in this work is reported as FP/GB (§6.4), per `[Dossier §33]`'s explicit requirement. |

### 7.4 Novelty / related-work attacks

| Attack | Prepared response |
|---|---|
| *"Hybrid-FA, XFA, D²FA, and Counting Automata already solve DFA state explosion for NIDS regex — what's new here?"* | Nothing in this work claims a new *single-automaton* compression scheme — those six published solutions (`[Dossier §22]`) are acknowledged directly in related work and are complementary, not competing: any of them could replace AEGIS-AC's plain Thompson→subset→Hopcroft per-rule DFA compiler as a drop-in optimization (§8 BUILD ORDER lists this as a stretch goal). The claimed contribution is the **three-tier composition** (AC literal prefilter + per-rule regular verifier + streaming DPDA for structural SQLi) on raw packets, which the dossier's own literature survey found no 2015–2026 peer-reviewed system combining `[Dossier §1, §3]`. |
| *"SQLi detection is already solved at the WAF/app layer by libinjection and ModSecurity CRS — why do it in the NIDS at all?"* | Because those operate on reconstructed queries with application-layer context (parameter names, expected templates) that a network-layer NIDS does not have and, by design, should not need — a NIDS sees raw/URL-encoded/fragmented bytes, not a parsed query `[Dossier §26]`. This is presented as a complementary, defense-in-depth layer, not a replacement for WAF-layer detection; the paper's related-work section must say this plainly rather than implying network-layer SQLi detection obsoletes the app-layer tools (an overclaim that would itself be a credibility risk). |
| *"Is 'no published system combines X+Y+Z' just an absence-of-evidence claim?"* | Yes, and it is phrased as one, not overclaimed as proof of non-existence — the paper states the literature survey's scope and method (§9 Related Work) and invites correction rather than asserting a negative with false certainty; this is standard academic hedging, not evasion. |

### 7.5 Reproducibility, citation hygiene, and disclosure attacks

| Attack | Prepared response |
|---|---|
| *"I can't find your 'Sapats et al. AICT 2013' citation anywhere."* | Because it was wrong in the original draft and has been replaced with White, Fitzsimmons & Matthews, SPIE 2013 (RDP-6, `[Dossier, Refuted Claim #6]`) — the team should be ready to explain *why* the citation changed, not just that it did. |
| *"You cite your own team's internal proposal as source #7 — that's circular."* | It has been removed from the bibliography (RDP-3); if the original design decision needs to be referenced, it is described in prose as the team's own prior design, not cited as external literature. |
| *"Can I reproduce your results?"* | Public repo, pinned dataset versions and PRNG seeds (`seed=20260920` reproduces every §4.4/§5 number bit-for-bit), and a single `run_benchmarks.sh` regenerating every table/figure — the artifact-evaluation requirements of `[Dossier §38]` are treated as a build requirement, not a stretch goal (§8 BUILD ORDER). |
| *"Did you use AI coding assistance? Is that disclosed?"* | If used, disclosed per venue policy (IEEE/ACM require tool name, version, and specific tasks in Acknowledgments/Methods; authors remain 100% accountable for correctness, licensing, and security of any AI-assisted code or text) `[Dossier §44]` — tracked as an explicit BUILD ORDER checklist item (§8), not an afterthought at submission time. |

---

## 8. BUILD ORDER

Dependency-ordered, targeting the dossier's own 8–12 week undergraduate scope estimate
`[Dossier §5, item 5]`; laid out here as 10 weeks with a 1–2 week buffer. Owners use the five roles
from §3/§5: **Integration Lead** (1st author), **Compiler Lead**, **Core Automaton Lead**,
**Scanner/Demo Lead**, **Benchmarking Lead** `[Dossier §43]`.

| ID | Task | Depends on | Owner | Effort | Completion criteria |
|---|---|---|---|---|---|
| T0.1 | Purge the "8.7× vs PCRE" figure from every existing slide/poster/draft (RDP-4) | — | Integration Lead | 0.5 day | `grep -ri "8.7" **/*.{md,pptx,tex}` returns zero hits anywhere in team materials |
| T0.2 | Replace the garbled Sapats-et-al. citation with White, Fitzsimmons & Matthews SPIE 2013 everywhere it appears (RDP-6) | — | Integration Lead | 0.5 day | Citation string audited and replaced in every document, not just this one |
| T0.3 | Remove the circular self-citation (dossier bibliography item 7) from the paper's reference list (RDP-3) | — | Integration Lead | 0.25 day | Bibliography contains no self-referential "AEGIS-AC Team, Internal Documentation" entry |
| T0.4 | Correct both original Suricata-default statements (poster's "Hyperscan by default", proposal's "AC by default") to the `mpm-algo: auto` wording everywhere (RDP-5) | — | Integration Lead | 0.5 day | Both original wrong statements no longer appear anywhere in team materials |
| **Week 1** | | | | | |
| T1.1 | Finalize §4.1 rule grammar parser + §4.1 worked-example fixtures | — | Compiler Lead | 3 days | `load_rules()` round-trips all three §4.1 worked examples to the exact `ParsedRule` fields shown |
| T1.2 | Implement §4.4 synthetic signature generator | — | Benchmarking Lead | 3 days | `test_sig_generator_reproducible_k1000` and the full §4.4 table reproduce bit-for-bit from `seed=20260920` |
| T1.3 | Stand up repo skeleton, CI, `run_benchmarks.sh` scaffold (empty but wired), Docker/Vagrant reproduction env per `[Dossier §38]` | — | Integration Lead | 2 days | `docker build && docker run run_benchmarks.sh --dry-run` exits 0 |
| **Weeks 2–4 (parallel)** | | | | | |
| T2.1 | AC trie construction + failure-link BFS + output inheritance (Module 1) | T1.1 | Core Automaton Lead | 4 days | `test_trie_size_classic`, `test_failure_links_classic`, `test_output_inheritance` pass |
| T2.2 | Next-Move DFA construction, dense + class-reduced layouts | T2.1 | Core Automaton Lead | 3 days | `test_scan_ushers_nextmove`, `test_scan_ushers_failure_machine`, `test_scan_independent_of_k` pass |
| T2.3 | Regex AST parser + Thompson construction + subset construction + Hopcroft minimization (Module 2) | T1.1 | Compiler Lead | 5 days | `test_thompson_bound`, `test_subset_textbook`, `test_hopcroft_bound_not_regex_length` pass |
| T2.4 | Back-reference classification + extended-NFA/static-liveness compiler path | T2.3 | Compiler Lead | 3 days | `test_backref_liveness_bound` passes against the Namjoshi & Narlikar 111/120 fixture |
| T2.5 | Verifier bank + no-anchor-fallback routing (RDP-1) | T2.3, T2.4 | Compiler Lead | 2 days | A rule with zero `content` options is provably routed to the fallback path, never silently dropped |
| **Weeks 3–5 (parallel with 2.x tail)** | | | | | |
| T3.1 | §2.6 grammar encoding + offline LR(1)/LALR(1) table generator (`gen_tables.py`) | — | Scanner/Demo Lead | 4 days | `test_grammar_conflict_free_lr1` (1,689 states, 0 conflicts) and `test_grammar_conflict_free_lalr1` (179 states, 0 conflicts) pass |
| T3.2 | Quote-parity DFA + lexer + taint-bit propagation | T3.1 | Scanner/Demo Lead | 3 days | `test_quote_dfa_escape` passes |
| T3.3 | Shift-reduce DPDA driver + decision predicate | T3.1, T3.2 | Scanner/Demo Lead | 4 days | All four `test_decision_predicate_*` cases in §5 Module 3 pass, including the benign-nested-subquery negative case |
| **Weeks 4–6** | | | | | |
| T4.1 | Flow control block + flow table + TTL eviction | T2.2 | Integration Lead | 3 days | `test_flow_eviction_bounds_memory` passes |
| T4.2 | Cross-packet AC state resumption wiring | T2.2, T4.1 | Integration Lead | 2 days | `test_ac_state_resumption_mid_pattern` and `test_ac_state_resumption_arbitrary_splits` pass exactly as specified in §5 Module 4 |
| T4.3 | Cross-packet DPDA/lexer resumption (partial-token carry) | T3.3, T4.1 | Integration Lead + Scanner/Demo Lead | 3 days | A SQLi keyword split across two packets is still detected identically to the unsplit case |
| T4.4 | Alert emitter + §4.2 schema | T2.5, T3.3 | Integration Lead | 2 days | `test_alert_schema_roundtrip` passes for both `AC_PLUS_DFA` and `SQLI_STRUCTURAL` tiers |
| T4.5 | Full pipeline orchestrator wiring all of Modules 1–4 end to end | T2.5, T3.3, T4.4 | Integration Lead | 3 days | The three §4.1 worked-example rules, run against their designed trigger payloads, produce the expected alert records |
| **Weeks 4–6 (parallel)** | | | | | |
| T5.1 | Instrumentation counters (op-count + wall-clock), zero-content-branching guarantee | T2.2 | Benchmarking Lead | 3 days | `test_metrics_no_content_branch` passes |
| T5.2 | Baseline adapters (naive, `pyahocorasick`, Hyperscan/Suricata, PCRE) | §6.2 packages installed | Benchmarking Lead | 4 days | Each baseline adapter round-trips the classic `{he,she,his,hers}`/`"ushers"` example with the correct hit set |
| T5.3 | Harness driver (`run_trial`, `summarize`, Mann-Whitney U) | T5.1, T5.2 | Benchmarking Lead | 3 days | `test_harness_min_runs_enforced` passes; a smoke-test trial at `k=100` produces a schema-valid `BenchResultRecord` set |
| **Weeks 6–7** | | | | | |
| T6.1 | Full integration test suite across all 5 modules together | T4.5, T5.3 | whole team, Integration Lead owns sign-off | 4 days | Every unit test in §5 passes in the fully-wired pipeline, not just in module isolation |
| T6.2 | Dataset acquisition (Snort Community, ET Open, CIC-IDS2017 request form, Kaggle/PayloadsAllTheThings/libinjection corpora) | — | Benchmarking Lead | 3 days (+ wait time for CIC-IDS2017 access approval, start this task in Week 1 in parallel if possible — access-request lead time is outside the team's control) | All §6.1 datasets present and checksummed locally |
| **Weeks 7–9** | | | | | |
| T7.1 | Run E1 (throughput/latency vs `k`) | T6.1, T6.2 | Benchmarking Lead | 3 days compute + 1 day analysis | F1, F2 generated with ≥100 runs/cell, both cache conditions |
| T7.2 | Run E2 (prefilter selectivity) | T6.1, T6.2 | Benchmarking Lead | 2 days | T1 generated |
| T7.3 | Run E3 (cross-packet fragmentation) | T4.3, T6.2 | Benchmarking Lead + Integration Lead | 2 days | F3 generated, secondary claim 2's falsification condition directly checked |
| T7.4 | Run E4 (adversarial ReDoS) | T2.4, T6.1 | Compiler Lead + Benchmarking Lead | 2 days | F4 generated, primary claim's falsification condition 2 directly checked |
| T7.5 | Run E5 (AC cache-thrashing, storage-layout comparison) | T2.2, T6.1 | Core Automaton Lead + Benchmarking Lead | 2 days | T2 (extended) generated, resolving RDP-8's memory-footprint question against real data |
| **Weeks 9–10** | | | | | |
| T8.1 | Draft paper per §9 skeleton, all figures/tables wired in from T7.x outputs | T7.1–T7.5 | whole team, Integration Lead integrates | 5 days | Full draft compiles, every claim in §1 has a corresponding figure/table cited |
| T8.2 | AI-assistance disclosure audit (`[Dossier §44]`) | T8.1 | Integration Lead | 0.5 day | Acknowledgments section lists every AI tool used, by task, per venue policy |
| T8.3 | Re-verify any quoted submission-deadline/venue window against the live CFP (RDP-8's last open item) | T8.1 | Integration Lead | 0.5 day | No `[Unconfirmed]`-sourced date appears in any submission commitment |
| **Weeks 10–11 (buffer)** | | | | | |
| T9.1 | Viva rehearsal against every §7 THREATS TO VALIDITY entry, whiteboard derivations included | T8.1 | whole team | 3 days | Every team member can reproduce, unprompted, the §2.5 Bounded-Length-Objection derivation and at least one §5 module's whiteboard worked example |
| T9.2 (stretch) | Swap Module 2's plain per-rule DFA compiler for one of the six published state-explosion mitigations (`[Dossier §22]`, e.g. Hybrid-FA) as a bonus contribution | T2.3 stable | Compiler Lead | remaining buffer time | Only attempted if T0–T8 are complete and stable; explicitly optional |

---

## 9. PAPER SKELETON

Target format: workshop/short paper, 4–6pp IEEE/ACM double-column, per the dossier's standard
structure `[Dossier §41]`; expand to the full 15–25pp journal structure only if pursuing a Tier-3
venue (e.g. MDPI *Algorithms*) as a stretch goal (T9.2-adjacent, not in the base build order).

| Paper section | Length | Content | Pulls from |
|---|---|---|---|
| Title & Abstract | 150–200 words | Problem (DPI automaton state explosion + ReDoS + SQLi structural blindness), formal construct (three-tier AC+DFA+DPDA composition), primary contribution claim, one headline empirical result | §1 CONTRIBUTION STATEMENT |
| 1. Introduction | ~1 page | Why naive/single-automaton DPI fails (state explosion, ReDoS); the architectural thesis (never merge regex into AC); the novelty gap this closes | §1, §3.1 intro paragraph, §2.3/§2.5 (state-explosion and succinctness framing) |
| 2. Formal Model & Pipeline Architecture | ~1.5 pages | DFA/NFA/AC/PDA definitions (condensed — full detail stays in this document, not the paper); component diagram; the §2.6 grammar summarized (full production list as an appendix or supplementary artifact, not in-line at 4–6pp) | §2 (condensed), §3 |
| 3. Implementation & Optimization | ~1 page | Data structures (bitmapped/class-reduced trie, per-rule DFA bank, LALR table), memory layout choices with the §4.4 table as evidence, cross-packet state persistence | §4, §5 (module summaries, not full pseudocode) |
| 4. Empirical Evaluation | ~1.5 pages | Throughput/tail-latency vs `k` (F1/F2), prefilter selectivity (T1), fragmentation robustness (F3), ReDoS resilience (F4), memory footprint (T2), baseline comparison (T3), SQLi FP/GB (T4); honest Python-vs-production framing stated explicitly, not left implicit | §6 |
| 5. Threats to Validity (short paper: folded into Discussion; full paper: standalone) | 0.25–0.5 page | Condensed version of §7's strongest 3–4 entries — the Bounded-Length Objection rebuttal, the strawman-baseline rebuttal, and the honest-throughput framing are the three most likely to be asked live and should not be omitted for space | §7 |
| 6. Related Work & Conclusion | ~0.5 page | Positions against: AC/PFAC/Bit-Split-AC optimization literature; Snort/Suricata/Hyperscan fast-pattern prefiltering; Namjoshi & Narlikar's deterministic back-reference work; libinjection/ModSecurity/AMNESIA-CANDID-SQLCheck SQLi detection; the six DFA-state-explosion mitigations (Hybrid-FA/XFA/D²FA/Counting Automata/lazy-DFA/Hyperscan-decomposition) — explicitly acknowledged as complementary, not competing (§7.4) | §3 THE NOVELTY GAP content folded in from the dossier, §7.4 |
| Acknowledgments | — | CRediT-style contribution statement (§8's five owners); AI-assistance disclosure (T8.2) | §8, `[Dossier §43, §44]` |
| Bibliography | — | **Must not include** the circular self-citation (RDP-3) or the garbled Sapats citation (RDP-6); must include the corrected White/Fitzsimmons/Matthews SPIE 2013 reference and every `[Dossier→...]`-tagged source actually used | RDP-3, RDP-6 |

**Venue targeting (carry the dossier's own hedge forward — do not commit to a date without
re-checking, per RDP-8/T8.3):** Tier-1 workshop candidates are EuroSec (co-located EuroSys,
~25–30% acceptance, 6pp) and ANCS (poster/extended-abstract track, ~30% acceptance); both had
`[Unconfirmed]` submission windows in the dossier's own venue table `[Dossier §39]` and must be
re-verified against the live CFP before any date is written into a plan. A Tier-2 ACM Student
Research Competition (co-located CCS/SIGCOMM/PLDI/ASPLOS) is a lower-risk fallback given the
undergraduate scope. Before submitting anywhere, cross-check the venue against the predatory-venue
red flags in `[Dossier §40]` (guaranteed sub-72-hour review, fake impact-factor branding, absence
from DBLP/ACM-DL/IEEE-Xplore/Scopus) — this is a real risk category for a first-time student
submission, not boilerplate advice.

---

*End of IMPLEMENTATION.md.*
