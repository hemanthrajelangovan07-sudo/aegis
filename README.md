# AEGIS-AC — Reference Implementation

A working implementation of the engine specified in `IMPLEMENTATION.md`. All five modules are
implemented, wired together end to end, covered by a passing test suite (**78/78 tests**), and
evaluated with real measurements against real data — not just unit tests.

```
python3 -m pytest tests/ -v      # 78 tests, all passing
python3 demo.py                  # narrated walkthrough of every worked example
./run_benchmarks.sh              # full suite + regenerates REPORT.md (real measurements)
```

## What's implemented and tested

| Module | Owner (per spec) | Files | Tests |
|---|---|---|---|
| 1 — AC Prefilter Engine | Core Automaton Lead | `ac_prefilter/` | 13 |
| 2 — Rule Loader & Regex Compiler | Compiler Lead | `rule_compiler/` | 20 |
| 3 — SQLi Lexer & DPDA Recognizer | Scanner/Demo Lead | `sqli_engine/` | 13 |
| 4 — Flow State Manager, Alert Emitter, Orchestrator, HTTP extraction | Integration Lead | `pipeline/` | 14 |
| 5 — Instrumentation, Generator, Harness, Baselines, Report, Experiments | Benchmarking Lead | `bench/` | 18 |

Numbers the spec marks `[Verified in this doc]` are asserted exactly in the test suite — the
classic `{he,she,his,hers}` trie (10 states), the 65-byte backdoor/keylogger payload (positions
10–17 / 23–31, exactly 65 transitions), the synthetic-generator table (k=100..10000 →
1079..98822 states), the `a.{n}b` state-explosion family, the full **1,689-state canonical LR(1)
table with 0 conflicts** and **179-state LALR(1) core with 0 conflicts**, generated live every run.

## Real evaluation, not just unit tests

Run `./run_benchmarks.sh` (or `python3 -m bench.report REPORT.md`) to regenerate `REPORT.md`,
which contains actual measured results from this environment:

- **A real 4-system comparison** (AEGIS-AC, naive multi-pattern, `pyahocorasick`, and **real
  Hyperscan** — `libhyperscan5`/`libhyperscan-dev` installed via apt, genuinely compiled and
  scanning, not mocked) across k=100/1000/10000. Naive search degrades badly with k (50μs →
  5.8ms); AEGIS-AC's pure-Python scan stays roughly flat across k (~155-184μs) despite being
  slower in absolute terms than the two C-backed engines — the actual k-independence claim,
  measured, not just asserted.
- **A real adversarial ReDoS demonstration** (E4): backtracking `re` on `(a+)+b` grows
  0.1ms → 1.3ms → 10.4ms → 41.7ms → 166.9ms as the adversarial input grows n=10→22, while
  AEGIS-AC's compile-time rejection stays flat at 13–32 **microseconds** regardless of n (it
  never looks at the input at all — Section 5 Module 2's `REJECTED_UNBOUNDED` path).
- **A real SQLi decision-predicate evaluation against libinjection's published test corpus**
  (Nick Galbreath, BSD-3-Clause, bundled under `third_party/libinjection-data/` with its
  original LICENSE) — 85,791 real attack strings and 421 real hard-benign strings. Honest
  three-outcome result (most real payloads use SQL dialect features outside this project's
  intentionally-scoped DML grammar): **11.0% strict recall** (parsed-and-caught only), **99.9%
  lenient recall** (treating "failed to parse as valid SQL" as a defensible fail-closed catch),
  **4.04% false-positive rate** on the hard-benign set, with a genuine, understandable failure
  mode: natural-language phrases containing "AND"/"OR" (`"40 AND FAB"`, `"LOCK AND KEY"`) trip
  the boolean-injection detector — a known, well-documented failure class for keyword-based
  heuristics, now actually measured on this engine rather than assumed. See
  `bench/sqli_corpus_eval.py`'s docstring for the full methodology, including a real bug this
  evaluation caught and fixed (payloads were being parsed as standalone top-level statements
  instead of embedded in a representative query context, which is how they're actually used).
- **E2 (prefilter selectivity)**: escalation rate collapses from 83.5% (2-byte anchor) → 5.85%
  (3-byte) → 0.09% (4-byte) → ~0.01% (5+ bytes) at k=10000 — a clean, measured demonstration of
  why short fast-pattern anchors destroy selectivity.
- **E3 (fragmentation)**: recall under fragmentation exactly equals full-reassembly recall at
  every tested fragmentation rate (0%, 10%, 30%, 50%), across 100 random split points each —
  not just the one hand-picked split the flagship unit test checks.
- **E5 (storage layout)**: class-reduced tables use ~40-55% less memory than dense `Σ=256`
  tables but cost ~35-40% more wall-clock per byte in this pure-Python reference implementation
  (the extra indirection), a real, measured tradeoff.

## What's genuinely NOT wired up, and why

- **Real Snort Community Rules, ET Open, and CIC-IDS2017** — `snort.org`, `rules.
  emergingthreats.net`, and `unb.ca` are not reachable from this build's sandboxed network
  allowlist (confirmed: `github.com`, `pypi.org`, and Ubuntu's own apt mirrors ARE reachable,
  which is what made real Hyperscan and the real libinjection corpus possible). Exact download
  commands are in `bench/harness.py`'s `DATASET_DOWNLOAD_COMMANDS` and `IMPLEMENTATION.md`
  Section 6.1 — run them on a machine with normal internet access, then point the harness at the
  local files.
- **Suricata's own `mpm-algo=hs` vs `mpm-algo=ac` production-pipeline comparison** — this needs a
  full Suricata source build (`--enable-hyperscan`), a materially larger dependency chain than
  what a direct Hyperscan-the-library comparison (which IS wired up) needs.
- **`byte_test`/`byte_jump`/`flowbits`/`http_*` sticky-buffer semantics** — the rule loader now
  parses these (so a real rule file with these keywords doesn't crash the loader — see
  `_PASSTHROUGH_KEYWORDS` in `rule_compiler/loader.py`) but doesn't act on them for detection.
- **Full ANSI SQL grammar coverage** — deliberately out of scope per the spec itself ("a
  representative, defensible subset... not full ANSI SQL," Section 2.6); the real corpus
  evaluation above now *quantifies* exactly how much of real-world attack traffic that leaves
  uncovered (89% of the libinjection corpus fails to parse under this grammar at all).

## Real bugs found and fixed while hardening this build

Documented honestly rather than silently patched, since several are genuinely instructive:

1. A Python closure-scoping bug in Thompson construction (`edges += [...]` inside a nested
   function silently made `edges` local, raising `UnboundLocalError`).
2. An off-by-one between the augmented and unaugmented grammar production lists that silently
   broke the SQLi decision predicate (structural-production indices were computed against the
   wrong list).
3. An anchored-verifier window bug in the orchestrator — per-rule regex verifiers were being
   scanned from payload byte 0 instead of from the fast-pattern's actual match position.
4. A lexer flush gap — a token landing exactly at a packet boundary could be held back forever
   waiting for a next packet that never comes at end-of-flow.
5. A `nocase` case-folding bug — character classes (`[a-z]`) were never folded at all, only bare
   letters; fixed by moving folding from a fragile source-text rewrite to the parsed AST.
6. A `re` anchor gotcha in the (new) HTTP extraction layer — `^` in a compiled pattern only
   matches at true string position 0, never at the `pos` argument passed to `.match()`, which
   silently broke header parsing past the request line.
7. A methodology bug in the SQLi corpus evaluator itself — first pass fed raw attack fragments
   to the parser as standalone top-level statements (which they are not; they're designed to be
   appended to an existing query), producing a near-meaningless ~0% recall until fixed to embed
   each payload in a representative query context.
8. Hyperscan compilation failures on synthetic signatures containing regex metacharacters —
   fixed by using Hyperscan's `literal=True` pure-literal compiler mode instead of its default
   regex mode.

## Build-order status (Section 8)

**T0–T6 done.** T6.2 (dataset acquisition) done for everything reachable (Hyperscan, GitHub-hosted
SQLi corpora); real Snort/ET/CIC-IDS2017 remain genuinely out of reach here, with exact commands
provided. **T7 (evaluation)** now has real runs for everything not gated on those three datasets —
E1-equivalent baseline comparison, E2–E5 all implemented and run for real, `bench/report.py`
(previously a named-but-missing file) generates `REPORT.md` from live data. **T8 (paper draft)**
and **T9 (viva rehearsal)** remain follow-on work.

## Known simplifications (flagged honestly)

- `rule_compiler/hopcroft.py`'s minimizer is correct but not the asymptotically optimal
  `O(|Σ|·n log n)` worklist-based algorithm the citation refers to.
- `rule_compiler/backref.py` implements the `L=1` deterministic back-reference case via a
  two-phase scan (O(n²)-ish) rather than the single-pass extended-NFA-with-registers
  construction the dossier's cited paper describes, and only recognizes one regex shape
  (`prefix(group)middle\1suffix`).
- Positional-modifier checking (`offset`/`depth`/`distance`/`within`) is implemented and tested
  against Section 4.1's worked example, not cross-validated against every Snort/Suricata edge
  case.
- Alert severity is a static default per call site, not computed from a rolling FP/GB volume
  counter despite Section 3 Component 8's description.
- `tests/test_backref_liveness_bound` (checking the real 111/120 Namjoshi & Narlikar census) was
  never built — that needs either the original published dataset or doing the census work
  against a real ruleset, both blocked by the same network restriction as the datasets above.

## Layout

```
ac_prefilter/   Module 1
rule_compiler/  Module 2
sqli_engine/    Module 3
pipeline/       Module 4 (+ http_extraction.py: raw HTTP -> TaintedSlot, real, tested)
bench/          Module 5 (+ report.py, experiments.py, sqli_corpus_eval.py -- all real)
third_party/    libinjection's real test corpus, bundled with its BSD-3-Clause LICENSE
tests/          one file per module/concern, 78 tests total
demo.py         narrated walkthrough of the spec's worked examples (not a test)
run_benchmarks.sh   one-command reproduction: full test suite + REPORT.md regeneration
Dockerfile      reproduction environment (written against this build's verified deps;
                docker CLI itself isn't available in this sandbox, so not build-tested here)
REPORT.md       generated output from the last real run -- see above for highlights
IMPLEMENTATION.md   the spec this was built from
```
