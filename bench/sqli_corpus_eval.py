"""
Evaluates AEGIS-AC's SQLi decision predicate (sqli_engine, Module 3) against a REAL, published,
labeled corpus: libinjection's own test data (Nick Galbreath, BSD-3-Clause), bundled under
third_party/libinjection-data/ with its original LICENSE file. This directly answers the
dossier's own reviewer-criticism checklist item "unmeasured false-positive rates on syntax
features present in benign traffic" (IMPLEMENTATION.md Section 7.2/7.3) with a real number
instead of a constructed example.

Corpus structure (as shipped by libinjection):
  - sqli-*.txt   : one known-SQLi-attack string per non-comment, non-blank line
  - false_positives.txt : known-hard BENIGN strings (curated specifically because they trip up
    naive detectors) -- this is the file that matters most for the "unmeasured FP rate" question

IMPORTANT SCOPE CAVEAT, stated up front rather than glossed over in the results: AEGIS-AC's
grammar (Section 2.6) is an intentionally small, defensible DML subset "not full ANSI SQL"
(Section 2.6's own text). Many real-world attack strings use MySQL-specific functions, inline
comments, or syntax this grammar was never meant to cover. Every corpus line therefore falls into
one of THREE outcomes, not two:
  - PARSED_ATTACK_DETECTED / PARSED_NO_ATTACK : the grammar parsed it and the decision predicate
    fired or didn't
  - UNPARSEABLE : the lexer or parser rejected the line outright (LexError / SyntaxOrLexError)

For a MALICIOUS-labeled line, both PARSED_ATTACK_DETECTED and UNPARSEABLE are defensible
"caught" outcomes from a pure security standpoint (a security-minded system should treat "value
slot failed to parse as valid SQL at all" as suspicious, same posture as the no-anchor/ReDoS
fallback paths elsewhere in this engine) -- but this module reports BOTH a strict metric (only
PARSED_ATTACK_DETECTED counts as a catch) and a lenient one (UNPARSEABLE also counts), rather than
picking whichever number looks better, so the reader can judge for themselves.

For a BENIGN-labeled line (false_positives.txt), UNPARSEABLE is a genuine harm if the pipeline's
policy is "block on parse failure" -- so this module always reports the FP rate against a
strict "must actually reach the parser and NOT be flagged as attack" bar.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from sqli_engine.lexer import LexError, lex
from sqli_engine.parser import SqliParser, SyntaxOrLexError


@dataclass
class CorpusEvalResult:
    n_malicious: int = 0
    n_benign: int = 0
    malicious_parsed_detected: int = 0
    malicious_parsed_not_detected: int = 0
    malicious_unparseable: int = 0
    benign_parsed_not_detected: int = 0
    benign_parsed_false_positive: int = 0
    benign_unparseable: int = 0
    elapsed_ns: int = 0
    fp_examples: list[str] = field(default_factory=list)
    unparseable_examples: list[str] = field(default_factory=list)

    @property
    def recall_strict(self) -> float:
        """Only counts a parsed-and-flagged attack as a catch."""
        return self.malicious_parsed_detected / self.n_malicious if self.n_malicious else 0.0

    @property
    def recall_lenient(self) -> float:
        """Also counts 'failed to parse as valid SQL at all' as a caught attack (defensible
        security posture, see module docstring), not just a semantically-detected one."""
        caught = self.malicious_parsed_detected + self.malicious_unparseable
        return caught / self.n_malicious if self.n_malicious else 0.0

    @property
    def false_positive_rate(self) -> float:
        """Strict: a benign string is a false positive if it parses AND the predicate fires.
        (Unparseable benign strings are reported separately -- see benign_unparseable -- since
        whether that counts as a 'false positive' depends entirely on deployment policy, which
        this module does not decide on the evaluator's behalf.)"""
        return (
            self.benign_parsed_false_positive / self.n_benign
            if self.n_benign
            else 0.0
        )

    def report(self) -> str:
        lines = [
            f"Malicious corpus:  n={self.n_malicious}",
            f"  parsed + detected (strict catch) : {self.malicious_parsed_detected}",
            f"  parsed + NOT detected (miss)      : {self.malicious_parsed_not_detected}",
            f"  unparseable (grammar scope limit) : {self.malicious_unparseable}",
            f"  recall (strict, parsed-only)      : {self.recall_strict:.1%}",
            f"  recall (lenient, unparseable=caught): {self.recall_lenient:.1%}",
            "",
            f"Benign corpus (false_positives.txt): n={self.n_benign}",
            f"  parsed + correctly NOT flagged    : {self.benign_parsed_not_detected}",
            f"  parsed + FALSE POSITIVE           : {self.benign_parsed_false_positive}",
            f"  unparseable (policy-dependent)     : {self.benign_unparseable}",
            f"  false positive rate (strict)      : {self.false_positive_rate:.2%}",
            "",
            f"elapsed: {self.elapsed_ns/1e9:.2f}s",
        ]
        if self.fp_examples:
            lines.append("\nSample false positives (benign strings incorrectly flagged):")
            for s in self.fp_examples[:10]:
                lines.append(f"  {s!r}")
        return "\n".join(lines)


def _load_lines(path: Path) -> list[str]:
    lines = []
    for raw in path.read_text(errors="replace").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    return lines


def _classify(parser: SqliParser, text: str) -> str:
    """Returns 'DETECTED', 'NOT_DETECTED', or 'UNPARSEABLE' for one corpus line.

    METHODOLOGY NOTE (important, found by running this against the real corpus -- not a
    theoretical concern): libinjection's test corpus contains ATTACK FRAGMENTS meant to be
    appended after an existing query value (e.g. "234+(1/ASCII(...))" is meant to follow
    "id="), not complete standalone SQL statements -- libinjection itself works by token-
    fingerprinting a fragment directly, with no notion of "statement." AEGIS-AC's grammar
    (Section 2.6) has no top-level production for a bare Expr; a Script requires a full Stmt.
    Parsing each corpus line AS A STANDALONE SCRIPT is therefore not a fair test of this
    engine's actual design, which is built around Section 2.5/3's static-template + tainted-
    value-slot model (exactly what Pipeline.process_packet expects via TaintedSlot).

    So: embed the payload into a small set of representative static contexts matching real
    parameter positions (numeric WHERE-clause value, quoted-string WHERE-clause value), with the
    embedding prefix/suffix marked NON-tainted and the payload itself marked tainted -- this
    mirrors real usage exactly. A payload is called DETECTED if the decision predicate fires in
    ANY applicable context; UNPARSEABLE only if it fails to parse in every context tried."""
    numeric_ctx = ("SELECT * FROM t WHERE id = ", "")
    string_ctx = ("SELECT * FROM t WHERE name = '", "'")

    contexts = [numeric_ctx]
    if "'" in text:
        contexts.append(string_ctx)

    any_unparseable = False
    any_parsed = False
    for prefix, suffix in contexts:
        payload = (prefix + text + suffix).encode("utf-8", errors="replace")
        mask = [False] * len(prefix) + [True] * len(text.encode("utf-8", errors="replace")) + [False] * len(suffix)
        try:
            tokens = lex(payload, taint_mask=mask)
        except LexError:
            any_unparseable = True
            continue
        try:
            verdict = parser.parse(tokens, stop_on_error=True)
        except SyntaxOrLexError:
            any_unparseable = True
            continue
        any_parsed = True
        if verdict.is_attack:
            return "DETECTED"

    if any_parsed:
        return "NOT_DETECTED"
    return "UNPARSEABLE" if any_unparseable else "NOT_DETECTED"


def evaluate_corpus(
    corpus_dir: Path, parser: SqliParser | None = None, max_per_file: int | None = None
) -> CorpusEvalResult:
    parser = parser or SqliParser.build()
    result = CorpusEvalResult()

    t0 = time.perf_counter_ns()

    benign_path = corpus_dir / "false_positives.txt"
    if benign_path.exists():
        for line in _load_lines(benign_path)[:max_per_file]:
            outcome = _classify(parser, line)
            result.n_benign += 1
            if outcome == "DETECTED":
                result.benign_parsed_false_positive += 1
                if len(result.fp_examples) < 50:
                    result.fp_examples.append(line)
            elif outcome == "NOT_DETECTED":
                result.benign_parsed_not_detected += 1
            else:
                result.benign_unparseable += 1
                if len(result.unparseable_examples) < 50:
                    result.unparseable_examples.append(line)

    for path in sorted(corpus_dir.glob("sqli-*.txt")):
        for line in _load_lines(path)[:max_per_file]:
            outcome = _classify(parser, line)
            result.n_malicious += 1
            if outcome == "DETECTED":
                result.malicious_parsed_detected += 1
            elif outcome == "NOT_DETECTED":
                result.malicious_parsed_not_detected += 1
            else:
                result.malicious_unparseable += 1

    result.elapsed_ns = time.perf_counter_ns() - t0
    return result


if __name__ == "__main__":
    import sys

    corpus_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("third_party/libinjection-data")
    if not corpus_dir.exists():
        print(f"corpus dir not found: {corpus_dir}")
        raise SystemExit(1)
    result = evaluate_corpus(corpus_dir)
    print(result.report())
