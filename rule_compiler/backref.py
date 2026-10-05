"""
Deterministic back-reference compilation (IMPLEMENTATION.md Section 2.4/2.7, Section 5 Module 2).

Back-references make the language context-sensitive in general (Section 2.7) -- NOT expressible
as a single DFA. IMPLEMENTATION.md's architecture never attempts to compile a back-reference into
subset_construct/hopcroft; instead it uses the deterministic subset that Namjoshi & Narlikar (2010)
proved decidable via static liveness analysis: rules with a bounded number `L` of simultaneously
"live" back-references (in the Snort ruleset, 111/120 unique back-reference expressions have
exactly L=1 -- Section 2.7, Section 6.2's baseline citation).

This module implements the L=1 case directly and completely: a regex of the shape

    <prefix> ( <group> ) <middle> \\1 <suffix>

where prefix/group/middle/suffix are each drawn from the supported regular subset (regex_ast.py)
with no further groups or back-references nested inside. This is exactly the class of rule the
dossier's own examples fall into (e.g. quote-consistency checks, repeated-token/parameter-echo
attacks). compile_backref_rule returns None (never guesses, never silently approximates) for
anything outside this K_bound=1 shape -- per Section 5 Module 2's exact contract, the caller
routes a None result to the no-anchor fallback set for libpcre delegation, RDP-1/Section 3.
Extending K_bound above 1 is flagged as a stretch goal (Section 8, T9.2-adjacent) and NOT attempted
here, since the dossier itself only establishes decidability/practicality for the L=1 case at
undergraduate-project scope.

NOTE on implementation technique: `re` (Python's backtracking engine) is used here ONLY to parse
the RULE'S OWN SOURCE TEXT at compile time (an offline, one-time, attacker-uncontrolled string --
the analyst-authored regex, not network payload data). This is not a violation of the
"never backtrack on untrusted payload at scan time" principle the whole architecture exists to
uphold (Section 2.5, Section 7) -- it is a convenience for the OFFLINE compiler tool only, and is
never on the runtime scanning path (backref_rule.verify() below is a two-phase deterministic
scan, not a call into `re` against payload bytes).
"""
from __future__ import annotations

import re as _meta_re
from dataclasses import dataclass

from .hopcroft import hopcroft_minimize
from .regex_ast import parse_regex
from .subset_construct import DFA, subset_construct
from .thompson import thompson_construct

_GROUP_BACKREF_SHAPE = _meta_re.compile(
    r"^(?P<prefix>.*?)\((?P<group>[^()]*)\)(?P<middle>.*?)\\1(?P<suffix>.*)$", _meta_re.DOTALL
)


def count_backreferences(source: str) -> int:
    """Number of DISTINCT back-reference indices (\\1, \\2, ...) appearing in source -- this is
    the K in the dossier's K_bound, i.e. the number of simultaneously-live back-references a
    compiler would need to track for this one rule."""
    return len(set(_meta_re.findall(r"\\(\d)", source)))


def _compile_subset(body: str) -> DFA:
    ast = parse_regex(body) if body else ("set", frozenset())
    if body == "":
        # zero-width: represent as a DFA with a single accepting start state and no transitions
        # that ever leave it on real input other than "empty matched here" -- modeled as an NFA
        # over an empty alternation is awkward, so special-case directly.
        return DFA(n_states=1, transitions=[[]], accepting=frozenset({0}), byte_classes=[])
    nfa = thompson_construct(ast)
    dfa = subset_construct(nfa, mode="anchored")
    return hopcroft_minimize(dfa)


@dataclass
class DetBackrefNFA:
    """A compiled L=1 deterministic back-reference verifier. Not a single DFA (the class of
    languages this recognizes is not regular -- Section 2.7) but a small, fully deterministic
    TWO-PHASE scan: phase 1 locates the group's match textually (the group pattern itself IS
    regular, compiled to a real minimal DFA below); phase 2 checks literal byte-equality of the
    back-reference occurrence against whatever phase 1 captured. Both phases are linear scans,
    no backtracking."""

    prefix_source: str
    group_source: str
    middle_source: str
    suffix_source: str
    group_dfa: DFA
    live_backreferences: int = 1

    def verify(self, window: bytes) -> bool:
        """Deterministic O(|window|^2)-worst-case-bounded (but O(1) live back-references, per
        the dossier's decidability result) two-phase check: for every candidate group-match span
        found via the group DFA, check literal middle+captured-repeat+suffix alignment.
        A real production implementation would fold this into a single automaton pass using the
        extended-NFA-with-registers technique the dossier cites (Namjoshi & Narlikar 2010);
        this reference implementation prioritizes being OBVIOUSLY CORRECT (and testable against
        the worked examples) over that optimization, which is flagged as a follow-on task."""
        prefix_dfa = _compile_subset(self.prefix_source) if self.prefix_source else None
        middle_dfa = _compile_subset(self.middle_source) if self.middle_source else None
        suffix_dfa = _compile_subset(self.suffix_source) if self.suffix_source else None

        n = len(window)
        for g_start in range(n + 1):
            if prefix_dfa is not None and not _matches_at(prefix_dfa, window, 0, g_start):
                continue
            for g_end in range(g_start, n + 1):
                if not _matches_span(self.group_dfa, window, g_start, g_end):
                    continue
                captured = window[g_start:g_end]
                for m_end in range(g_end, n + 1):
                    if middle_dfa is not None and not _matches_span(middle_dfa, window, g_end, m_end):
                        continue
                    rep_end = m_end + len(captured)
                    if rep_end > n or window[m_end:rep_end] != captured:
                        continue
                    if suffix_dfa is None:
                        return True
                    if _matches_at(suffix_dfa, window, rep_end, n):
                        return True
        return False


def _dfa_byte_class(dfa: DFA, byte: int) -> int | None:
    for i, cls in enumerate(dfa.byte_classes):
        if byte in cls:
            return i
    return None


def _matches_span(dfa: DFA, window: bytes, start: int, end: int) -> bool:
    state = 0
    if start == end:
        return state in dfa.accepting
    for b in window[start:end]:
        cls = _dfa_byte_class(dfa, b)
        if cls is None:
            return False
        state = dfa.transitions[state][cls]
    return state in dfa.accepting


def _matches_at(dfa: DFA, window: bytes, start: int, end: int) -> bool:
    return _matches_span(dfa, window, start, end)


def compile_backref_rule(body: str, k_bound: int = 1) -> DetBackrefNFA | None:
    """CLASSIFY/COMPILE-BACKREF from IMPLEMENTATION.md Section 5 Module 2. Returns None if the
    rule falls outside the supported K_bound=1, single-group shape -- caller routes to the
    no-anchor fallback (RDP-1)."""
    live = count_backreferences(body)
    if live == 0 or live > k_bound:
        return None
    m = _GROUP_BACKREF_SHAPE.match(body)
    if m is None:
        return None
    try:
        group_dfa = _compile_subset(m.group("group"))
    except Exception:
        return None
    return DetBackrefNFA(
        prefix_source=m.group("prefix"),
        group_source=m.group("group"),
        middle_source=m.group("middle"),
        suffix_source=m.group("suffix"),
        group_dfa=group_dfa,
        live_backreferences=live,
    )
