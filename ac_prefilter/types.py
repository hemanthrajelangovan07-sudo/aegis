"""
Core data types for the AC Prefilter Engine (Module 1, IMPLEMENTATION.md §5 Module 1).

These mirror the formal 5-tuple / goto-failure-output model of §2.4:
    ACTrie      -- the goto function g(s,a) plus the output function out(s), pre-failure-links
    (fail links are stored as a parallel array, filled in place by failure.build_failure_links)
    NextMoveDFA -- the precomputed total transition function delta(s,a) of §2.4b / §2.1
    Match       -- one reported occurrence, (end_position, rule_ids), per §2.4's out(s) semantics
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, NamedTuple


@dataclass
class ACTrie:
    """goto[state][byte] -> state.  out[state] -> frozenset of rule_ids accepted at that state.
    fail[state] -> state; filled in by failure.build_failure_links (root's own fail is itself, 0).
    label[state] -> the bytes labeling this trie node, kept only for debugging / whiteboard dumps.
    """

    goto: list[dict[int, int]] = field(default_factory=lambda: [dict()])
    out: list[frozenset[int]] = field(default_factory=lambda: [frozenset()])
    fail: list[int] = field(default_factory=lambda: [0])
    label: list[bytes] = field(default_factory=lambda: [b""])

    @property
    def n_states(self) -> int:
        return len(self.goto)


@dataclass
class NextMoveDFA:
    """Precomputed Next-Move DFA (Aho & Corasick 1975, Algorithm 4). delta is a TOTAL function:
    every (state, byte) pair has an entry, so scanning is exactly one dict/array lookup per byte,
    with no fallback loop -- see IMPLEMENTATION.md §2.4b.

    Two storage layouts are supported (§4.4's dense-vs-class-reduced comparison):
      - "dense":         delta[state] is a 256-entry list, one slot per raw byte value.
      - "class_reduced":  delta[state] is a list indexed by byte-CLASS id; class_of[byte] maps a
                           raw byte to its class. Bytes that never distinguish any pattern collapse
                           into the same class, shrinking the table at the cost of one extra
                           indirection per lookup.
    """

    layout: str  # "dense" | "class_reduced"
    delta: list[list[int]]
    out: list[frozenset[int]]
    class_of: list[int] | None = None  # only set when layout == "class_reduced"

    @property
    def n_states(self) -> int:
        return len(self.delta)

    def step(self, state: int, byte: int) -> int:
        if self.layout == "dense":
            return self.delta[state][byte]
        assert self.class_of is not None
        return self.delta[state][self.class_of[byte]]


class Match(NamedTuple):
    end_position: int
    rule_ids: frozenset[int]


def iter_matches(
    dfa: NextMoveDFA, payload: bytes, start_state: int = 0
) -> Iterator[Match]:
    """Convenience re-export point; the real implementation lives in scan.scan(), this alias
    exists only so callers can `from ac_prefilter.types import iter_matches` without caring which
    submodule owns the scan loop. See scan.py."""
    from .scan import scan

    yield from scan(dfa, payload, start_state)
