"""
SCAN pseudocode from IMPLEMENTATION.md Section 5 Module 1 / Section 2.4:

    SCAN(delta, out, payload, s = start_state):
        for i, byte in enumerate(payload):
            s = delta[s][byte]                     # exactly 1 transition/byte -- [Dossier Sec 1]
            if out[s] not empty: yield Match(i, out[s])
        return s                                    # returned for flow-state persistence

Exactly len(payload) transitions, independent of the number of patterns k
(Refuted Claim #4 -- see IMPLEMENTATION.md Section 2.4, Section 5 Module 1's
test_scan_independent_of_k). accepts start_state so Module 4's flow control block can resume
scanning across a TCP-flow's packet boundary without re-scanning from the root.
"""
from __future__ import annotations

from typing import Iterator

from .types import Match, NextMoveDFA


def scan(dfa: NextMoveDFA, payload: bytes, start_state: int = 0) -> Iterator[Match]:
    state = start_state
    for i, byte in enumerate(payload):
        state = dfa.step(state, byte)
        hits = dfa.out[state]
        if hits:
            yield Match(i, hits)


def scan_final_state(dfa: NextMoveDFA, payload: bytes, start_state: int = 0) -> tuple[int, list[Match]]:
    """Non-generator convenience form: returns (final_state, all_matches). Used by Module 4's
    flow-state persistence, where both the match list AND the resumable state are needed."""
    state = start_state
    matches: list[Match] = []
    for i, byte in enumerate(payload):
        state = dfa.step(state, byte)
        hits = dfa.out[state]
        if hits:
            matches.append(Match(i, hits))
    return state, matches
