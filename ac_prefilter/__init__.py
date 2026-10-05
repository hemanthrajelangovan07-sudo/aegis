"""AC Prefilter Engine (IMPLEMENTATION.md Module 1, Owner: Core Automaton Lead).

Public API:
    build_trie(patterns) -> ACTrie
    build_failure_links(trie) -> None            (in-place)
    build_nextmove(trie, layout) -> NextMoveDFA
    scan(dfa, payload, start_state) -> Iterator[Match]
"""
from .types import ACTrie, NextMoveDFA, Match
from .trie import build_trie, build_trie_literals
from .failure import build_failure_links
from .nextmove import build_nextmove
from .scan import scan, scan_final_state

__all__ = [
    "ACTrie",
    "NextMoveDFA",
    "Match",
    "build_trie",
    "build_trie_literals",
    "build_failure_links",
    "build_nextmove",
    "scan",
    "scan_final_state",
]
