"""
TRIE-BUILD pseudocode from IMPLEMENTATION.md §5 Module 1.

    TRIE-BUILD(patterns):
        root = new state 0
        for (rule_id, p) in patterns:
            s = root
            for byte in p:
                if goto[s][byte] undefined: goto[s][byte] = new state
                s = goto[s][byte]
            out[s] = out[s] U {rule_id}
        return trie

O(sum|p_i|) time and space -- one trie edge created per pattern byte at most. [Dossier Section 1]
"""
from __future__ import annotations

from .types import ACTrie


def build_trie(patterns: list[tuple[int, bytes]]) -> ACTrie:
    """patterns: list of (rule_id, literal_bytes). Multiple rule_ids may share one literal
    (the "duplicate patterns with different rule_ids" edge case, §5 Module 1) -- both accumulate
    in out[] at the shared accepting state."""
    trie = ACTrie()
    for rule_id, pattern in patterns:
        state = 0
        for byte in pattern:
            nxt = trie.goto[state].get(byte)
            if nxt is None:
                trie.goto.append({})
                trie.out.append(frozenset())
                trie.fail.append(0)
                trie.label.append(trie.label[state] + bytes([byte]))
                nxt = len(trie.goto) - 1
                trie.goto[state][byte] = nxt
            state = nxt
        trie.out[state] = trie.out[state] | {rule_id}
    return trie


def build_trie_literals(patterns: list[bytes | str]) -> ACTrie:
    """Convenience wrapper for the common case where the caller doesn't care about rule_ids
    (e.g. the classic textbook {he,she,his,hers} example) -- assigns rule_id = index in `patterns`.
    Accepts str for readability in tests/docs; encodes as UTF-8 (patterns in this engine are
    always treated as raw bytes downstream, per Sigma=256 in Section 2.1 -- str input here is a
    convenience, not a claim that the engine is text-aware)."""
    encoded = [p.encode() if isinstance(p, str) else p for p in patterns]
    return build_trie(list(enumerate(encoded)))
