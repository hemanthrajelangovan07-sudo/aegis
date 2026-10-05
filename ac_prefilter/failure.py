"""
FAILURE-BUILD pseudocode from IMPLEMENTATION.md §5 Module 1 (Aho & Corasick 1975, Algorithms 2/3):

    FAILURE-BUILD(trie):
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
                out[s] = out[s] U out[fail[s]]              # inheritance -- [Dossier Section 1]

O(sum|p_i|) total work across all states (each state's failure-link chase is amortized bounded by
the trie's depth, standard Aho-Corasick argument). [Dossier Section 1]
"""
from __future__ import annotations

from collections import deque

from .types import ACTrie


def build_failure_links(trie: ACTrie) -> None:
    """In-place: fills trie.fail and extends trie.out via out[s] |= out[fail[s]]."""
    root = 0
    queue: deque[int] = deque()

    for byte, s in trie.goto[root].items():
        trie.fail[s] = root
        queue.append(s)

    while queue:
        r = queue.popleft()
        for byte, s in trie.goto[r].items():
            queue.append(s)
            t = trie.fail[r]
            while t != root and byte not in trie.goto[t]:
                t = trie.fail[t]
            nxt = trie.goto[t].get(byte, root)
            # a state's failure link must never point to itself (only relevant at depth-1 states
            # reached via the root's own default loop) -- guard explicitly, matching ac_check.py's
            # verified construction from the spec's derivation.
            trie.fail[s] = nxt if nxt != s else root
            trie.out[s] = trie.out[s] | trie.out[trie.fail[s]]
