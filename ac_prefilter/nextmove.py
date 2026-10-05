"""
NEXTMOVE-BUILD pseudocode from IMPLEMENTATION.md Section 5 Module 1 / Section 2.4b
(Aho & Corasick 1975, Algorithm 4):

    NEXTMOVE-BUILD(trie, Sigma):
        for byte in Sigma: delta[root][byte] = goto[root][byte] if defined else root
        queue = children of root
        while queue not empty:
            r = queue.pop()
            for byte in Sigma:
                if goto[r][byte] defined: delta[r][byte] = goto[r][byte]; queue.push(goto[r][byte])
                else: delta[r][byte] = delta[fail[r]][byte]
        return delta

O(|S|*|Sigma|) time regardless of storage layout -- layout only changes the storage constant
(dense Sigma=256 vs class-reduced), per Section 4.4's table. [Dossier Section 1, Section 12]

Byte-class reduction: two bytes are in the same class iff no trie edge, at any state,
distinguishes them (i.e. for every state s, goto[s] either has both bytes leading to trie
children or neither is a trie-defined edge at s). This is exactly the partition Section 4.4's
"byte classes (case-folded)" column reports.
"""
from __future__ import annotations

from collections import deque

from .types import ACTrie, NextMoveDFA

ALPHABET_SIZE = 256


def _byte_classes(trie: ACTrie) -> list[int]:
    """Returns class_of: byte -> class id, 0..num_classes-1. Two bytes share a class iff they
    are goto-defined at exactly the same set of trie states (the only property NEXTMOVE-BUILD's
    per-byte loop can ever distinguish)."""
    signature: dict[frozenset[int], int] = {}
    class_of = [0] * ALPHABET_SIZE
    for byte in range(ALPHABET_SIZE):
        states_with_edge = frozenset(
            s for s in range(trie.n_states) if byte in trie.goto[s]
        )
        if states_with_edge not in signature:
            signature[states_with_edge] = len(signature)
        class_of[byte] = signature[states_with_edge]
    return class_of


def build_nextmove(trie: ACTrie, layout: str = "dense") -> NextMoveDFA:
    """trie.fail must already be populated (call failure.build_failure_links first)."""
    if layout not in ("dense", "class_reduced"):
        raise ValueError(f"unknown layout {layout!r}")

    root = 0
    n = trie.n_states

    if layout == "class_reduced":
        class_of = _byte_classes(trie)
        n_classes = max(class_of) + 1
        rep_byte = [-1] * n_classes
        for b, c in enumerate(class_of):
            if rep_byte[c] == -1:
                rep_byte[c] = b
        symbols = list(range(n_classes))
        byte_for = rep_byte  # class id -> a representative raw byte, for goto lookups
    else:
        class_of = None
        symbols = list(range(ALPHABET_SIZE))
        byte_for = list(range(ALPHABET_SIZE))  # identity

    delta: list[list[int]] = [[0] * len(symbols) for _ in range(n)]

    for c in symbols:
        b = byte_for[c]
        delta[root][c] = trie.goto[root].get(b, root)

    queue: deque[int] = deque(trie.goto[root].values())
    visited_children = set(trie.goto[root].values())
    while queue:
        r = queue.popleft()
        for c in symbols:
            b = byte_for[c]
            child = trie.goto[r].get(b)
            if child is not None:
                delta[r][c] = child
                if child not in visited_children:
                    visited_children.add(child)
                    queue.append(child)
            else:
                delta[r][c] = delta[trie.fail[r]][c]

    return NextMoveDFA(layout=layout, delta=delta, out=list(trie.out), class_of=class_of)
