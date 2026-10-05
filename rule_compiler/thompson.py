"""
Thompson's construction (IMPLEMENTATION.md Section 2.2, Section 5 Module 2): regex AST -> NFA
with epsilon-moves, |Q_N| <= 2r states for regex length r, O(r) time/space.

The "merge" variant (default, matching Section 2.2's stated construction convention) fuses a
concatenation's left-accept state with its right-start state rather than adding an explicit
epsilon edge between them -- this is what keeps the classic (a|b)*abb example's canonical
numbering (5 subset states -> 4 minimal) reproducible exactly as worked in Section 5 Module 2's
viva example. A non-merged variant is also provided for the "eps-linked" comparison IMPLEMENTATION.md's
verification work used to sanity-check |Q_N| <= 2r.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .regex_ast import RegexAST


@dataclass
class NFA:
    n_states: int
    # edges: list of (from_state, label_or_None, to_state); label is a frozenset[int] byte set,
    # or None for an epsilon-move.
    edges: list[tuple[int, frozenset[int] | None, int]]
    start: int
    accept: int


def thompson_construct(ast: RegexAST, merge: bool = True) -> NFA:
    """merge=True: concatenation fuses states (fewer states, matches Section 2.2's convention).
    merge=False: explicit epsilon edge at concatenation boundaries (used only for the |Q_N|<=2r
    sanity-check comparison in Section 2.2's illustrative note)."""

    counter = [0]
    edges: list[tuple[int, frozenset[int] | None, int]] = []
    alias: dict[int, int] = {}

    def new_state() -> int:
        s = counter[0]
        counter[0] += 1
        return s

    def build(n: RegexAST) -> tuple[int, int]:
        t = n[0]
        if t == "set":
            a, b = new_state(), new_state()
            edges.append((a, n[1], b))
            return a, b
        if t == "cat":
            s1, f1 = build(n[1])
            s2, f2 = build(n[2])
            if merge:
                alias[s2] = f1
                return s1, f2
            edges.append((f1, None, s2))
            return s1, f2
        if t == "alt":
            s1, f1 = build(n[1])
            s2, f2 = build(n[2])
            a, b = new_state(), new_state()
            edges.extend([(a, None, s1), (a, None, s2), (f1, None, b), (f2, None, b)])
            return a, b
        if t == "star":
            s1, f1 = build(n[1])
            a, b = new_state(), new_state()
            edges.extend([(a, None, s1), (a, None, b), (f1, None, s1), (f1, None, b)])
            return a, b
        if t == "plus":
            return build(("cat", n[1], ("star", n[1])))
        if t == "opt":
            s1, f1 = build(n[1])
            a, b = new_state(), new_state()
            edges.extend([(a, None, s1), (a, None, b), (f1, None, b)])
            return a, b
        if t == "rep":
            _, x, m, hi = n
            parts = [x] * m
            if hi is None:
                parts.append(("star", x))
            else:
                parts += [("opt", x)] * (hi - m)
            if not parts:
                raise ValueError("rep{0,0} not supported")
            node = parts[0]
            for p in parts[1:]:
                node = ("cat", node, p)
            return build(node)
        raise ValueError(f"unknown AST node {t!r}")

    start, accept = build(ast)

    def resolve(x: int) -> int:
        while x in alias:
            x = alias[x]
        return x

    resolved_edges = [(resolve(a), lbl, resolve(b)) for a, lbl, b in edges]
    live_states = sorted({resolve(x) for x in range(counter[0])})
    renumber = {old: i for i, old in enumerate(live_states)}
    final_edges = [(renumber[a], lbl, renumber[b]) for a, lbl, b in resolved_edges]

    return NFA(
        n_states=len(live_states),
        edges=final_edges,
        start=renumber[resolve(start)],
        accept=renumber[resolve(accept)],
    )
