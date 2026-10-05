"""
Subset construction (IMPLEMENTATION.md Section 2.3, Section 5 Module 2): NFA -> DFA via
epsilon-closure, worst case |Q_D| = 2^|Q_N|.

Two modes:
  "anchored"      -- standard subset construction; the resulting DFA matches the regex against
                      the FULL string (used for per-rule verifiers invoked on an already-anchored
                      window after an AC prefilter hit, Section 3 Component 4).
  "search_sticky" -- adds an implicit ".*" prefix (so the automaton can start matching anywhere
                      in a byte stream) and treats the accept state as absorbing ("sticky": once
                      accepted, stays accepted). This models MPM-style "match anywhere, then
                      done" verifier semantics and is the mode used for the no-anchor-fallback
                      rule class (RDP-1) and for the state-explosion demonstration family in
                      Section 2.3 / Section 5 Module 2's regression fixtures.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .thompson import NFA

MAX_SUBSET_STATES_DEFAULT = 200_000


class StateExplosionError(RuntimeError):
    """Raised when subset construction exceeds the configured state cap -- Section 5 Module 2's
    edge case: "must fail fast with a clear diagnostic rather than hanging", reproducing the
    Yu et al. / Becchi & Crowley failure mode deliberately rather than accidentally."""


@dataclass
class DFA:
    n_states: int
    # transitions[state] -> list[int], indexed by class id (see byte_classes)
    transitions: list[list[int]]
    accepting: frozenset[int]
    byte_classes: list[frozenset[int]]  # symbols[i] is the i-th equivalence class of bytes


def _byte_classes(edges: list[tuple[int, frozenset[int] | None, int]]) -> list[frozenset[int]]:
    label_sets = [lbl for _, lbl, _ in edges if lbl is not None]
    signature: dict[tuple[bool, ...], list[int]] = {}
    for b in range(256):
        key = tuple(b in s for s in label_sets)
        signature.setdefault(key, []).append(b)
    return [frozenset(v) for v in signature.values()]


def _epsilon_closure(states: set[int] | frozenset[int], eps: dict[int, set[int]]) -> frozenset[int]:
    stack = list(states)
    seen = set(states)
    while stack:
        u = stack.pop()
        for v in eps.get(u, ()):
            if v not in seen:
                seen.add(v)
                stack.append(v)
    return frozenset(seen)


def subset_construct(
    nfa: NFA, mode: str = "anchored", cap: int = MAX_SUBSET_STATES_DEFAULT
) -> DFA:
    if mode not in ("anchored", "search_sticky"):
        raise ValueError(f"unknown mode {mode!r}")

    classes = _byte_classes(nfa.edges)
    eps: dict[int, set[int]] = {}
    lab: dict[int, list[tuple[frozenset[int], int]]] = {}
    for a, lbl, b in nfa.edges:
        if lbl is None:
            eps.setdefault(a, set()).add(b)
        else:
            lab.setdefault(a, []).append((lbl, b))

    start_set = _epsilon_closure({nfa.start}, eps)
    dfa_states: dict[frozenset[int], int] = {start_set: 0}
    order: list[frozenset[int]] = [start_set]
    trans: dict[int, list[int]] = {}

    i = 0
    while i < len(order):
        S = order[i]
        i += 1
        if mode == "search_sticky" and nfa.accept in S:
            # absorbing accept state: every symbol self-loops
            trans[dfa_states[S]] = [dfa_states[S]] * len(classes)
            continue
        row = []
        for cls in classes:
            rep = next(iter(cls))
            T: set[int] = set()
            for u in S:
                for lbl, v in lab.get(u, ()):
                    if rep in lbl:
                        T.add(v)
            if mode == "search_sticky":
                T.add(nfa.start)  # unanchored: can always restart a match at this position
            T_closed = _epsilon_closure(T, eps)
            if T_closed not in dfa_states:
                if len(order) >= cap:
                    raise StateExplosionError(
                        f"subset construction exceeded {cap} states "
                        f"(mode={mode}) -- would-explode diagnostic per Section 5 Module 2"
                    )
                dfa_states[T_closed] = len(order)
                order.append(T_closed)
            row.append(dfa_states[T_closed])
        trans[dfa_states[S]] = row

    accepting = frozenset(dfa_states[S] for S in order if nfa.accept in S)
    n = len(order)
    transitions = [trans[s] for s in range(n)]
    return DFA(n_states=n, transitions=transitions, accepting=accepting, byte_classes=classes)
