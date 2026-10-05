"""
Offline LR(1)/LALR(1) table generator (IMPLEMENTATION.md Section 5 Module 3: gen_tables.py).
NOT run at scan time -- run once at build time, and the resulting tables are what parser.py's
shift-reduce driver actually uses. This module is the machine verification behind Section 2.6's
claim of "canonical LR(1) with 1,689 states and zero conflicts; LALR(1) core with 179 states,
also zero conflicts."

Implementation note: this grammar (Section 2.6) has NO epsilon productions, which simplifies
FIRST-set computation to a simple fixed-point over "FIRST(A) includes FIRST(first symbol of each
A-production)" -- the general epsilon-aware algorithm is not needed here and is not implemented,
to keep this reference generator's logic directly auditable against the grammar it targets.
"""
from __future__ import annotations

import collections
from dataclasses import dataclass, field

from .grammar import GRAMMAR_TEXT, START_SYMBOL, load_productions, nonterminals, terminals

Item = tuple[int, int]  # (production index, dot position)


@dataclass
class GrammarTables:
    productions: list[tuple[str, tuple[str, ...]]]  # index 0 is the augmented S' -> start
    nonterminals: set[str]
    terminals: set[str]
    states: list[dict[Item, set[str]]]  # canonical LR(1) states (or LALR-merged, see n_states)
    edges: dict[tuple[int, str], int]
    action: dict[tuple[int, str], tuple]  # ('s', state) | ('r', prod_idx) | ('acc',)
    goto: dict[tuple[int, str], int]
    conflicts: list[tuple]
    representative: dict[int, int] | None = None  # for LALR: canonical-state -> merged-state id


def _augment(prods: list[tuple[str, tuple[str, ...]]], start: str):
    return [("S'", (start,))] + prods


def _first_sets(prods, NT, T):
    first = {t: {t} for t in T}
    for n in NT:
        first[n] = set()
    by = collections.defaultdict(list)
    for i, (l, r) in enumerate(prods):
        by[l].append(i)
    changed = True
    while changed:
        changed = False
        for l, r in prods:
            f = first[r[0]]
            if not f <= first[l]:
                first[l] |= f
                changed = True
    return first, by


def _closure(kernel: dict[Item, set[str]], prods, NT, by, first) -> dict[Item, set[str]]:
    items = {k: set(v) for k, v in kernel.items()}
    work = list(items)
    while work:
        p, d = work.pop()
        l, r = prods[p]
        if d < len(r) and r[d] in NT:
            B = r[d]
            lookaheads = first[r[d + 1]] if d + 1 < len(r) else items[(p, d)]
            for q in by[B]:
                cur = items.setdefault((q, 0), set())
                new = lookaheads - cur
                if new:
                    cur |= new
                    work.append((q, 0))
    return items


def _item_key(items: dict[Item, set[str]]):
    return tuple(sorted((k, tuple(sorted(v))) for k, v in items.items()))


def build_lr1(prods: list[tuple[str, tuple[str, ...]]], start: str = START_SYMBOL) -> GrammarTables:
    aug = _augment(prods, start)
    NT = nonterminals(aug)
    T = terminals(aug) | {"$"}
    first, by = _first_sets(aug, NT, T - {"$"})

    I0 = _closure({(0, 0): {"$"}}, aug, NT, by, first)
    states = [I0]
    index = {_item_key(I0): 0}
    edges: dict[tuple[int, str], int] = {}

    i = 0
    while i < len(states):
        I = states[i]
        moves: dict[str, dict[Item, set[str]]] = collections.defaultdict(dict)
        for (p, d), las in I.items():
            l, r = aug[p]
            if d < len(r):
                X = r[d]
                kern = moves[X].setdefault((p, d + 1), set())
                kern |= las
        for X, kernel in moves.items():
            J = _closure(kernel, aug, NT, by, first)
            kj = _item_key(J)
            if kj not in index:
                index[kj] = len(states)
                states.append(J)
            edges[(i, X)] = index[kj]
        i += 1

    action: dict[tuple[int, str], tuple] = {}
    conflicts: list[tuple] = []
    for i, I in enumerate(states):
        for (p, d), las in I.items():
            l, r = aug[p]
            if d == len(r):
                for a in las:
                    act = ("acc",) if p == 0 and a == "$" else ("r", p)
                    if (i, a) in action and action[(i, a)] != act:
                        conflicts.append((i, a, action[(i, a)], act))
                    else:
                        action[(i, a)] = act
    for (i, X), j in edges.items():
        if X not in NT:
            act = ("s", j)
            if (i, X) in action and action[(i, X)] != act:
                conflicts.append((i, X, action[(i, X)], act))
            else:
                action[(i, X)] = act
    goto = {(i, X): j for (i, X), j in edges.items() if X in NT}

    return GrammarTables(
        productions=aug,
        nonterminals=NT,
        terminals=T,
        states=states,
        edges=edges,
        action=action,
        goto=goto,
        conflicts=conflicts,
    )


def lalr_core_merge(tables: GrammarTables) -> GrammarTables:
    """Merges canonical LR(1) states that share the same CORE (item set with lookaheads
    stripped, restricted to kernel items: dot>0, or the augmented start item) -- the standard
    LALR(1) construction. Re-derives ACTION/GOTO over the merged states and re-checks for
    conflicts (an LALR merge CAN introduce reduce/reduce conflicts that the canonical
    construction didn't have, so this is a genuine, separate check, not just a state count)."""
    prods = tables.productions
    NT = tables.nonterminals

    def core(I: dict[Item, set[str]]):
        return tuple(sorted(k for k in I if k[1] > 0 or k[0] == 0))

    groups: dict[tuple, list[int]] = collections.defaultdict(list)
    for i, I in enumerate(tables.states):
        groups[core(I)].append(i)

    rep_of: dict[int, int] = {}
    merged_id: dict[tuple, int] = {}
    for new_id, (c, members) in enumerate(groups.items()):
        merged_id[c] = new_id
        for m in members:
            rep_of[m] = new_id

    merged_items: list[dict[Item, set[str]]] = [dict() for _ in groups]
    for i, I in enumerate(tables.states):
        target = merged_items[rep_of[i]]
        for k, las in I.items():
            target.setdefault(k, set())
            target[k] |= las

    action: dict[tuple[int, str], tuple] = {}
    conflicts: list[tuple] = []
    for i, I in enumerate(merged_items):
        for (p, d), las in I.items():
            l, r = prods[p]
            if d == len(r):
                for a in las:
                    act = ("acc",) if p == 0 and a == "$" else ("r", p)
                    if (i, a) in action and action[(i, a)] != act:
                        conflicts.append((i, a, action[(i, a)], act))
                    else:
                        action[(i, a)] = act

    goto: dict[tuple[int, str], int] = {}
    for (i, X), j in tables.edges.items():
        mi, mj = rep_of[i], rep_of[j]
        if X in NT:
            goto[(mi, X)] = mj
        else:
            act = ("s", mj)
            if (mi, X) in action and action[(mi, X)] != act:
                conflicts.append((mi, X, action[(mi, X)], act))
            else:
                action[(mi, X)] = act

    return GrammarTables(
        productions=prods,
        nonterminals=NT,
        terminals=tables.terminals,
        states=merged_items,
        edges={},  # not maintained post-merge; action/goto are authoritative
        action=action,
        goto=goto,
        conflicts=conflicts,
        representative=rep_of,
    )


def check_no_unit_cycles(tables: GrammarTables) -> list[str]:
    """A -> B unit productions forming a cycle (A =>+ A) would make the grammar ill-formed for
    LR parsing in a way conflict-counting alone might not surface cleanly. Returns the list of
    nonterminals involved in a cycle (empty = clean, per Section 5 Module 3's test)."""
    unit: dict[str, set[str]] = collections.defaultdict(set)
    for l, r in tables.productions[1:]:
        if len(r) == 1 and r[0] in tables.nonterminals:
            unit[l].add(r[0])

    def reachable(a: str) -> set[str]:
        seen: set[str] = set()
        stack = [a]
        while stack:
            u = stack.pop()
            for v in unit[u]:
                if v not in seen:
                    seen.add(v)
                    stack.append(v)
        return seen

    return [a for a in tables.nonterminals if a in reachable(a)]


def build_all(text: str = GRAMMAR_TEXT, start: str = START_SYMBOL):
    prods = load_productions(text)
    canonical = build_lr1(prods, start)
    lalr = lalr_core_merge(canonical)
    cycles = check_no_unit_cycles(canonical)
    return prods, canonical, lalr, cycles
