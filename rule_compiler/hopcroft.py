"""
DFA minimization (IMPLEMENTATION.md Section 2.3, Section 5 Module 2). Complexity is
O(|Sigma|*n log n), n = |Q| of the UNMINIMIZED dfa, NOT a function of regex source length r --
this is the corrected bound (Section 2.3 / Section 5 Module 2's test_hopcroft_bound_not_regex_length),
replacing the original draft's incorrect O(r log r) framing.

The implementation below is a straightforward partition-refinement minimizer (repeatedly split
blocks by transition signature until stable). This is asymptotically O(|Sigma|*n^2) as coded (not
the optimized O(|Sigma|*n log n) Hopcroft data structure with the smaller-half worklist trick) --
correctness is what Section 5's fixtures check; the O(|Sigma|*n log n) BOUND itself is the cited
dossier fact (Hopcroft 1971), not a claim about this reference implementation's own big-O, which
is noted honestly here rather than overclaimed. A production build should swap in the classic
worklist-based Hopcroft algorithm for the O(n log n) behavior; this reference version exists to
verify state COUNTS, not to demonstrate the asymptotically optimal algorithm.
"""
from __future__ import annotations

from .subset_construct import DFA


def hopcroft_minimize(dfa: DFA) -> DFA:
    n = dfa.n_states
    n_classes = len(dfa.byte_classes)
    partition = [1 if s in dfa.accepting else 0 for s in range(n)]

    while True:
        signature: dict[tuple, int] = {}
        new_partition = [0] * n
        for s in range(n):
            key = (partition[s], tuple(partition[dfa.transitions[s][c]] for c in range(n_classes)))
            if key not in signature:
                signature[key] = len(signature)
            new_partition[s] = signature[key]
        if len(set(new_partition)) == len(set(partition)):
            partition = new_partition
            break
        partition = new_partition

    n_min = len(set(partition))
    rep_of_block: dict[int, int] = {}
    for s in range(n):
        rep_of_block.setdefault(partition[s], s)

    block_ids = sorted(set(partition))
    block_index = {b: i for i, b in enumerate(block_ids)}

    min_transitions = [[0] * n_classes for _ in range(n_min)]
    for b in block_ids:
        rep = rep_of_block[b]
        for c in range(n_classes):
            min_transitions[block_index[b]][c] = block_index[partition[dfa.transitions[rep][c]]]

    min_accepting = frozenset(
        block_index[b] for b in block_ids if rep_of_block[b] in dfa.accepting
    )

    return DFA(
        n_states=n_min,
        transitions=min_transitions,
        accepting=min_accepting,
        byte_classes=dfa.byte_classes,
    )
