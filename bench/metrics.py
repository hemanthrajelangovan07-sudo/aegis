"""
Instrumentation (IMPLEMENTATION.md Section 3 Component 9, Section 5 Module 5). Counters must be a
pure function of (control-flow path taken, payload length), never of specific payload byte
values -- Section 5 Module 5's test_metrics_no_content_branch checks this directly. This is what
lets Section 6.5's "algorithmic op-count vs wall-clock" honesty split actually mean something.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class Counters:
    transitions: int = 0
    failure_moves: int = 0
    mem_refs: int = 0
    wall_clock_ns: int = 0

    def snapshot(self) -> dict[str, int]:
        return {
            "transitions": self.transitions,
            "failure_moves": self.failure_moves,
            "mem_refs": self.mem_refs,
            "wall_clock_ns": self.wall_clock_ns,
        }

    def reset(self) -> None:
        self.transitions = 0
        self.failure_moves = 0
        self.mem_refs = 0
        self.wall_clock_ns = 0


class InstrumentedScanner:
    """Wraps ac_prefilter's scan loop with counter increments ONLY -- never inspects a byte
    VALUE to decide whether to count it, only whether a transition happened at all (a pure
    function of control-flow position and payload length, per the module's contract)."""

    def __init__(self, dfa, counters: Counters):
        self.dfa = dfa
        self.counters = counters

    def scan(self, payload: bytes, start_state: int = 0):
        from ac_prefilter.scan import scan as _scan

        t0 = time.perf_counter_ns()
        state = start_state
        matches = []
        for i, byte in enumerate(payload):
            state = self.dfa.step(state, byte)
            self.counters.transitions += 1
            self.counters.mem_refs += 1  # one table lookup per transition
            hits = self.dfa.out[state]
            if hits:
                from ac_prefilter.types import Match

                matches.append(Match(i, hits))
        self.counters.wall_clock_ns += time.perf_counter_ns() - t0
        return state, matches


@contextmanager
def timed(counters: Counters):
    t0 = time.perf_counter_ns()
    yield
    counters.wall_clock_ns += time.perf_counter_ns() - t0
