"""
FlowControlBlock + FlowTable (IMPLEMENTATION.md Section 3 Component 7, Section 5 Module 4).

Owns the per-TCP-flow state that lets AC scanning (Module 1) and SQLi parsing (Module 3) resume
across packet boundaries WITHOUT flow reassembly (Section 2.5, [Dossier Section 18 Option A]).
Bounded memory is an explicit acceptance criterion (Secondary Claim 2, Section 1) -- enforced here
via TTL eviction, not by hoping flows complete cleanly.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

FlowKey = tuple[str, int, str, int, str]  # (src_ip, src_port, dst_ip, dst_port, proto)


@dataclass
class FlowControlBlock:
    ac_state: int = 0
    dpda_stack: list[tuple[int, bool]] = field(default_factory=lambda: [(0, False)])
    sqli_partial_token: bytes = b""
    last_seen_ns: int = 0
    byte_count: int = 0
    created_ns: int = 0


@dataclass
class FlowTable:
    _flows: dict[FlowKey, FlowControlBlock] = field(default_factory=dict)

    def get_or_create(self, key: FlowKey, now_ns: int | None = None) -> FlowControlBlock:
        now_ns = now_ns if now_ns is not None else time.time_ns()
        fcb = self._flows.get(key)
        if fcb is None:
            fcb = FlowControlBlock(created_ns=now_ns, last_seen_ns=now_ns)
            self._flows[key] = fcb
        return fcb

    def evict_stale(self, now_ns: int, ttl_ns: int) -> int:
        """Removes flows idle longer than ttl_ns. Returns count evicted (Section 5 Module 4's
        test_flow_eviction_bounds_memory checks that this converges the table to empty after an
        idle period, proving peak memory is bounded by (arrival rate x TTL), not by total flows
        ever seen)."""
        stale = [k for k, fcb in self._flows.items() if now_ns - fcb.last_seen_ns > ttl_ns]
        for k in stale:
            del self._flows[k]
        return len(stale)

    def __len__(self) -> int:
        return len(self._flows)

    def __contains__(self, key: FlowKey) -> bool:
        return key in self._flows
