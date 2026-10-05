"""
Baseline adapters (IMPLEMENTATION.md Section 6.2). Four baselines are required before any
"AEGIS-AC is faster than naive search" claim is meaningful (Section 7.3's strawman-baseline
rebuttal): naive multi-pattern, standard C Aho-Corasick, Hyperscan/Suricata, and backtracking
PCRE. This module implements the two that run anywhere Python does (naive, and re-based
backtracking as a PCRE stand-in) plus an optional pyahocorasick adapter that activates only if
the package is installed. Hyperscan and a real Suricata mpm-algo comparison require a compiled
Hyperscan/Suricata binary and are NOT wired up here -- see the module docstring at the bottom for
exactly what's needed to add them, since they can't be provisioned inside this build's sandboxed
network (Section 8 T6.2's dataset-acquisition note applies to these binaries too).
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass


@dataclass
class ScanResult:
    hits: list[tuple[int, str]]  # (end_position, pattern) pairs, matching ac_prefilter's Match
    wall_clock_ns: int
    op_count: int  # baseline-specific notion of "operation" -- see each adapter's docstring


class NaiveMultiPatternBaseline:
    """O(k*n) unindexed loop: for every pattern, scan the whole payload. This is the mandatory
    "trivial strawman" comparison point (Section 6.2) -- never the headline comparison, only a
    sanity floor."""

    def __init__(self, patterns: list[bytes]):
        self.patterns = patterns

    def scan(self, payload: bytes) -> ScanResult:
        t0 = time.perf_counter_ns()
        hits: list[tuple[int, str]] = []
        ops = 0
        for p in self.patterns:
            start = 0
            while True:
                idx = payload.find(p, start)
                ops += len(payload) - start  # coarse but consistent op-count proxy
                if idx == -1:
                    break
                hits.append((idx + len(p) - 1, p.decode("latin-1")))
                start = idx + 1
        return ScanResult(hits=hits, wall_clock_ns=time.perf_counter_ns() - t0, op_count=ops)


class BacktrackingRegexBaseline:
    """Python `re` (backtracking NFA engine) standing in for libpcre -- used specifically to
    demonstrate the ReDoS vulnerability class AEGIS-AC's compiler routes around at compile time
    (Section 6.3 E4, Section 7.3). NOT a general-purpose multi-pattern baseline -- one regex at a
    time, matching how a rule engine would actually invoke libpcre per-rule."""

    def __init__(self, pattern: str, flags: int = 0):
        self.compiled = re.compile(pattern, flags)

    def scan(self, payload: bytes, timeout_s: float | None = None) -> ScanResult:
        text = payload.decode("latin-1")
        t0 = time.perf_counter_ns()
        hits = []
        for m in self.compiled.finditer(text):
            hits.append((m.end() - 1, m.group()))
        elapsed = time.perf_counter_ns() - t0
        return ScanResult(hits=hits, wall_clock_ns=elapsed, op_count=len(text))


def try_build_pyahocorasick_baseline(patterns: list[bytes]):
    """Returns a pyahocorasick-backed scanner if the package is installed, else None (caller
    should skip this baseline's rows in the report rather than fail the whole harness run --
    Section 5 Module 5's edge case: an unavailable baseline must be flagged, not silently
    dropped). See tests/test_metrics.py for the availability-gated test."""
    try:
        import ahocorasick
    except ImportError:
        return None

    automaton = ahocorasick.Automaton()
    for idx, p in enumerate(patterns):
        automaton.add_word(p.decode("latin-1"), (idx, p))
    automaton.make_automaton()

    class _PyahocorasickBaseline:
        def scan(self, payload: bytes) -> ScanResult:
            text = payload.decode("latin-1")
            t0 = time.perf_counter_ns()
            hits = [(end, orig.decode("latin-1")) for end, (idx, orig) in automaton.iter(text)]
            elapsed = time.perf_counter_ns() - t0
            return ScanResult(hits=hits, wall_clock_ns=elapsed, op_count=len(text))

    return _PyahocorasickBaseline()


def try_build_hyperscan_baseline(patterns: list[bytes]):
    """Returns a real Hyperscan-backed multi-pattern scanner if the `hyperscan` package and its
    underlying libhyperscan are available, else None. This is genuinely wired up in this build
    (libhyperscan5/libhyperscan-dev installed via apt, `pip install hyperscan` -- both reachable
    from this sandbox's allowlist, which includes archive.ubuntu.com/security.ubuntu.com and
    pypi.org). What is NOT available here is a full Suricata build with --enable-hyperscan for
    the `mpm-algo=hs` vs `mpm-algo=ac` production-pipeline comparison Section 6.2 also asks
    for -- that needs Suricata's full source build, which is a much larger dependency chain not
    attempted in this pass. This adapter covers the "Hyperscan as a multi-pattern engine"
    baseline directly, which is the comparison Section 1's Falsification Condition 1 (op-count
    parity) and Section 6.3 E1 actually need."""
    try:
        import hyperscan
    except ImportError:
        return None

    db = hyperscan.Database()
    ids = list(range(len(patterns)))
    flags = [hyperscan.HS_FLAG_SINGLEMATCH] * len(patterns)
    # literal=True (Hyperscan >=5.2.0's pure literal compiler) is required here -- without it,
    # `expressions` are interpreted as REGEXES, and this baseline's whole point is comparing
    # against literal multi-pattern matching (the same job AC does), not regex matching. Found
    # this the hard way: synthetic signatures (Section 4.4) include regex metacharacters like
    # `(`, `[` in their punctuation mixture, which broke compilation before this flag was added.
    db.compile(expressions=patterns, ids=ids, elements=len(patterns), flags=flags, literal=True)
    pattern_by_id = {i: p for i, p in enumerate(patterns)}

    class _HyperscanBaseline:
        def scan(self, payload: bytes) -> ScanResult:
            hits: list[tuple[int, str]] = []

            def on_match(id_, start, end, flags, ctx):
                # Hyperscan reports `end` as one-past-the-last-matched-byte (exclusive);
                # ac_prefilter.Match.end_position is the INCLUSIVE index of the last matched
                # byte -- verified equivalent (end_hyperscan == end_position_ac + 1) against the
                # 65-byte demo payload before this adapter was wired in.
                hits.append((end - 1, pattern_by_id[id_].decode("latin-1")))

            t0 = time.perf_counter_ns()
            db.scan(payload, match_event_handler=on_match)
            elapsed = time.perf_counter_ns() - t0
            return ScanResult(hits=hits, wall_clock_ns=elapsed, op_count=len(payload))

    return _HyperscanBaseline()


# ---------------------------------------------------------------------------
# NOT WIRED UP IN THIS SANDBOX -- see IMPLEMENTATION.md Section 6.2, Section 8 T6.2:
#
#   Suricata's own mpm-algo=hs vs mpm-algo=ac comparison (the production-pipeline-level
#   comparison, as opposed to Hyperscan-the-library-used-directly above, which IS wired up via
#   try_build_hyperscan_baseline): needs a full Suricata source build (--enable-hyperscan) and
#   its unix-socket/eve.json driving harness. Not attempted here -- large dependency chain
#   relative to what a multi-pattern-engine-level Hyperscan comparison already gives you.
#
#   Real rule/PCAP datasets (Snort Community, ET Open, CIC-IDS2017):
#     snort.org, rules.emergingthreats.net, and unb.ca are not reachable from this sandbox's
#     network allowlist (confirmed: github.com, pypi.org, and Ubuntu's apt mirrors ARE reachable,
#     which is what made the Hyperscan wiring above possible -- these three specific hosts are
#     not on the list). The exact download commands are in IMPLEMENTATION.md Section 6.1 and
#     bench/harness.py's DATASET_DOWNLOAD_COMMANDS -- run them on a machine with normal internet
#     access, then point harness.run_trial's `dataset` argument at the local path.
# ---------------------------------------------------------------------------
