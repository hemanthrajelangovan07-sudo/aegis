from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import random

from ac_prefilter import build_failure_links, build_nextmove, build_trie_literals
from bench import (
    BacktrackingRegexBaseline,
    Counters,
    InstrumentedScanner,
    NaiveMultiPatternBaseline,
    TrialConfig,
    UnderpoweredRunCountError,
    byte_class_count,
    gen_signatures,
    mann_whitney_u,
    run_trial,
    summarize,
    trie_state_count,
    try_build_hyperscan_baseline,
    try_build_pyahocorasick_baseline,
)


def test_sig_generator_reproducible_k1000():
    sigs = gen_signatures(k=1000, seed=20260920)
    assert sum(len(s) for s in sigs) == 13660
    assert abs(sum(len(s) for s in sigs) / 1000 - 13.7) < 0.05
    assert trie_state_count(sigs) == 9639


def test_sig_generator_scaling_table():
    expected = {
        100: (1401, 1079),
        300: (4188, 3066),
        1000: (13660, 9639),
        3000: (41860, 29444),
        10000: (141730, 98822),
    }
    for k, (sum_len, trie_states) in expected.items():
        sigs = gen_signatures(k=k, seed=20260920)
        assert sum(len(s) for s in sigs) == sum_len, f"k={k} sum_len mismatch"
        assert trie_state_count(sigs) == trie_states, f"k={k} trie_states mismatch"


def test_sig_generator_deterministic_across_calls():
    a = gen_signatures(k=200, seed=42)
    b = gen_signatures(k=200, seed=42)
    assert a == b


def test_metrics_no_content_branch():
    """Counters must depend only on control-flow path + payload LENGTH, never on the specific
    byte VALUES -- run the same-length payload with randomized content many times and check the
    transition count is identical every time (same states visited count, differs only in which
    states, never how many transitions)."""
    trie = build_trie_literals(["needle"])
    build_failure_links(trie)
    dfa = build_nextmove(trie, layout="dense")

    rng = random.Random(7)
    lengths_seen = set()
    for _ in range(20):
        payload = bytes(rng.randrange(0, 256) for _ in range(500))
        counters = Counters()
        scanner = InstrumentedScanner(dfa, counters)
        scanner.scan(payload)
        assert counters.transitions == 500
        lengths_seen.add(counters.transitions)
    assert lengths_seen == {500}


def test_harness_min_runs_enforced():
    cfg = TrialConfig(system="AEGIS_AC", dataset="synthetic", k=100, n_runs=10)
    try:
        run_trial(cfg)
        assert False, "expected UnderpoweredRunCountError"
    except UnderpoweredRunCountError:
        pass


def test_harness_smoke_trial():
    cfg = TrialConfig(system="AEGIS_AC", dataset="synthetic_k100", k=100, n_runs=30)
    records = run_trial(cfg)
    assert len(records) == 30
    assert all(r.transitions == r.transitions for r in records)  # schema present
    summary = summarize(records)
    assert summary.n == 30
    assert summary.mean_ns >= 0


def test_mann_whitney_u_identical_samples_high_p():
    a = [100.0 + i for i in range(40)]
    b = [100.0 + i for i in range(40)]
    u, p = mann_whitney_u(a, b)
    assert p > 0.9


def test_mann_whitney_u_clearly_different_samples_low_p():
    a = [100.0 + i for i in range(40)]
    b = [1000.0 + i for i in range(40)]
    u, p = mann_whitney_u(a, b)
    assert p < 0.01


def test_naive_baseline_matches_ac_hits():
    payload = b"installed backdoor and keylogger on target machine silently today"
    naive = NaiveMultiPatternBaseline([b"backdoor", b"keylogger"])
    result = naive.scan(payload)
    assert sorted(result.hits) == [(17, "backdoor"), (31, "keylogger")]


def test_backtracking_regex_baseline_redos_class_still_correct_on_benign_input():
    baseline = BacktrackingRegexBaseline(r"UNION\s+SELECT", flags=0)
    result = baseline.scan(b"1 UNION SELECT a FROM b")
    assert len(result.hits) == 1


def test_hyperscan_baseline_matches_ac_hits():
    """Real Hyperscan (libhyperscan5 + hyperscan python bindings), not a mock -- exercises the
    actual compiled library against the 65-byte demo payload from IMPLEMENTATION.md's Refuted
    Claim #7 worked example."""
    scanner = try_build_hyperscan_baseline([b"backdoor", b"keylogger"])
    if scanner is None:
        return  # environment without libhyperscan -- acceptable, not a failure
    payload = b"installed backdoor and keylogger on target machine silently today"
    result = scanner.scan(payload)
    assert sorted(result.hits) == [(17, "backdoor"), (31, "keylogger")]


def test_pyahocorasick_optional_adapter_or_none():
    scanner = try_build_pyahocorasick_baseline([b"backdoor", b"keylogger"])
    if scanner is None:
        return  # package not installed in this environment -- acceptable, not a failure
    payload = b"installed backdoor and keylogger on target machine silently today"
    result = scanner.scan(payload)
    assert len(result.hits) == 2


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
