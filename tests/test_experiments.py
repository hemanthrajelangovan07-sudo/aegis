from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench.experiments import (
    run_e2_prefilter_selectivity,
    run_e3_fragmentation,
    run_e4_redos_adversarial,
    run_e5_storage_layout,
)


def test_e2_selectivity_collapses_with_short_anchors():
    """Regression-pins the real finding: very short anchors (2-3 bytes) have dramatically worse
    selectivity than anchors >=4 bytes, at a fixed k."""
    results = run_e2_prefilter_selectivity(ks=[10000], anchor_lens=[2, 5])
    by_len = {r.anchor_len: r for r in results}
    assert by_len[2].escalation_rate > 10 * by_len[5].escalation_rate


def test_e3_fragmentation_recall_always_equals_full_reassembly():
    """The real point of Secondary Claim 2: fragmented-with-resumption recall must equal
    full-reassembly recall exactly, at every fragmentation rate, not just the one split point
    the flagship Module 4 unit test checks."""
    results = run_e3_fragmentation(n_payloads=50, fragmentation_rates=[0.0, 0.3, 0.7])
    for r in results:
        assert r.recall_fragmented == r.recall_full_reassembly == 1.0


def test_e4_aegis_ac_classification_time_flat_vs_n():
    """AEGIS-AC's compile-time rejection cost must not grow with n (it never looks at the
    adversarial INPUT at all, only the regex AST) -- while the backtracking baseline's cost must
    strictly increase with n, demonstrating the exponential-vs-flat contrast for real."""
    results = run_e4_redos_adversarial(ns=[10, 16, 20], timeout_s=2.0)
    assert all(r.aegis_ac_classification == "REJECTED_UNBOUNDED" for r in results)
    times = [r.aegis_ac_time_ns for r in results]
    assert max(times) < 5 * min(times)  # flat, not growing with n (loose bound for CI noise)

    bt_times = [r.backtracking_time_ns for r in results if r.backtracking_time_ns is not None]
    assert len(bt_times) >= 2
    assert bt_times[-1] > bt_times[0]  # strictly grew as n increased


def test_e5_class_reduced_uses_less_memory_than_dense():
    results = run_e5_storage_layout(ks=[100], payload_len=5000)
    by_layout = {r.layout: r for r in results}
    assert by_layout["class_reduced"].estimated_bytes < by_layout["dense"].estimated_bytes
    assert by_layout["class_reduced"].n_states == by_layout["dense"].n_states  # same automaton


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
