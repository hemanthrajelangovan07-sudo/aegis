from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench.report import generate_full_report, table_t2_memory_footprint


def test_table_t2_memory_footprint_matches_spec():
    table = table_t2_memory_footprint(ks=[100, 1000])
    assert "1079" in table  # k=100 trie states
    assert "9639" in table  # k=1000 trie states


def test_generate_full_report_smoke(tmp_path):
    out = tmp_path / "report.md"
    path = generate_full_report(
        out,
        corpus_dir=Path(__file__).resolve().parents[1] / "third_party" / "libinjection-data",
        ks_memory=[100],
        ks_baseline=[100],
        n_runs=30,
        include_e2_e5=False,  # E2-E5 run their own separate, fast regression tests
        # (tests/test_experiments.py); skipped here purely to keep this smoke test quick.
    )
    text = path.read_text()
    assert "T2 -- Memory footprint" in text
    assert "T3 -- Baseline comparison" in text
    assert "AEGIS_AC" in text


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
