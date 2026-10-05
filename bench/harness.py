"""
Harness driver (IMPLEMENTATION.md Section 5 Module 5, Section 6 EVALUATION HARNESS). Runs AEGIS-AC
(and, where available, baselines) over synthetic or real datasets, >=100 independent runs per
cell, records the Section 4.3 BenchResultRecord schema, and computes summary statistics including
a Mann-Whitney U significance test before any comparative claim (Section 6.5).

Real-dataset acquisition (Snort Community, ET Open, CIC-IDS2017) is NOT executed by this module in
this sandbox -- see DATASET_DOWNLOAD_COMMANDS below and Section 6.1/Section 8 T6.2. Everything
else (synthetic generation, AEGIS-AC's own scan, statistics) runs end to end right now.
"""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Literal

from ac_prefilter import build_failure_links, build_nextmove, build_trie_literals, scan_final_state
from bench.metrics import Counters
from bench.sig_generator import gen_signatures

# Verified-live download commands (Section 6.1) -- kept here as data, not executed automatically,
# since snort.org / rules.emergingthreats.net / unb.ca are outside this build's sandboxed network
# allowlist. Run these on a machine with normal internet access.
DATASET_DOWNLOAD_COMMANDS = {
    "snort_community": (
        "curl -L -o community-rules.tar.gz "
        "https://www.snort.org/downloads/community/community-rules.tar.gz"
    ),
    "et_open": (
        "curl -L -o emerging.rules.tar.gz "
        "https://rules.emergingthreats.net/open/suricata-7.0.0/emerging.rules.tar.gz"
    ),
    "cic_ids2017": (
        "# manual: submit the access-request form at "
        "https://www.unb.ca/cic/datasets/ids-2017.html, then download "
        "GeneratedLabelledFlows.zip and the per-day PCAPs"
    ),
}

System = Literal[
    "AEGIS_AC", "NAIVE_MULTIPATTERN", "STANDARD_AC", "HYPERSCAN_SURICATA", "PCRE_BACKTRACKING"
]
CacheCondition = Literal["COLD", "WARM"]

MIN_RUNS_FLOOR = 30  # [Dossier Section 35]'s documented lower bound; 100 is the target default


@dataclass
class TrialConfig:
    system: System
    dataset: str
    k: int
    n_runs: int = 100
    cache_condition: CacheCondition = "WARM"


@dataclass
class BenchResultRecord:
    system: str
    dataset: str
    k: int
    run_index: int
    transitions: int
    wall_clock_ns: int
    throughput_gbps: float
    memory_bytes: int
    cache: str


class UnderpoweredRunCountError(ValueError):
    pass


def _build_aegis_ac_scanner(k: int, seed: int = 20260920):
    sigs = gen_signatures(k=k, seed=seed)
    trie = build_trie_literals(sigs)
    build_failure_links(trie)
    dfa = build_nextmove(trie, layout="dense")
    return dfa


def run_trial(
    cfg: TrialConfig, payload: bytes | None = None, seed: int = 20260920
) -> list[BenchResultRecord]:
    if cfg.n_runs < MIN_RUNS_FLOOR:
        raise UnderpoweredRunCountError(
            f"n_runs={cfg.n_runs} is below the documented floor of {MIN_RUNS_FLOOR} "
            f"([Dossier Section 35]); the harness will not silently accept an underpowered run count."
        )

    if payload is None:
        sigs = gen_signatures(k=cfg.k, seed=seed)
        payload = (b"benign traffic padding " * 50) + b"".join(sigs[:5]) + (b" more padding" * 50)

    if cfg.system == "AEGIS_AC":
        return _run_aegis_ac_trial(cfg, payload, seed)
    if cfg.system == "STANDARD_AC":
        return _run_pyahocorasick_trial(cfg, payload, seed)
    if cfg.system == "NAIVE_MULTIPATTERN":
        return _run_naive_trial(cfg, payload, seed)
    if cfg.system == "HYPERSCAN_SURICATA":
        return _run_hyperscan_trial(cfg, payload, seed)
    if cfg.system == "PCRE_BACKTRACKING":
        raise NotImplementedError(
            "PCRE_BACKTRACKING is a single-regex baseline (Section 6.2's ReDoS demonstration "
            "point, E4), not a multi-pattern comparison point like the other four systems -- see "
            "run_redos_adversarial_experiment() below instead of run_trial for this baseline."
        )
    raise ValueError(f"unknown system {cfg.system!r}")


def _run_aegis_ac_trial(cfg: TrialConfig, payload: bytes, seed: int) -> list[BenchResultRecord]:
    dfa = _build_aegis_ac_scanner(cfg.k, seed=seed)
    records: list[BenchResultRecord] = []
    for run in range(cfg.n_runs):
        if cfg.cache_condition == "WARM" and run == 0:
            scan_final_state(dfa, payload)
        t0 = time.perf_counter_ns()
        _, matches = scan_final_state(dfa, payload)
        elapsed_ns = time.perf_counter_ns() - t0
        transitions = len(payload)
        throughput_gbps = (len(payload) * 8) / max(elapsed_ns, 1)
        memory_bytes = dfa.n_states * len(dfa.delta[0]) * 4
        records.append(
            BenchResultRecord(
                system=cfg.system, dataset=cfg.dataset, k=cfg.k, run_index=run,
                transitions=transitions, wall_clock_ns=elapsed_ns,
                throughput_gbps=throughput_gbps, memory_bytes=memory_bytes,
                cache=cfg.cache_condition,
            )
        )
    return records


def _run_pyahocorasick_trial(cfg: TrialConfig, payload: bytes, seed: int) -> list[BenchResultRecord]:
    from bench.baselines import try_build_pyahocorasick_baseline

    sigs = gen_signatures(k=cfg.k, seed=seed)
    scanner = try_build_pyahocorasick_baseline(sigs)
    if scanner is None:
        raise RuntimeError(
            "pyahocorasick not installed in this environment -- `pip install pyahocorasick` to "
            "run the STANDARD_AC baseline."
        )
    records: list[BenchResultRecord] = []
    for run in range(cfg.n_runs):
        if cfg.cache_condition == "WARM" and run == 0:
            scanner.scan(payload)
        result = scanner.scan(payload)
        throughput_gbps = (len(payload) * 8) / max(result.wall_clock_ns, 1)
        records.append(
            BenchResultRecord(
                system=cfg.system, dataset=cfg.dataset, k=cfg.k, run_index=run,
                transitions=result.op_count, wall_clock_ns=result.wall_clock_ns,
                throughput_gbps=throughput_gbps, memory_bytes=0,  # not introspectable via the
                # pyahocorasick C-extension API -- reported as unknown rather than guessed
                cache=cfg.cache_condition,
            )
        )
    return records


def _run_naive_trial(cfg: TrialConfig, payload: bytes, seed: int) -> list[BenchResultRecord]:
    from bench.baselines import NaiveMultiPatternBaseline

    sigs = gen_signatures(k=cfg.k, seed=seed)
    scanner = NaiveMultiPatternBaseline(sigs)
    records: list[BenchResultRecord] = []
    for run in range(cfg.n_runs):
        result = scanner.scan(payload)
        throughput_gbps = (len(payload) * 8) / max(result.wall_clock_ns, 1)
        records.append(
            BenchResultRecord(
                system=cfg.system, dataset=cfg.dataset, k=cfg.k, run_index=run,
                transitions=result.op_count, wall_clock_ns=result.wall_clock_ns,
                throughput_gbps=throughput_gbps, memory_bytes=0, cache=cfg.cache_condition,
            )
        )
    return records


def _run_hyperscan_trial(cfg: TrialConfig, payload: bytes, seed: int) -> list[BenchResultRecord]:
    from bench.baselines import try_build_hyperscan_baseline

    sigs = gen_signatures(k=cfg.k, seed=seed)
    scanner = try_build_hyperscan_baseline(sigs)
    if scanner is None:
        raise RuntimeError(
            "hyperscan/libhyperscan not available in this environment -- see "
            "bench/baselines.py's try_build_hyperscan_baseline docstring."
        )
    records: list[BenchResultRecord] = []
    for run in range(cfg.n_runs):
        if cfg.cache_condition == "WARM" and run == 0:
            scanner.scan(payload)
        result = scanner.scan(payload)
        throughput_gbps = (len(payload) * 8) / max(result.wall_clock_ns, 1)
        records.append(
            BenchResultRecord(
                system=cfg.system, dataset=cfg.dataset, k=cfg.k, run_index=run,
                transitions=result.op_count, wall_clock_ns=result.wall_clock_ns,
                throughput_gbps=throughput_gbps, memory_bytes=0, cache=cfg.cache_condition,
            )
        )
    return records


def run_comparative_trial(
    k: int, dataset: str = "synthetic", n_runs: int = 100, seed: int = 20260920
) -> dict[str, list[BenchResultRecord]]:
    """Runs EVERY available system (AEGIS_AC always; STANDARD_AC/HYPERSCAN_SURICATA/
    NAIVE_MULTIPATTERN if their packages are installed) over the SAME synthetic signature set and
    the SAME payload, side by side -- this is what Section 6.2's "don't compare only to a naive
    strawman" requirement actually needs: several systems, one dataset, one run. Systems whose
    package isn't available are skipped with a note, not silently omitted from the return value."""
    sigs = gen_signatures(k=k, seed=seed)
    payload = (b"benign traffic padding " * 50) + b"".join(sigs[:5]) + (b" more padding" * 50)

    results: dict[str, list[BenchResultRecord]] = {}
    skipped: list[str] = []
    for system in ("AEGIS_AC", "NAIVE_MULTIPATTERN", "STANDARD_AC", "HYPERSCAN_SURICATA"):
        cfg = TrialConfig(system=system, dataset=dataset, k=k, n_runs=n_runs)
        try:
            results[system] = run_trial(cfg, payload=payload, seed=seed)
        except RuntimeError as e:
            skipped.append(f"{system}: {e}")
    if skipped:
        results["_skipped"] = skipped  # type: ignore[assignment]
    return results


@dataclass
class Summary:
    n: int
    mean_ns: float
    stddev_ns: float
    p50_ns: float
    p95_ns: float
    p99_ns: float


def summarize(records: list[BenchResultRecord]) -> Summary:
    values = sorted(r.wall_clock_ns for r in records)
    n = len(values)
    return Summary(
        n=n,
        mean_ns=statistics.fmean(values),
        stddev_ns=statistics.pstdev(values) if n > 1 else 0.0,
        p50_ns=values[int(0.50 * (n - 1))],
        p95_ns=values[int(0.95 * (n - 1))],
        p99_ns=values[int(0.99 * (n - 1))],
    )


def mann_whitney_u(sample_a: list[float], sample_b: list[float]) -> tuple[float, float]:
    """Two-sided Mann-Whitney U test (no scipy dependency -- small, self-contained
    implementation, adequate for the harness's own regression tests; swap in
    scipy.stats.mannwhitneyu for the real evaluation run, Section 6.5). Returns (U, approximate
    two-sided p-value via the normal approximation, valid for n>=~20 per sample)."""
    a = sorted(sample_a)
    b = sorted(sample_b)
    combined = sorted((v, 0) for v in a) + sorted((v, 1) for v in b)
    combined.sort(key=lambda t: t[0])

    ranks: dict[int, list[float]] = {0: [], 1: []}
    i = 0
    n = len(combined)
    while i < n:
        j = i
        while j < n and combined[j][0] == combined[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for idx in range(i, j):
            ranks[combined[idx][1]].append(avg_rank)
        i = j

    na, nb = len(a), len(b)
    r_a = sum(ranks[0])
    u_a = r_a - na * (na + 1) / 2.0
    u_b = na * nb - u_a
    u = min(u_a, u_b)

    mean_u = na * nb / 2.0
    std_u = ((na * nb * (na + nb + 1)) / 12.0) ** 0.5
    if std_u == 0:
        return u, 1.0
    z = (u - mean_u) / std_u
    # two-sided p-value via the standard normal CDF (erf-based, no scipy needed)
    import math

    p = 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))
    return u, max(0.0, min(1.0, p))
