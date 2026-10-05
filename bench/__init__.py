"""Instrumentation, Synthetic Data Generator & Evaluation Harness Driver
(IMPLEMENTATION.md Module 5, Owner: Benchmarking Lead)."""
from .sig_generator import gen_signatures, trie_state_count, byte_class_count
from .metrics import Counters, InstrumentedScanner, timed
from .baselines import (
    NaiveMultiPatternBaseline,
    BacktrackingRegexBaseline,
    ScanResult,
    try_build_pyahocorasick_baseline,
    try_build_hyperscan_baseline,
)
from .harness import (
    BenchResultRecord,
    Summary,
    TrialConfig,
    UnderpoweredRunCountError,
    DATASET_DOWNLOAD_COMMANDS,
    MIN_RUNS_FLOOR,
    mann_whitney_u,
    run_trial,
    run_comparative_trial,
    summarize,
)

__all__ = [
    "gen_signatures",
    "trie_state_count",
    "byte_class_count",
    "Counters",
    "InstrumentedScanner",
    "timed",
    "NaiveMultiPatternBaseline",
    "BacktrackingRegexBaseline",
    "ScanResult",
    "try_build_pyahocorasick_baseline",
    "try_build_hyperscan_baseline",
    "BenchResultRecord",
    "Summary",
    "TrialConfig",
    "UnderpoweredRunCountError",
    "DATASET_DOWNLOAD_COMMANDS",
    "MIN_RUNS_FLOOR",
    "mann_whitney_u",
    "run_trial",
    "run_comparative_trial",
    "summarize",
]
