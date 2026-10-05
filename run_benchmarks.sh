#!/usr/bin/env bash
# run_benchmarks.sh -- one-command reproduction (IMPLEMENTATION.md Section 8 T1.3,
# Section 6.5's artifact-evaluation requirement: a single command regenerating every table this
# build can regenerate from data available in this environment).
#
# What this DOES regenerate: the full test suite (60+ tests, including every [Verified in this
# doc] number in IMPLEMENTATION.md), the synthetic-data harness comparison across AEGIS-AC and
# whichever of the 4 required baselines are installed, and the real libinjection-corpus SQLi
# evaluation.
#
# What this does NOT regenerate: anything needing the real Snort/ET Open/CIC-IDS2017 datasets
# (Section 6.1) -- those aren't reachable from a sandboxed build environment; see README.md and
# bench/harness.py's DATASET_DOWNLOAD_COMMANDS for exact commands to run on a machine with normal
# internet access, then point this script's REPORT step at the local files.

set -euo pipefail
cd "$(dirname "$0")"

echo "=== 1/3: full test suite ==="
python3 -m pytest tests/ -v

echo
echo "=== 2/3: narrated worked-example walkthrough (demo.py) ==="
python3 demo.py

echo
echo "=== 3/3: generating REPORT.md (synthetic-data harness + real libinjection corpus eval) ==="
N_RUNS="${AEGIS_AC_BENCH_RUNS:-100}"
python3 -m bench.report REPORT.md "$N_RUNS"

echo
echo "Done. See REPORT.md for the generated tables."
