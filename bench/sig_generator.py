"""
GEN-SIGNATURES pseudocode from IMPLEMENTATION.md Section 5 Module 5 / Section 4.4:

    GEN-SIGNATURES(k, seed):
        rng = SEEDED-RNG(seed)
        F = max(8, round(0.05*k)); family_seeds = [RANDOM-BYTES(rng, 3..12) for _ in range(F)]
        weights = ZIPF-WEIGHTS(F)
        sigs = {}
        while len(sigs) < k:
            L = CLIP(LOGNORMAL(rng, mu=ln(12), sigma=0.55), 4, 64)
            u = rng.random()
            if sigs and u < 0.15: base = RANDOM-EXISTING-PREFIX(rng, sigs, L)
            elif u < 0.15+0.40: base = ZIPF-PICK(rng, family_seeds, weights)[:L-1]
            else: base = b""
            s = base + RANDOM-BYTES(rng, mixture=BYTE_CLASS_MIXTURE, count=L-len(base))
            if s not in sigs: sigs.add(s)
        return sigs

This is a direct, faithful port of the scratch verification script (gen.py) that produced
Section 4.4's table -- the constants below (mu=ln(12), sigma=0.55, byte-class mixture weights,
p_deep=0.15, p_fam=0.40, fam_frac=0.05) are exactly the ones cited there, and this function MUST
reproduce that table bit-for-bit at seed=20260920 (see tests/test_sig_generator.py).
"""
from __future__ import annotations

import math

import numpy as np

DEFAULT_SEED = 20260920
MU = math.log(12)
SIGMA = 0.55
LMIN, LMAX = 4, 64
P_FAM = 0.40
FAM_FRAC = 0.05
P_DEEP = 0.15

_LETTERS = np.frombuffer(b"abcdefghijklmnopqrstuvwxyz", dtype=np.uint8)
_UPPER = np.frombuffer(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", dtype=np.uint8)
_DIGITS = np.frombuffer(b"0123456789", dtype=np.uint8)
_PUNCT = np.frombuffer(b"/.-_=:;%&?+()[]{}<>'\"\\,@!#$*", dtype=np.uint8)
_SPACE = np.array([32], dtype=np.uint8)

_CATS = [
    (0.55, _LETTERS),
    (0.10, _UPPER),
    (0.08, _DIGITS),
    (0.17, _PUNCT),
    (0.05, _SPACE),
    (0.05, None),  # arbitrary byte, 0-255
]
_CAT_PROBS = np.array([c[0] for c in _CATS])
_CAT_PROBS = _CAT_PROBS / _CAT_PROBS.sum()


def _rbytes(rng: np.random.Generator, n: int) -> bytes:
    out = bytearray()
    for c in rng.choice(len(_CATS), size=n, p=_CAT_PROBS):
        arr = _CATS[c][1]
        if arr is None:
            out.append(int(rng.integers(0, 256)))
        else:
            out.append(int(arr[rng.integers(0, len(arr))]))
    return bytes(out)


def _rlen(rng: np.random.Generator) -> int:
    return int(np.clip(round(rng.lognormal(MU, SIGMA)), LMIN, LMAX))


def gen_signatures(
    k: int,
    seed: int = DEFAULT_SEED,
    mu: float = MU,
    sigma: float = SIGMA,
    lmin: int = LMIN,
    lmax: int = LMAX,
    p_fam: float = P_FAM,
    fam_frac: float = FAM_FRAC,
    p_deep: float = P_DEEP,
) -> list[bytes]:
    """Deterministic given (k, seed, ...distribution params). MUST use numpy's default_rng
    (PCG64) -- pinning the RNG algorithm, not just the seed, is itself called out in
    IMPLEMENTATION.md Section 5 Module 5's edge cases as required for bit-for-bit reproducibility."""
    rng = np.random.default_rng(seed)

    fam_count = max(8, round(fam_frac * k))
    family_seeds = [_rbytes(rng, int(rng.integers(3, 13))) for _ in range(fam_count)]
    weights = 1.0 / np.arange(1, fam_count + 1)
    weights = weights / weights.sum()

    sigs: list[bytes] = []
    seen: set[bytes] = set()

    while len(sigs) < k:
        length = int(np.clip(round(rng.lognormal(mu, sigma)), lmin, lmax))
        u = rng.random()
        if sigs and u < p_deep:
            q = sigs[int(rng.integers(0, len(sigs)))]
            cut = int(rng.integers(max(1, len(q) // 2), len(q) + 1))
            base = q[: min(cut, length - 1)]
        elif u < p_deep + p_fam:
            fam_idx = int(rng.choice(fam_count, p=weights))
            base = family_seeds[fam_idx][: length - 1]
        else:
            base = b""
        s = base + _rbytes(rng, length - len(base))
        if s in seen:
            continue
        seen.add(s)
        sigs.append(s)

    return sigs


def trie_state_count(sigs: list[bytes]) -> int:
    """Fast check of the resulting trie size without building a full ACTrie -- counts distinct
    prefixes, which IS the trie state count by definition. Used for regression-testing Section
    4.4's table without paying the full build_trie+build_failure_links cost."""
    prefixes: set[bytes] = {b""}
    for s in sigs:
        for i in range(1, len(s) + 1):
            prefixes.add(s[:i])
    return len(prefixes)


def byte_class_count(sigs: list[bytes], fold_case: bool = True) -> int:
    used: set[int] = set()
    for s in sigs:
        for b in s:
            if fold_case and 65 <= b <= 90:
                b += 32
            used.add(b)
    return len(used) + 1  # +1 for the implicit "everything else" class in the AC scanner


if __name__ == "__main__":
    for k in (100, 300, 1000, 3000, 10000):
        sigs = gen_signatures(k)
        total = sum(len(s) for s in sigs)
        print(
            f"k={k:>6} sum|p|={total:>8} mean_len={total/k:5.1f} "
            f"trie_states={trie_state_count(sigs):>8} classes={byte_class_count(sigs)}"
        )
