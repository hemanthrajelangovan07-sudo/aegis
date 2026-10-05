"""
VerifierBank + COMPILE-RULESET (IMPLEMENTATION.md Section 5 Module 2):

    COMPILE-RULESET(rules):
        for rule in rules:
            if rule.regex_body is None: continue
            cls = CLASSIFY-REGEX(rule.regex_body)
            if cls == REJECTED_UNBOUNDED:
                flag_for_fallback(rule.rule_id, reason="redos-risk"); continue
            if cls == DET_BACKREF:
                v = COMPILE-BACKREF(rule.regex_body, K_bound)
                if v is None: flag_for_fallback(rule.rule_id, reason="backref-K-exceeded"); continue
                bank.register(rule.rule_id, v); continue
            ast = PARSE-REGEX(rule.regex_body)
            nfa = THOMPSON(ast)
            mode = "anchored" if rule.fast_pattern is not None else "search_sticky"
            dfa = SUBSET-CONSTRUCT(nfa, mode)
            dfa = HOPCROFT-MINIMIZE(dfa)
            bank.register(rule.rule_id, dfa)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

from .backref import DetBackrefNFA, compile_backref_rule
from .hopcroft import hopcroft_minimize
from .loader import ParsedRule
from .regex_ast import classify_regex, fold_case_ast, parse_regex
from .subset_construct import DFA, StateExplosionError, subset_construct
from .thompson import thompson_construct

Verifier = Union[DFA, DetBackrefNFA]


@dataclass
class FallbackFlag:
    rule_id: int
    reason: str  # "no-content" | "redos-risk" | "backref-K-exceeded" | "state-explosion"


@dataclass
class VerifierBank:
    _verifiers: dict[int, Verifier] = field(default_factory=dict)

    def register(self, rule_id: int, verifier: Verifier) -> None:
        self._verifiers[rule_id] = verifier

    def get(self, rule_id: int) -> Verifier | None:
        return self._verifiers.get(rule_id)

    def __len__(self) -> int:
        return len(self._verifiers)


def compile_ruleset(
    rules: list[ParsedRule], k_bound: int = 1, subset_cap: int = 200_000
) -> tuple[VerifierBank, list[FallbackFlag]]:
    bank = VerifierBank()
    fallbacks: list[FallbackFlag] = []

    for rule in rules:
        if rule.regex_body is None:
            continue  # pure content rule, no verifier needed -- AC hit IS the verdict

        nocase = "i" in rule.regex_flags
        body = rule.regex_body

        cls = classify_regex(body, has_fast_pattern_anchor=rule.fast_pattern is not None)

        if cls == "REJECTED_UNBOUNDED":
            fallbacks.append(FallbackFlag(rule.rule_id, "redos-risk"))
            continue

        if cls == "DET_BACKREF":
            v = compile_backref_rule(body, k_bound=k_bound)
            if v is None:
                fallbacks.append(FallbackFlag(rule.rule_id, "backref-K-exceeded"))
                continue
            bank.register(rule.rule_id, v)
            continue

        try:
            ast = parse_regex(body)
            if nocase:
                ast = fold_case_ast(ast)
            nfa = thompson_construct(ast)
            mode = "anchored" if rule.fast_pattern is not None else "search_sticky"
            dfa = subset_construct(nfa, mode=mode, cap=subset_cap)
            dfa = hopcroft_minimize(dfa)
            bank.register(rule.rule_id, dfa)
        except StateExplosionError:
            fallbacks.append(FallbackFlag(rule.rule_id, "state-explosion"))

    for rule in rules:
        if rule.fast_pattern is None and rule.regex_body is None:
            fallbacks.append(FallbackFlag(rule.rule_id, "no-content"))

    return bank, fallbacks
