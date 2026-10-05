"""Rule Loader & Regex Compiler (IMPLEMENTATION.md Module 2, Owner: Compiler Lead)."""
from .loader import ParsedRule, PositionalMods, load_rules, parse_rule, RuleSyntaxError
from .regex_ast import (
    RegexAST,
    RegexSyntaxError,
    classify_regex,
    contains_backreference,
    contains_nested_unbounded_quantifier,
    fold_case_ast,
    max_len,
    parse_regex,
)
from .thompson import NFA, thompson_construct
from .subset_construct import DFA, StateExplosionError, subset_construct
from .hopcroft import hopcroft_minimize
from .backref import DetBackrefNFA, compile_backref_rule, count_backreferences
from .verifier_bank import FallbackFlag, VerifierBank, compile_ruleset

__all__ = [
    "ParsedRule",
    "PositionalMods",
    "load_rules",
    "parse_rule",
    "RuleSyntaxError",
    "RegexAST",
    "RegexSyntaxError",
    "classify_regex",
    "contains_backreference",
    "contains_nested_unbounded_quantifier",
    "fold_case_ast",
    "max_len",
    "parse_regex",
    "NFA",
    "thompson_construct",
    "DFA",
    "StateExplosionError",
    "subset_construct",
    "hopcroft_minimize",
    "DetBackrefNFA",
    "compile_backref_rule",
    "count_backreferences",
    "FallbackFlag",
    "VerifierBank",
    "compile_ruleset",
]
