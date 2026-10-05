from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rule_compiler import (
    DFA,
    classify_regex,
    compile_ruleset,
    contains_backreference,
    contains_nested_unbounded_quantifier,
    count_backreferences,
    compile_backref_rule,
    hopcroft_minimize,
    load_rules,
    parse_regex,
    subset_construct,
    thompson_construct,
)


def dfa_accepts(dfa: DFA, s: bytes) -> bool:
    state = 0
    for b in s:
        cls = None
        for i, group in enumerate(dfa.byte_classes):
            if b in group:
                cls = i
                break
        if cls is None:
            return False
        state = dfa.transitions[state][cls]
    return state in dfa.accepting


def dfa_search(dfa: DFA, s: bytes) -> bool:
    """search_sticky-mode DFAs are already "match anywhere"; scanning from state 0 across the
    whole string and checking whether any prefix landed in an accepting state is equivalent to
    asking dfa_accepts on the full string for a sticky automaton (since sticky absorbs)."""
    state = 0
    for b in s:
        cls = None
        for i, group in enumerate(dfa.byte_classes):
            if b in group:
                cls = i
                break
        if cls is None:
            return state in dfa.accepting
        state = dfa.transitions[state][cls]
        if state in dfa.accepting:
            return True
    return state in dfa.accepting


def compile_anchored(pattern: str) -> DFA:
    ast = parse_regex(pattern)
    nfa = thompson_construct(ast)
    dfa = subset_construct(nfa, mode="anchored")
    return hopcroft_minimize(dfa)


def compile_search_sticky(pattern: str, cap: int = 400_000) -> DFA:
    ast = parse_regex(pattern)
    nfa = thompson_construct(ast)
    dfa = subset_construct(nfa, mode="search_sticky", cap=cap)
    return hopcroft_minimize(dfa)


# ---------------------------------------------------------------------------
# Section 2.2 -- Thompson's construction bound |Q_N| <= 2r
# ---------------------------------------------------------------------------


def test_thompson_bound():
    ast = parse_regex("abc")  # r = 3 literal symbols
    nfa = thompson_construct(ast)
    assert nfa.n_states <= 2 * 3


# ---------------------------------------------------------------------------
# Section 5 Module 2 -- test_subset_textbook: (a|b)*abb, byte-oriented (Sigma=256)
# ---------------------------------------------------------------------------


def test_subset_textbook_language_correctness():
    dfa = compile_anchored("(a|b)*abb")
    for accepted in (b"abb", b"aabb", b"babb", b"ababb", b"aaaabb", b"bbbabb"):
        assert dfa_accepts(dfa, accepted), f"{accepted!r} should be accepted"
    for rejected in (b"ab", b"abbb"[:-1] + b"a", b"", b"abba", b"xabb"):
        assert not dfa_accepts(dfa, rejected), f"{rejected!r} should be rejected"


def test_subset_textbook_state_counts_full_byte_alphabet():
    """Over the FULL byte alphabet (Sigma=256, per Section 2.1), the minimal DFA for (a|b)*abb
    has exactly one MORE state than the textbook's restricted-Sigma={a,b} whiteboard example
    (Section 5 Module 2's viva walkthrough: 5 subset -> 4 minimal over {a,b} only) -- the extra
    state is the explicit dead/trap state every byte outside {a,b} must fall into, which a
    byte-oriented Sigma=256 automaton needs but a hand-drawn Sigma={a,b} whiteboard diagram
    omits by convention. Both are correct for their respective alphabets; this test pins the
    real engine's (Sigma=256) numbers."""
    ast = parse_regex("(a|b)*abb")
    nfa = thompson_construct(ast)
    dfa = subset_construct(nfa, mode="anchored")
    assert dfa.n_states == 6
    minimal = hopcroft_minimize(dfa)
    assert minimal.n_states == 5  # 4 (textbook, Sigma={a,b}) + 1 dead state


# ---------------------------------------------------------------------------
# Section 5 Module 2 -- test_hopcroft_bound_not_regex_length
# ---------------------------------------------------------------------------


def test_hopcroft_bound_not_regex_length():
    """Two regexes of very different source length r can have similar unminimized DFA size n
    (or vice versa) -- minimization cost tracks n, not r. We don't assert a specific big-O here
    (that's a citation, not a unit-testable property of one run) but we DO assert that the
    minimizer's behavior is a pure function of the DFA passed in, never of any regex-string
    argument -- guarding against ever reintroducing an r-based short-circuit."""
    import inspect

    sig = inspect.signature(hopcroft_minimize)
    params = list(sig.parameters)
    assert params == ["dfa"], "hopcroft_minimize must take only a DFA, never regex source/length"


# ---------------------------------------------------------------------------
# Section 5 Module 2 -- test_state_explosion_family: a.{n} in search+sticky mode
# ---------------------------------------------------------------------------


def test_state_explosion_family():
    # a.{n}b -- literal 'a', exactly n wildcard bytes, literal 'b' (Section 2.3 illustrative
    # family). NOT "a.{n}" alone -- the trailing anchor 'b' is what makes the minimal DFA need to
    # remember "how many of the last n bytes have I seen since the 'a'", giving 2^(n+1)+1 states.
    expected = {2: 9, 4: 33, 6: 129, 8: 513, 10: 2049, 11: 4097, 12: 8193}
    for n, exp in expected.items():
        dfa = compile_search_sticky(f"a.{{{n}}}b")
        assert dfa.n_states == exp, f"n={n}: got {dfa.n_states}, expected {exp}"


def test_gap_family_distance_within():
    expected = {(0, 8): 11, (4, 12): 35, (8, 12): 141, (8, 16): 139, (12, 16): 635}
    for (d, w), exp in expected.items():
        dfa = compile_search_sticky(f"A.{{{d},{w}}}B", cap=400_000)
        assert dfa.n_states == exp, f"(d,w)=({d},{w}): got {dfa.n_states}, expected {exp}"


# ---------------------------------------------------------------------------
# CLASSIFY-REGEX / ReDoS-class detection
# ---------------------------------------------------------------------------


def test_classify_rejects_nested_unbounded_quantifier():
    ast = parse_regex("(a+)+b")
    assert contains_nested_unbounded_quantifier(ast)
    assert classify_regex("(a+)+b", has_fast_pattern_anchor=False) == "REJECTED_UNBOUNDED"


def test_classify_accepts_ordinary_regex():
    assert classify_regex(r"UNION\s+SELECT", has_fast_pattern_anchor=True) == "REGULAR_ANCHORED"
    assert (
        classify_regex(r"UNION\s+SELECT", has_fast_pattern_anchor=False) == "REGULAR_NO_ANCHOR"
    )


def test_classify_detects_backreference():
    assert contains_backreference(r"(['\"]).*\1")
    assert classify_regex(r"(['\"]).*\1", has_fast_pattern_anchor=False) == "DET_BACKREF"


# ---------------------------------------------------------------------------
# Deterministic back-reference compiler (L=1 case)
# ---------------------------------------------------------------------------


def test_backref_count():
    assert count_backreferences(r"(a)\1") == 1
    assert count_backreferences(r"(a)(b)\1\2") == 2
    assert count_backreferences(r"abc") == 0


def test_backref_k_bound_exceeded_returns_none():
    assert compile_backref_rule(r"(a)(b)\1\2", k_bound=1) is None


def test_backref_quote_consistency_compiles_and_verifies():
    """Classic single-back-reference pattern: a quote character, captured, must reappear
    identically later (used to detect exact SQL quote-consistency violations). Namjoshi &
    Narlikar's L=1 decidable class -- Section 2.7, Section 6.2."""
    v = compile_backref_rule(r"(['\"])x\1", k_bound=1)
    assert v is not None
    assert v.live_backreferences == 1
    assert v.verify(b"'x'") is True
    assert v.verify(b'"x"') is True
    assert v.verify(b"'x\"") is False  # mismatched quote chars
    assert v.verify(b"xx") is False  # no quote at all


# ---------------------------------------------------------------------------
# Section 4.1 -- rule loader worked examples
# ---------------------------------------------------------------------------

RULE_TEXT_1 = (
    'alert tcp any any -> any 80 (msg:"HTTP GET to admin panel"; '
    'content:"GET"; offset:0; depth:3; '
    'content:"/index.html"; distance:1; within:20; sid:1000001;)'
)

RULE_TEXT_2 = (
    'alert tcp any any -> any 80 (msg:"SQLi UNION probe"; content:"UNION"; nocase; '
    'fast_pattern; pcre:"/UNION\\s+SELECT/i"; sid:1000002;)'
)

RULE_TEXT_3 = (
    'alert tcp any any -> any 80 (msg:"pathological nested quantifier"; '
    'pcre:"/(a+)+b/"; sid:1000003;)'
)


def test_loader_worked_example_1_longest_content_autoselected():
    rules = load_rules(RULE_TEXT_1)
    assert len(rules) == 1
    r = rules[0]
    assert r.rule_id == 1000001
    assert r.fast_pattern == b"/index.html"  # longer of the two contents, auto-selected
    assert r.regex_body is None
    assert r.positional_mods.distance == 1
    assert r.positional_mods.within == 20


def test_loader_worked_example_2_fast_pattern_override_plus_pcre():
    rules = load_rules(RULE_TEXT_2)
    r = rules[0]
    assert r.fast_pattern == b"UNION"
    assert r.regex_body == r"UNION\s+SELECT"
    assert r.regex_flags == "i"
    assert r.nocase is True


def test_loader_worked_example_3_no_content_routes_to_fallback():
    rules = load_rules(RULE_TEXT_3)
    r = rules[0]
    assert r.fast_pattern is None
    assert r.regex_body == "(a+)+b"


def test_loader_realistic_rule_with_passthrough_keywords_and_negated_content():
    """Regression test for a real gap found and fixed during hardening: the loader used to raise
    RuleSyntaxError on any keyword outside a tiny fixed set, which meant it couldn't even READ
    past the first line of most real Snort/Suricata rules (flow, reference, metadata, flowbits,
    http_* sticky buffers, etc. are all common). Now it parses these as passthrough metadata
    instead of crashing, and correctly excludes negated content from fast-pattern selection."""
    rules = load_rules(
        'alert tcp $EXTERNAL_NET any -> $HOME_NET [80,8080] '
        '(msg:"ET WEB SPECIFIC SQLi attempt"; flow:to_server,established; '
        'content:"UNION"; nocase; fast_pattern; content:!"benign_marker"; '
        'pcre:"/UNION\\s+SELECT/i"; reference:cve,2019-12345; '
        'classtype:web-application-attack; sid:2001234; rev:3; '
        'metadata:affected_product Web_Server;)'
    )
    r = rules[0]
    assert r.fast_pattern == b"UNION"  # negated content correctly excluded from selection
    assert r.unsupported_options["flow"] == "to_server,established"
    assert r.unsupported_options["reference"] == "cve,2019-12345"
    negated = {c.literal: c.negated for c in r.contents}
    assert negated[b"UNION"] is False
    assert negated[b"benign_marker"] is True


def test_loader_rule_with_only_negated_content_routes_to_fallback():
    rules = load_rules('alert tcp any any -> any 80 (msg:"t"; content:!"safe"; sid:42;)')
    r = rules[0]
    assert r.fast_pattern is None  # no positive content to anchor on -- correctly no-anchor


def test_compile_ruleset_worked_examples_end_to_end():
    rules = load_rules("\n".join([RULE_TEXT_1, RULE_TEXT_2, RULE_TEXT_3]))
    bank, fallbacks = compile_ruleset(rules)

    # rule 1: pure content, no verifier needed
    assert bank.get(1000001) is None

    # rule 2: UNION\s+SELECT (nocase) compiled to a real per-rule DFA, anchored mode since it
    # has a fast_pattern anchor
    v2 = bank.get(1000002)
    assert isinstance(v2, DFA)

    # rule 3: (a+)+b is REJECTED_UNBOUNDED -- never compiled, flagged for redos-risk fallback
    assert bank.get(1000003) is None
    reasons = {f.rule_id: f.reason for f in fallbacks}
    assert reasons[1000003] == "redos-risk"


def test_nocase_char_class_folding():
    """Regression test for a real bug found and fixed during hardening: nocase folding used to
    be a source-text rewrite that explicitly SKIPPED character classes, so `[a-z]+` under nocase
    never matched uppercase input. fold_case_ast operates on the parsed AST's actual byte-sets
    instead, which is correct for classes, escapes, and literals uniformly."""
    from rule_compiler.regex_ast import fold_case_ast

    ast = parse_regex("[a-z]+")
    folded = fold_case_ast(ast)
    nfa = thompson_construct(folded)
    dfa = subset_construct(nfa, mode="search_sticky")
    minimal = hopcroft_minimize(dfa)

    def matches(dfa, s: bytes) -> bool:
        state = 0
        for b in s:
            cls = None
            for i, group in enumerate(dfa.byte_classes):
                if b in group:
                    cls = i
                    break
            if cls is None:
                return state in dfa.accepting
            state = dfa.transitions[state][cls]
            if state in dfa.accepting:
                return True
        return state in dfa.accepting

    assert matches(minimal, b"abc")
    assert matches(minimal, b"ABC")  # this is exactly what was broken before the fix
    assert matches(minimal, b"AbC")


def test_compile_ruleset_nocase_end_to_end():
    """End-to-end: a nocase pcre rule with a character class must match uppercase input through
    the full compile_ruleset -> VerifierBank -> verify() path, not just the AST-level unit test
    above."""
    rules = load_rules(
        'alert tcp any any -> any 80 (msg:"t"; content:"X"; fast_pattern; '
        'pcre:"/[a-z]+/i"; sid:9999;)'
    )
    bank, fallbacks = compile_ruleset(rules)
    verifier = bank.get(9999)
    assert verifier is not None
    assert dfa_accepts(verifier, b"ABC")
    assert dfa_accepts(verifier, b"abc")


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
