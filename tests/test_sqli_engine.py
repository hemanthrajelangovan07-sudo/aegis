from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqli_engine import (
    QuoteState,
    SqliParser,
    build_all,
    lex,
    quote_scan,
    quote_step,
)


def test_grammar_conflict_free_lr1():
    prods, canonical, lalr, cycles = build_all()
    assert len(prods) == 104
    assert len(canonical.states) == 1689
    assert len(canonical.conflicts) == 0


def test_grammar_conflict_free_lalr1():
    prods, canonical, lalr, cycles = build_all()
    assert len(lalr.states) == 179
    assert len(lalr.conflicts) == 0


def test_no_unit_cycles():
    prods, canonical, lalr, cycles = build_all()
    assert cycles == []


def test_quote_dfa_escape():
    # A closing quote that ends the buffer lands in INSIDE_SAW_QUOTE, not OUTSIDE -- the DFA
    # cannot yet know whether the NEXT byte (not present here) would be another quote (extending
    # the string via a doubled-quote escape) or something else (truly closing it). This is
    # correct, deliberate streaming behavior (Section 5 Module 4's cross-packet partial-token
    # carry relies on exactly this ambiguity being preserved, not resolved early) -- so these
    # tests append one trailing delimiter byte to force resolution, as a real tokenizer would
    # always have (a comma, paren, or end of statement) after a string literal.
    s1 = quote_scan(b"'O''Brien' ")  # doubled-quote escape inside a string, then a space
    assert s1 == QuoteState.OUTSIDE
    s2 = quote_scan(b"'it\\'s' ")  # backslash-escaped quote inside a string, then a space
    assert s2 == QuoteState.OUTSIDE
    # a truly unterminated string ends INSIDE
    s3 = quote_scan(b"'unterminated")
    assert s3 == QuoteState.INSIDE
    # a quote that is the very last byte of a chunk is "pending close" -- exactly the state
    # Module 4's cross-packet carry must persist rather than discard
    s4 = quote_scan(b"'closed'")
    assert s4 == QuoteState.INSIDE_SAW_QUOTE


def test_lexer_basic_tainted():
    tokens = lex(b"SELECT * FROM t", taint_mask=[False] * 15)
    kinds = [t.kind for t in tokens]
    assert kinds == ["SELECT", "STAR", "FROM", "IDENT"]
    assert all(not t.tainted for t in tokens)


def test_lexer_taint_propagation():
    payload = b"1 UNION SELECT a FROM b"
    # only bytes 2..23 (" UNION SELECT a FROM b") are "user-controlled" in this synthetic example
    mask = [i >= 2 for i in range(len(payload))]
    tokens = lex(payload, taint_mask=mask)
    assert tokens[0].kind == "NUM" and tokens[0].tainted is False
    union_tok = next(t for t in tokens if t.kind == "UNION")
    assert union_tok.tainted is True


_PARSER = SqliParser.build(use_lalr=True)


def _tainted_lex(static_prefix: str, tainted_suffix: str):
    payload = (static_prefix + tainted_suffix).encode()
    mask = [False] * len(static_prefix) + [True] * len(tainted_suffix)
    return lex(payload, taint_mask=mask)


def test_decision_predicate_union_injection():
    # static template: "SELECT * FROM t WHERE id = " ; attacker-controlled: "1 UNION SELECT a FROM b"
    tokens = _tainted_lex("SELECT * FROM t WHERE id = ", "1 UNION SELECT a FROM b")
    v = _PARSER.parse(tokens, stop_on_error=True)
    assert v.is_attack is True
    assert any("UNION" in step for step in v.production_trace)


def test_decision_predicate_or_injection():
    tokens = _tainted_lex("SELECT * FROM t WHERE name = ", "'x' OR 'a'='a'")
    v = _PARSER.parse(tokens, stop_on_error=True)
    assert v.is_attack is True
    assert any(step.startswith("OrExpr -> OrExpr OR") for step in v.production_trace)


def test_decision_predicate_benign_parens_arithmetic():
    # entirely static query using a parenthesised scalar expression -- Primary -> LPAREN Expr
    # RPAREN is NOT a structural production, so this must never latch even though it's fully
    # tainted.
    tokens = _tainted_lex("", "SELECT (1+2)*3")
    v = _PARSER.parse(tokens, stop_on_error=True)
    assert v.is_attack is False


def test_decision_predicate_benign_static_nested_subquery():
    # the ENTIRE nested subquery is static template SQL; only a leaf numeric literal deep inside
    # is tainted, and that literal never itself touches a structural production.
    static_query = "SELECT * FROM t WHERE id IN (SELECT id FROM u WHERE flag = "
    tokens = _tainted_lex(static_query, "42")
    tokens += lex(b")", taint_mask=[False])
    v = _PARSER.parse(tokens, stop_on_error=True)
    assert v.is_attack is False


def test_decision_predicate_benign_all_static():
    payload = b"SELECT id FROM users WHERE id = 5"
    tokens = lex(payload, taint_mask=[False] * len(payload))
    v = _PARSER.parse(tokens, stop_on_error=True)
    assert v.is_attack is False


def test_decision_predicate_comment_truncation():
    tokens = _tainted_lex("SELECT * FROM users WHERE name = '", "admin'--")
    v = _PARSER.parse(tokens, stop_on_error=True)
    assert v.is_attack is True
    assert any("TAIL_COMMENT" in step for step in v.production_trace)


def test_decision_predicate_stacked_query():
    tokens = _tainted_lex("SELECT 1", "; DROP TABLE users")
    v = _PARSER.parse(tokens, stop_on_error=True)
    assert v.is_attack is True
    assert any(step.startswith("StmtList -> StmtList SEMI") for step in v.production_trace)


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
