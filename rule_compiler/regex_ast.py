"""
Regex subset parser -> AST, and rule classification (IMPLEMENTATION.md Section 2.6, Section 5
Module 2). Supported subset (Section 5 Module 2 / Section 2.6): concatenation, union (|), literal
bytes, character classes ([...], \\d \\w \\s and negations), bounded wildcards (.), Kleene closure
(*), plus (+), optional (?), and bounded repetition ({m,n}). Excluded: back-references (handled
separately by backref.py, never reach this parser) and unbounded-nested-quantifier constructs are
detected here and flagged, not silently compiled (see classify_regex).

This is a direct, cleaned-up port of the scratch verification parser (rx_check.py) used to derive
every regex-pipeline number in IMPLEMENTATION.md Section 2 and Section 5 Module 2.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Union

ALL_BYTES = frozenset(range(256))

# AST node shapes (tuples, matching the scratch verification code's representation 1:1 so the
# thompson/subset/hopcroft modules below need no translation layer):
#   ("set", frozenset[int])
#   ("cat", node, node)
#   ("alt", node, node)
#   ("star", node)
#   ("plus", node)
#   ("opt", node)
#   ("rep", node, m:int, n:int|None)
RegexAST = tuple


class RegexSyntaxError(ValueError):
    pass


def _esc_set(c: str) -> frozenset[int]:
    if c == "d":
        return frozenset(range(48, 58))
    if c == "D":
        return ALL_BYTES - frozenset(range(48, 58))
    if c == "s":
        return frozenset(b" \t\r\n\x0b\x0c")
    if c == "S":
        return ALL_BYTES - frozenset(b" \t\r\n\x0b\x0c")
    if c == "w":
        return frozenset(
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
        )
    if c == "n":
        return frozenset([10])
    if c == "r":
        return frozenset([13])
    if c == "t":
        return frozenset([9])
    return frozenset([ord(c)])


def parse_regex(rx: str) -> RegexAST:
    """Recursive-descent parser for the supported subset. Raises RegexSyntaxError on anything
    outside the subset (e.g. back-references \\1 -- those are recognized upstream by
    classify_regex/backref.py and never reach here)."""
    pos = 0

    def peek() -> str | None:
        return rx[pos] if pos < len(rx) else None

    def eat() -> str:
        nonlocal pos
        c = rx[pos]
        pos += 1
        return c

    def alt() -> RegexAST:
        node = cat()
        while peek() == "|":
            eat()
            node = ("alt", node, cat())
        return node

    def cat() -> RegexAST:
        items = []
        while peek() not in (None, "|", ")"):
            items.append(rep())
        if not items:
            raise RegexSyntaxError(f"empty concatenation at position {pos} in {rx!r}")
        node = items[0]
        for x in items[1:]:
            node = ("cat", node, x)
        return node

    def rep() -> RegexAST:
        a = atom()
        while peek() in ("*", "+", "?", "{"):
            c = eat()
            if c == "*":
                a = ("star", a)
            elif c == "+":
                a = ("plus", a)
            elif c == "?":
                a = ("opt", a)
            else:
                nonlocal pos
                j = rx.index("}", pos)
                body = rx[pos:j]
                pos = j + 1
                if "," in body:
                    m_s, n_s = body.split(",")
                    m = int(m_s)
                    n = None if n_s == "" else int(n_s)
                else:
                    m = n = int(body)
                a = ("rep", a, m, n)
        return a

    def atom() -> RegexAST:
        c = eat()
        if c == "(":
            node = alt()
            if eat() != ")":
                raise RegexSyntaxError(f"unbalanced parens in {rx!r}")
            return node
        if c == ".":
            return ("set", ALL_BYTES)
        if c == "[":
            neg = False
            if peek() == "^":
                eat()
                neg = True
            s: set[int] = set()
            first = True
            while peek() != "]" or first:
                first = False
                if peek() is None:
                    raise RegexSyntaxError(f"unterminated char class in {rx!r}")
                ch = eat()
                if ch == "\\":
                    s |= _esc_set(eat())
                    continue
                if peek() == "-" and pos + 1 < len(rx) and rx[pos + 1] != "]":
                    eat()
                    hi = eat()
                    s |= set(range(ord(ch), ord(hi) + 1))
                else:
                    s.add(ord(ch))
            eat()  # consume ']'
            return ("set", (ALL_BYTES - frozenset(s)) if neg else frozenset(s))
        if c == "\\":
            return ("set", _esc_set(eat()))
        return ("set", frozenset([ord(c)]))

    result = alt()
    if pos != len(rx):
        raise RegexSyntaxError(f"trailing input {rx[pos:]!r} in {rx!r}")
    return result


def max_len(n: RegexAST) -> float:
    """Upper bound on matched-string length; float('inf') for unbounded repetition. Used by
    classify_regex to help decide fallback routing, and referenced in Section 2.2's discussion
    of bounded-vs-unbounded constructs."""
    t = n[0]
    if t == "set":
        return 1
    if t == "cat":
        return max_len(n[1]) + max_len(n[2])
    if t == "alt":
        return max(max_len(n[1]), max_len(n[2]))
    if t in ("star", "plus"):
        return float("inf") if max_len(n[1]) > 0 else 0
    if t == "opt":
        return max_len(n[1])
    if t == "rep":
        _, x, m, hi = n
        return float("inf") if hi is None else hi * max_len(x)
    raise ValueError(f"unknown node type {t!r}")


def _is_unbounded(n: RegexAST) -> bool:
    t = n[0]
    if t in ("star", "plus"):
        return True
    if t == "rep":
        return n[3] is None
    return False


def contains_nested_unbounded_quantifier(n: RegexAST) -> bool:
    """Detects the (a+)+ / ((a|b)*)* ReDoS-class shape: an unbounded-repetition node whose body
    itself contains another unbounded-repetition node. This is exactly the construct
    IMPLEMENTATION.md Section 5 Module 2's CLASSIFY-REGEX flags as REJECTED_UNBOUNDED -- never
    fed to subset_construct (Section 2.3's exponential worst case), routed to the no-anchor
    fallback with a ReDoS-risk flag instead (Section 3 Component 4, RDP-1)."""

    def _contains_any_unbounded(n: RegexAST) -> bool:
        t = n[0]
        if t == "set":
            return False
        if _is_unbounded(n):
            return True
        if t in ("cat", "alt"):
            return _contains_any_unbounded(n[1]) or _contains_any_unbounded(n[2])
        if t in ("star", "plus", "opt", "rep"):
            return _contains_any_unbounded(n[1])
        return False

    def walk(n: RegexAST) -> bool:
        t = n[0]
        if t == "set":
            return False
        if t in ("star", "plus") or (t == "rep" and n[3] is None):
            body = n[1]
            if _contains_any_unbounded(body):
                return True
        children = [c for c in n[1:] if isinstance(c, tuple)]
        return any(walk(c) for c in children)

    return walk(n)


def contains_backreference(source: str) -> bool:
    """Back-references (\\1, \\2, ...) are lexically detected on the RAW SOURCE STRING, before
    parsing, because the parser above does not (and per Section 2.6/Section 5 Module 2's
    architecture, must not) attempt to parse them as part of the regular subset -- a
    back-reference makes the language context-sensitive (Section 2.7), so it is routed to
    backref.py's separate extended-NFA + static-liveness path, never to parse_regex/thompson."""
    i = 0
    while i < len(source):
        if source[i] == "\\" and i + 1 < len(source) and source[i + 1].isdigit():
            return True
        i += 1
    return False


RegexClass = Literal[
    "REGULAR_ANCHORED", "REGULAR_NO_ANCHOR", "DET_BACKREF", "REJECTED_UNBOUNDED"
]


def classify_regex(body: str, has_fast_pattern_anchor: bool) -> RegexClass:
    """CLASSIFY-REGEX from IMPLEMENTATION.md Section 5 Module 2. Order matters: back-reference
    detection happens on the raw source (parser cannot see back-refs at all), THEN unbounded-
    nesting detection on the parsed AST of the (necessarily back-ref-free) remainder."""
    if contains_backreference(body):
        return "DET_BACKREF"
    ast = parse_regex(body)
    if contains_nested_unbounded_quantifier(ast):
        return "REJECTED_UNBOUNDED"
    return "REGULAR_ANCHORED" if has_fast_pattern_anchor else "REGULAR_NO_ANCHOR"


def fold_case_ast(ast: RegexAST) -> RegexAST:
    """Case-insensitive folding applied to the PARSED AST, not the regex source text (Section 5
    Module 2's "case-insensitive flag folding applied before Thompson construction" edge case).
    Operating on the AST's actual byte-sets, rather than textually rewriting the regex source, is
    what makes this correct for character classes: `[a-z]+` under nocase must become a byte-set
    containing both cases at the ("set", frozenset) node -- a source-text rewrite that special-
    cases and skips `[...]` blocks (an earlier, buggier version of this fold) cannot do that
    without a real bracket-range parser; walking the already-parsed AST sidesteps the problem
    entirely, since by the time we see a `("set", S)` node, S is already the fully-resolved byte
    set regardless of whether it came from a literal char, \\d/\\w/\\s, or a `[...]` class."""
    t = ast[0]
    if t == "set":
        bytes_set = set(ast[1])
        for b in list(bytes_set):
            if 65 <= b <= 90:  # A-Z
                bytes_set.add(b + 32)
            elif 97 <= b <= 122:  # a-z
                bytes_set.add(b - 32)
        return ("set", frozenset(bytes_set))
    if t in ("cat", "alt"):
        return (t, fold_case_ast(ast[1]), fold_case_ast(ast[2]))
    if t in ("star", "plus", "opt"):
        return (t, fold_case_ast(ast[1]))
    if t == "rep":
        return ("rep", fold_case_ast(ast[1]), ast[2], ast[3])
    raise ValueError(f"unknown AST node {t!r}")
