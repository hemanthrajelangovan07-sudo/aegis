"""
LEX pseudocode from IMPLEMENTATION.md Section 5 Module 3:

    LEX(field_bytes, taint_mask):
        q = OUTSIDE; tokens = []; i = 0
        while i < len(field_bytes):
            q' = QUOTE-STEP(q, field_bytes[i])
            # ... standard maximal-munch tokenization, folding QUOTE-STEP into the STR-token
            # branch; every emitted token's `tainted` = OR of taint_mask over its source bytes
            q = q'; i += advance
        return tokens

Tokenizes into the terminal alphabet of sqli_engine.grammar (SELECT, FROM, IDENT, NUM, STR, ...).
Every token carries a `tainted` bit: True iff ANY source byte of that token came from a
user-controlled slot, per taint_mask. A lex error is itself a signal (Section 3 Component 5):
raised as LexError, never silently swallowed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .quote_dfa import QuoteState, quote_step

KEYWORDS = {
    w.upper()
    for w in (
        "ALL AND AS ASC BY CASE DELETE DESC DROP ELSE END EXISTS FROM GROUP "
        "HAVING IN INSERT INTO IS LIKE LIMIT NOT NULL OFFSET OR ORDER SELECT "
        "SET TABLE THEN UNION UPDATE VALUES WHEN WHERE"
    ).split()
}

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+|/\*.*?\*/)
    |(?P<TAIL_COMMENT>--.*|\#.*)
    |(?P<STR>'(?:[^'\\]|\\.|'')*')
    |(?P<UNTERMINATED_STR>')
    |(?P<NUM>0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)
    |(?P<IDENT>[A-Za-z_@][A-Za-z0-9_@$]*)
    |(?P<OP><=|>=|<>|!=|\|\||=|<|>|\+|-|\*|/|%|\(|\)|,|;|\.)
    """,
    re.VERBOSE | re.DOTALL,
)

_OP_NAMES = {
    "<=": "LE", ">=": "GE", "<>": "NE", "!=": "NE", "||": "CONCAT",
    "=": "EQ", "<": "LT", ">": "GT", "+": "PLUS", "-": "MINUS",
    "*": "STAR", "/": "SLASH", "%": "PCT", "(": "LPAREN", ")": "RPAREN",
    ",": "COMMA", ";": "SEMI", ".": "DOT",
}


class LexError(ValueError):
    def __init__(self, message: str, position: int):
        super().__init__(f"{message} at byte offset {position}")
        self.position = position


@dataclass
class Token:
    kind: str
    text: bytes
    tainted: bool
    start: int
    end: int


def lex(field_bytes: bytes, taint_mask: list[bool] | None = None) -> list[Token]:
    """taint_mask[i] = True iff field_bytes[i] came from a user-controlled slot. If omitted,
    defaults to "everything is tainted" (the conservative default for a value slot whose upstream
    provenance wasn't tracked byte-by-byte -- callers that DO have finer-grained provenance
    should always pass an explicit mask)."""
    if taint_mask is None:
        taint_mask = [True] * len(field_bytes)
    if len(taint_mask) != len(field_bytes):
        raise ValueError("taint_mask length must match field_bytes length")

    text = field_bytes.decode("latin-1")  # 1 char <-> 1 byte, preserves exact byte semantics
    tokens: list[Token] = []
    pos = 0
    quote_state = QuoteState.OUTSIDE

    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise LexError(f"unrecognized byte {field_bytes[pos]!r}", pos)
        kind = m.lastgroup
        raw = m.group()
        start, end = m.start(), m.end()

        # advance the quote-parity DFA across every consumed byte, regardless of token kind --
        # this is the "folding QUOTE-STEP into the main byte loop" the pseudocode specifies.
        for b in field_bytes[start:end]:
            quote_state = quote_step(quote_state, b)

        pos = end
        if kind == "ws":
            continue
        if kind == "UNTERMINATED_STR":
            raise LexError("unterminated string literal", start)

        tainted = any(taint_mask[start:end])

        if kind == "OP":
            tokens.append(Token(_OP_NAMES[raw], raw.encode("latin-1"), tainted, start, end))
        elif kind == "IDENT" and raw.upper() in KEYWORDS:
            tokens.append(Token(raw.upper(), raw.encode("latin-1"), tainted, start, end))
        else:
            tokens.append(Token(kind, raw.encode("latin-1"), tainted, start, end))

    return tokens


def lex_with_carry(
    prior_partial: bytes, new_bytes: bytes, taint_mask: list[bool], flush: bool = False
) -> tuple[list[Token], bytes]:
    """Cross-packet-safe lexing (Section 5 Module 4's LEX-WITH-CARRY): `prior_partial` is the
    tail of the previous packet's field bytes that did not yet form a complete token (e.g. a
    string literal opened but not yet closed). Concatenates, lexes, and if the LAST token in the
    stream abuts the end of `new_bytes` exactly (i.e. might still be extended by the next
    packet), holds it back as the new partial-token carry rather than emitting it prematurely.
    taint_mask covers `new_bytes` only; `prior_partial` is treated as already-tainted (it can
    only have come from a tainted value slot to begin with, by construction).

    `flush=True` signals this is the LAST chunk for this value slot (the flow/field has ended) --
    a trailing token that would otherwise be held back as ambiguous is instead emitted as final,
    since there is no next packet to extend it. Without this, a token that happens to land
    exactly at the end of the LAST packet of a flow would be held back forever and never reach
    the parser -- a real correctness gap, not just a formality."""
    combined = prior_partial + new_bytes
    combined_mask = [True] * len(prior_partial) + list(taint_mask)

    try:
        tokens = lex(combined, combined_mask)
    except LexError as e:
        if e.position >= len(prior_partial):
            # the failure is inside NEW bytes and could resolve once more bytes arrive next
            # packet (e.g. an unterminated string) -- treat everything from a safe resync point
            # onward as carry. Conservative: carry the whole combined buffer.
            if flush:
                raise  # nothing more is coming to resolve this -- a real error, surface it
            return [], combined
        raise

    if not tokens:
        return [], combined

    if flush:
        return tokens, b""

    last = tokens[-1]
    if last.end == len(combined):
        # last token touches the end of available bytes -- it MIGHT continue into the next
        # packet (can't be sure without a lookahead byte we don't have yet), so hold it back.
        return tokens[:-1], combined[last.start :]
    return tokens, b""
