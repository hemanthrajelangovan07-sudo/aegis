"""
Quote-parity DFA (IMPLEMENTATION.md Section 2.5 point 1, Section 5 Module 3).

Matching balanced/escaped SQL string-literal quotes does NOT need a stack -- it is provably
finite-state: a 2-state DFA (outside-string / inside-string) toggling on an unescaped quote,
extended to at most 4 states to also absorb '' / \\' escape sequences, suffices, because SQL
string literals cannot contain recursive unescaped literals inside themselves (Section 2.5,
Section 7 "matched quotes vs stack" rebuttal). Folded into the lexer's main byte loop (lexer.py),
never a separate pass.
"""
from __future__ import annotations

from enum import IntEnum


class QuoteState(IntEnum):
    OUTSIDE = 0
    INSIDE = 1
    INSIDE_SAW_QUOTE = 2  # just saw a quote while inside -- could be end-of-string OR the start
    #                        of a doubled '' escape; resolved by the NEXT byte
    INSIDE_ESCAPE = 3  # just saw a backslash while inside -- next byte is escaped, unconditionally


_QUOTE = ord("'")
_DQUOTE = ord('"')
_BACKSLASH = ord("\\")


def quote_step(state: QuoteState, byte: int) -> QuoteState:
    """Pure transition function, O(1). Treats both ' and " as string delimiters (SQL dialects
    vary; the union is the conservative, safe choice for a detector)."""
    is_quote = byte in (_QUOTE, _DQUOTE)

    if state == QuoteState.OUTSIDE:
        return QuoteState.INSIDE if is_quote else QuoteState.OUTSIDE

    if state == QuoteState.INSIDE:
        if byte == _BACKSLASH:
            return QuoteState.INSIDE_ESCAPE
        if is_quote:
            return QuoteState.INSIDE_SAW_QUOTE
        return QuoteState.INSIDE

    if state == QuoteState.INSIDE_SAW_QUOTE:
        if is_quote:
            # doubled quote ('') -- SQL-standard escape, stay inside the string
            return QuoteState.INSIDE
        # the quote we saw really did end the string; re-process `byte` as if freshly OUTSIDE
        return quote_step(QuoteState.OUTSIDE, byte)

    if state == QuoteState.INSIDE_ESCAPE:
        # any byte immediately following a backslash is escaped, unconditionally back to INSIDE
        return QuoteState.INSIDE

    raise ValueError(f"unknown QuoteState {state!r}")


def quote_scan(data: bytes, start: QuoteState = QuoteState.OUTSIDE) -> QuoteState:
    """Convenience: run quote_step across a whole buffer, returning the final state (used both
    by tests and by Module 4's cross-packet partial-token carry, which persists this state
    alongside the raw partial-token bytes -- see pipeline/sqli_token_buffer.py)."""
    state = start
    for b in data:
        state = quote_step(state, b)
    return state
