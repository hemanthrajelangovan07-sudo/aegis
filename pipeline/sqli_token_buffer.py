"""
Cross-packet partial-token carry for the SQLi lexer (IMPLEMENTATION.md Section 5 Module 4 file
layout: pipeline/sqli_token_buffer.py). Thin wrapper around sqli_engine.lexer.lex_with_carry.

Design note: lex_with_carry's strategy is "carry the undigested tail bytes forward and re-lex the
concatenated buffer from scratch next packet" rather than "persist an explicit QuoteState and
resume the DFA mid-token." Both achieve the same correctness property (a token split across a
packet boundary, including one that splits mid-quoted-string, is still tokenized identically to
having seen it in one contiguous buffer) because the quote-parity DFA (Section 2.5 point 1) is
cheap enough to simply re-run over the short carried tail each time -- there is no need to
persist its intermediate state separately. PartialTokenState below still exposes the QuoteState
explicitly (computed on demand from the carried bytes) so callers/tests can inspect it directly,
matching the spec's stated edge case ("the lexer state, not just the raw bytes, must be part of
what's carried") at the OBSERVABLE level, even though the implementation strategy is whole-buffer
re-lex rather than incremental state resumption.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqli_engine.lexer import Token, lex_with_carry
from sqli_engine.quote_dfa import QuoteState, quote_scan


@dataclass
class PartialTokenState:
    partial_bytes: bytes
    quote_state: QuoteState

    @classmethod
    def empty(cls) -> "PartialTokenState":
        return cls(partial_bytes=b"", quote_state=QuoteState.OUTSIDE)


def lex_slot_with_carry(
    prior: PartialTokenState, new_bytes: bytes, taint_mask: list[bool], flush: bool = False
) -> tuple[list[Token], PartialTokenState]:
    tokens, remainder = lex_with_carry(prior.partial_bytes, new_bytes, taint_mask, flush=flush)
    new_quote_state = quote_scan(remainder)
    return tokens, PartialTokenState(partial_bytes=remainder, quote_state=new_quote_state)
