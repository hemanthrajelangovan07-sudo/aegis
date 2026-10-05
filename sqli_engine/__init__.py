"""SQLi Lexer, Taint Tracker & DPDA Structural Recognizer
(IMPLEMENTATION.md Module 3, Owner: Scanner/Demo Lead)."""
from .quote_dfa import QuoteState, quote_step, quote_scan
from .lexer import Token, LexError, lex, lex_with_carry, KEYWORDS
from .grammar import GRAMMAR_TEXT, START_SYMBOL, load_productions, STRUCTURAL_SHAPES
from .gen_tables import GrammarTables, build_lr1, build_all, lalr_core_merge, check_no_unit_cycles
from .parser import SqliParser, SqliVerdict, SyntaxOrLexError

__all__ = [
    "QuoteState",
    "quote_step",
    "quote_scan",
    "Token",
    "LexError",
    "lex",
    "lex_with_carry",
    "KEYWORDS",
    "GRAMMAR_TEXT",
    "START_SYMBOL",
    "load_productions",
    "STRUCTURAL_SHAPES",
    "GrammarTables",
    "build_lr1",
    "build_all",
    "lalr_core_merge",
    "check_no_unit_cycles",
    "SqliParser",
    "SqliVerdict",
    "SyntaxOrLexError",
]
