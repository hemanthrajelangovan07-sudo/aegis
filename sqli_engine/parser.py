"""
PARSE pseudocode from IMPLEMENTATION.md Section 5 Module 3:

    PARSE(tokens):
        stack = [(state=0, tainted=False)]
        trace = []; latch = None
        tokens = tokens + [EOF]
        loop:
            s = stack[-1].state; a = tokens[i].kind
            action = ACTION[s][a]
            if action == SHIFT(t): stack.push((t, tokens[i].tainted)); i += 1
            elif action == REDUCE(prod):
                l, r = PRODUCTIONS[prod]; m = len(r)
                popped = stack[-m:]; pivot_tainted = OR(entry.tainted for entry in popped)
                del stack[-m:]
                trace.append(f"{l} -> {' '.join(r)}")
                if prod in STRUCTURAL_PRODUCTIONS and pivot_tainted and latch is None:
                    latch = current_input_position
                stack.push((GOTO[stack[-1].state][l], tainted=False))
            elif action == ACCEPT: return SqliVerdict(...)
            else: return LEX_OR_SYNTAX_ERROR

O(n) in token count -- one shift or reduce per loop iteration, each consuming or producing
exactly one stack entry, standard LR-parsing linear-time argument (Section 2.6).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .gen_tables import GrammarTables, build_all
from .grammar import structural_production_indices
from .lexer import Token

EOF = "$"


@dataclass
class SqliVerdict:
    is_attack: bool
    production_trace: list[str]
    taint_latch_position: int | None
    stack_snapshot: list[tuple[int, bool]] | None = None  # for cross-packet resumption (Module 4)


class SyntaxOrLexError(ValueError):
    pass


@dataclass
class SqliParser:
    """Wraps a compiled GrammarTables + the STRUCTURAL_PRODUCTIONS index set. Built once at
    startup (gen_tables.py's construction cost, ~0.3s for the full grammar, is NOT paid per
    packet -- see Section 5 Module 3's file-layout note distinguishing gen_tables.py from the
    runtime parser.py path)."""

    tables: GrammarTables
    structural: frozenset[int]

    @classmethod
    def build(cls, use_lalr: bool = True) -> "SqliParser":
        prods, canonical, lalr, cycles = build_all()
        if cycles:
            raise RuntimeError(f"grammar has unit-production cycles: {cycles}")
        tables = lalr if use_lalr else canonical
        if tables.conflicts:
            raise RuntimeError(f"grammar table has {len(tables.conflicts)} conflicts")
        # IMPORTANT: structural indices must be computed against tables.productions (the
        # AUGMENTED list, index 0 = S' -> Script), because that is what `prod_idx` in the
        # parse loop actually indexes into -- NOT the raw `prods` list from build_all(), which
        # is unaugmented and therefore off by one relative to every reduce action's prod_idx.
        structural = structural_production_indices(tables.productions)
        return cls(tables=tables, structural=structural)

    def parse(
        self,
        tokens: list[Token],
        resume_stack: list[tuple[int, bool]] | None = None,
        stop_on_error: bool = False,
    ) -> SqliVerdict:
        stack: list[tuple[int, bool]] = list(resume_stack) if resume_stack else [(0, False)]
        trace: list[str] = []
        latch: int | None = None

        stream = list(tokens) + [Token(EOF, b"", False, -1, -1)]
        i = 0
        while True:
            state = stack[-1][0]
            a = stream[i].kind
            act = self.tables.action.get((state, a))
            if act is None:
                if stop_on_error:
                    raise SyntaxOrLexError(
                        f"no ACTION for state={state}, lookahead={a!r} at token {i}"
                    )
                return SqliVerdict(
                    is_attack=(latch is not None),
                    production_trace=trace,
                    taint_latch_position=latch,
                    stack_snapshot=stack,
                )

            kind = act[0]
            if kind == "s":
                stack.append((act[1], stream[i].tainted))
                i += 1
            elif kind == "r":
                prod_idx = act[1]
                lhs, rhs = self.tables.productions[prod_idx]
                m = len(rhs)
                popped = stack[-m:] if m else []
                pivot_tainted = any(entry[1] for entry in popped)
                if m:
                    del stack[-m:]
                trace.append(f"{lhs} -> {' '.join(rhs)}")
                if prod_idx in self.structural and pivot_tainted and latch is None:
                    latch = i
                goto_state = self.tables.goto[(stack[-1][0], lhs)]
                stack.append((goto_state, False))  # nonterminals carry no taint of their own
            elif kind == "acc":
                return SqliVerdict(
                    is_attack=(latch is not None),
                    production_trace=trace,
                    taint_latch_position=latch,
                    stack_snapshot=stack,
                )
            else:
                raise RuntimeError(f"unknown action kind {kind!r}")
