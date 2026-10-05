"""
The SQLi grammar (IMPLEMENTATION.md Section 2.6): 104 productions, 37 nonterminals, 56 terminals,
start symbol Script. This is the EXACT grammar text from the spec document -- do not hand-edit
without re-running gen_tables.py's conflict check (test_grammar_conflict_free_lr1/lalr1 in
tests/test_grammar_tables_conflict_free.py) and updating IMPLEMENTATION.md Section 2.6 to match.
"""
from __future__ import annotations

GRAMMAR_TEXT = r"""
Script     : StmtList | StmtList TAIL_COMMENT
StmtList   : Stmt | StmtList SEMI Stmt | StmtList SEMI
Stmt       : QueryExpr | DROP TABLE IDENT | DELETE FROM QName | DELETE FROM QName WhereClause | INSERT INTO QName VALUES LPAREN ExprList RPAREN | UPDATE QName SET SetList | UPDATE QName SET SetList WhereClause
SetList    : SetItem | SetList COMMA SetItem
SetItem    : QName EQ Expr
QueryExpr  : SelectCore | QueryExpr UNION SelectCore | QueryExpr UNION ALL SelectCore
SelectCore : SelectHead | SelectHead ClauseList
SelectHead : SELECT SelList | SELECT SelList FromClause
SelList    : SelItem | SelList COMMA SelItem
SelItem    : STAR | Expr | Expr AS IDENT
FromClause : FROM TableList
TableList  : TableRef | TableList COMMA TableRef
TableRef   : QName | QName IDENT | QName AS IDENT | LPAREN QueryExpr RPAREN IDENT | LPAREN QueryExpr RPAREN AS IDENT
ClauseList : Clause | ClauseList Clause
Clause     : WhereClause | GroupClause | HavingClause | OrderClause | LimitClause
WhereClause: WHERE Expr
GroupClause: GROUP BY ExprList
HavingClause: HAVING Expr
OrderClause: ORDER BY OrderList
OrderList  : OrderItem | OrderList COMMA OrderItem
OrderItem  : Expr | Expr ASC | Expr DESC
LimitClause: LIMIT NUM | LIMIT NUM COMMA NUM | LIMIT NUM OFFSET NUM
Expr       : OrExpr
OrExpr     : AndExpr | OrExpr OR AndExpr
AndExpr    : NotExpr | AndExpr AND NotExpr
NotExpr    : CmpExpr | NOT NotExpr
CmpExpr    : AddExpr | AddExpr CmpOp AddExpr | AddExpr IN LPAREN ExprList RPAREN | AddExpr IN LPAREN QueryExpr RPAREN | AddExpr LIKE AddExpr | AddExpr IS NULL | AddExpr IS NOT NULL
CmpOp      : EQ | NE | LT | GT | LE | GE
AddExpr    : MulExpr | AddExpr AddOp MulExpr
AddOp      : PLUS | MINUS | CONCAT
MulExpr    : UnExpr | MulExpr MulOp UnExpr
MulOp      : STAR | SLASH | PCT
UnExpr     : Primary | MINUS UnExpr
Primary    : NUM | STR | NULL | QName | QName LPAREN RPAREN | QName LPAREN STAR RPAREN | QName LPAREN ExprList RPAREN | LPAREN Expr RPAREN | LPAREN QueryExpr RPAREN | EXISTS LPAREN QueryExpr RPAREN | CASE WhenList END | CASE WhenList ELSE Expr END
WhenList   : WHEN Expr THEN Expr | WhenList WHEN Expr THEN Expr
ExprList   : Expr | ExprList COMMA Expr
QName      : IDENT | QName DOT IDENT
"""

START_SYMBOL = "Script"


def load_productions(text: str = GRAMMAR_TEXT) -> list[tuple[str, tuple[str, ...]]]:
    """Parses the pipe-delimited grammar text above into (lhs, rhs) production tuples."""
    prods: list[tuple[str, tuple[str, ...]]] = []
    for line in text.strip().splitlines():
        lhs, _, rhs = line.partition(":")
        lhs = lhs.strip()
        for alt in rhs.split("|"):
            symbols = tuple(alt.split())
            prods.append((lhs, symbols))
    return prods


def nonterminals(prods: list[tuple[str, tuple[str, ...]]]) -> set[str]:
    return {lhs for lhs, _ in prods}


def terminals(prods: list[tuple[str, tuple[str, ...]]]) -> set[str]:
    nts = nonterminals(prods)
    return {sym for _, rhs in prods for sym in rhs if sym not in nts}


# The STRUCTURAL productions the decision predicate (Section 2.6, Section 5 Module 3) latches on:
# UNION chaining, statement stacking (;), nested-subquery parenthesisation, boolean OR/AND
# chaining, and trailing-comment truncation. Identified here by (lhs, rhs) shape so the index can
# be resolved against whichever production-numbering gen_tables.py assigns (production ORDER is
# an implementation detail of the LR table generator, not part of the grammar's meaning).
STRUCTURAL_SHAPES: set[tuple[str, tuple[str, ...]]] = {
    ("QueryExpr", ("QueryExpr", "UNION", "SelectCore")),
    ("QueryExpr", ("QueryExpr", "UNION", "ALL", "SelectCore")),
    ("StmtList", ("StmtList", "SEMI", "Stmt")),
    ("TableRef", ("LPAREN", "QueryExpr", "RPAREN", "IDENT")),
    ("TableRef", ("LPAREN", "QueryExpr", "RPAREN", "AS", "IDENT")),
    ("Primary", ("LPAREN", "QueryExpr", "RPAREN")),
    ("CmpExpr", ("AddExpr", "IN", "LPAREN", "QueryExpr", "RPAREN")),
    ("OrExpr", ("OrExpr", "OR", "AndExpr")),
    ("AndExpr", ("AndExpr", "AND", "NotExpr")),
    ("Script", ("StmtList", "TAIL_COMMENT")),
}


def structural_production_indices(prods: list[tuple[str, tuple[str, ...]]]) -> frozenset[int]:
    """Maps STRUCTURAL_SHAPES onto indices into `prods` (0-indexed, matching whatever list
    gen_tables.py was given -- callers pass the SAME prods list used to build the LR tables)."""
    return frozenset(i for i, p in enumerate(prods) if p in STRUCTURAL_SHAPES)
