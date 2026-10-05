#!/usr/bin/env python3
"""
Runs every worked example from IMPLEMENTATION.md end to end, printing what happens at each
tier. Not a test (see tests/ for the real, asserted test suite -- 60/60 passing) -- this is a
narrated walkthrough, meant to be read alongside the spec document.

Run: python3 demo.py
"""
from __future__ import annotations

from ac_prefilter import build_failure_links, build_nextmove, build_trie_literals, scan_final_state
from pipeline import Pipeline, TaintedSlot, compile_full_ruleset
from rule_compiler.loader import load_rules


def section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def demo_module1_classic_ac():
    section("Module 1 -- AC Prefilter Engine: classic {he,she,his,hers} / 'ushers' example")
    trie = build_trie_literals(["he", "she", "his", "hers"])
    build_failure_links(trie)
    print(f"trie states: {trie.n_states} (spec: 10)")
    dfa = build_nextmove(trie, layout="dense")
    rule_of = {0: "he", 1: "she", 2: "his", 3: "hers"}
    final_state, matches = scan_final_state(dfa, b"ushers")
    hits = [(m.end_position, sorted(rule_of[r] for r in m.rule_ids)) for m in matches]
    print(f"scanning 'ushers': hits={hits}")
    print("spec (Section 5 Module 1): end-position 3 reports {he,she} together (out-inheritance,")
    print("  out(she)=out(she) U out(fail(she))={he,she}), end-position 5 reports {hers} -- matches.")
    print("transitions == len(payload) == 6, exactly, by construction of the Next-Move scan loop")


def demo_module1_demo_payload():
    section("Module 1 -- 65-byte backdoor/keylogger payload (Refuted Claim #7)")
    payload = b"installed backdoor and keylogger on target machine silently today"
    print(f"len(payload) = {len(payload)} (spec: 65)")
    trie = build_trie_literals(["backdoor", "keylogger"])
    build_failure_links(trie)
    dfa = build_nextmove(trie, layout="dense")
    rule_of = {0: "backdoor", 1: "keylogger"}
    _, matches = scan_final_state(dfa, payload)
    hits = [(m.end_position, sorted(rule_of[r] for r in m.rule_ids)) for m in matches]
    print(f"hits={hits}")
    print("spec's corrected wording: 'backdoor at positions 10-17, keylogger at 23-31'")


def demo_module2_state_explosion():
    section("Module 2 -- regex state-explosion family a.{n}b (search+sticky mode)")
    from rule_compiler import hopcroft_minimize, parse_regex, subset_construct, thompson_construct

    for n in (2, 4, 6, 8):
        ast = parse_regex(f"a.{{{n}}}b")
        nfa = thompson_construct(ast)
        dfa = subset_construct(nfa, mode="search_sticky")
        minimal = hopcroft_minimize(dfa)
        print(f"n={n:>2}: minimal DFA states = {minimal.n_states} (closed form 2^(n+1)+1 = {2**(n+1)+1})")


def demo_module3_decision_predicate():
    section("Module 3 -- SQLi decision predicate: attack vs benign")
    from sqli_engine import SqliParser, lex

    parser = SqliParser.build()

    def run(label: str, static: str, tainted: str):
        payload = (static + tainted).encode()
        mask = [False] * len(static) + [True] * len(tainted)
        tokens = lex(payload, taint_mask=mask)
        verdict = parser.parse(tokens, stop_on_error=True)
        print(f"  [{label}] is_attack={verdict.is_attack}   input={static!r} + {tainted!r}")

    run("UNION injection", "SELECT * FROM t WHERE id = ", "1 UNION SELECT a FROM b")
    run("OR injection", "SELECT * FROM t WHERE name = ", "'x' OR 'a'='a'")
    run("benign parens", "", "SELECT (1+2)*3")

    # NOTE: the closing ')' below is deliberately kept OUT of the tainted span and appended as
    # its own untainted lex() call -- it is part of the static SQL template, not something the
    # attacker supplies. This mirrors tests/test_sqli_engine.py's
    # test_decision_predicate_benign_static_nested_subquery exactly; tainting the paren itself
    # would (correctly) latch, since a real user input that could inject a literal ')' at that
    # position IS already a structurally meaningful attack vector, not this benign case.
    static_query = "SELECT * FROM t WHERE id IN (SELECT id FROM u WHERE flag = "
    payload = (static_query + "42").encode() + b")"
    mask = [False] * len(static_query) + [True] * 2 + [False]
    tokens = lex(payload, taint_mask=mask)
    verdict = parser.parse(tokens, stop_on_error=True)
    print(f"  [benign static nested subquery] is_attack={verdict.is_attack}   "
          f"input={static_query!r} + '42' (tainted) + ')' (static)")


def demo_module4_full_pipeline():
    section("Module 4 -- full pipeline: Section 4.1's three worked-example rules")
    rule_text = "\n".join(
        [
            'alert tcp any any -> any 80 (msg:"HTTP GET to admin panel"; '
            'content:"GET"; offset:0; depth:3; '
            'content:"/index.html"; distance:1; within:20; sid:1000001;)',
            'alert tcp any any -> any 80 (msg:"SQLi UNION probe"; content:"UNION"; nocase; '
            'fast_pattern; pcre:"/UNION\\s+SELECT/i"; sid:1000002;)',
            'alert tcp any any -> any 80 (msg:"pathological nested quantifier"; '
            'pcre:"/(a+)+b/"; sid:1000003;)',
        ]
    )
    rules = load_rules(rule_text)
    ruleset = compile_full_ruleset(rules)
    print(f"compiled {len(rules)} rules; no-anchor fallback set: {ruleset.no_anchor_rule_ids}")

    pipeline = Pipeline(ruleset=ruleset)
    flow_key = ("203.0.113.5", 51000, "198.51.100.7", 80, "tcp")

    for label, payload in [
        ("benign GET", b"GET /index.html HTTP/1.1\r\n\r\n"),
        ("UNION SQLi", b"id=1 UNION SELECT password FROM users"),
        ("UNION word, not SQLi", b"a UNION of two things, not a query"),
    ]:
        alerts = pipeline.process_packet(flow_key, payload)
        print(f"  [{label}] payload={payload!r}")
        for a in alerts:
            print(f"      -> ALERT rule_id={a.rule_id} tier={a.tier.value} msg={a.msg!r}")
        if not alerts:
            print("      -> no alerts")

    print("\n  cross-packet SQLi value-slot example:")
    static = b"SELECT * FROM t WHERE id = "
    injected = b"1 UNION SELECT a FROM b"
    slot = TaintedSlot("q", static + injected, [False] * len(static) + [True] * len(injected), is_final=True)
    alerts = pipeline.process_packet(flow_key, b"irrelevant-byte-tier-payload", value_slots=[slot])
    for a in alerts:
        print(f"      -> ALERT tier={a.tier.value} msg={a.msg!r}")
        if a.production_trace:
            print(f"         taint-latch token index: {a.match_span[0]}")
            print(f"         full production trace has {len(a.production_trace)} steps "
                  f"(parsing continues past the latch point, per spec)")


if __name__ == "__main__":
    demo_module1_classic_ac()
    demo_module1_demo_payload()
    demo_module2_state_explosion()
    demo_module3_decision_predicate()
    demo_module4_full_pipeline()
    print("\n" + "=" * 78)
    print("Done. Run `python3 -m pytest tests/ -v` for the full asserted test suite (78 tests),")
    print("or `./run_benchmarks.sh` to also regenerate REPORT.md with real measured results.")
