from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ac_prefilter import build_failure_links, build_nextmove, build_trie_literals, scan_final_state
from pipeline import (
    FlowTable,
    Pipeline,
    TaintedSlot,
    Tier,
    compile_full_ruleset,
    positional_check,
)
from rule_compiler.loader import load_rules

DEMO_PAYLOAD = b"installed backdoor and keylogger on target machine silently today"


def test_ac_state_resumption_mid_pattern():
    """Section 5 Module 4's flagship test: splitting the 65-byte demo payload at byte offset 14
    (inside "backdoor", which spans bytes 10-17) must produce IDENTICAL combined hits to scanning
    the full 65 bytes in one call, and the state after packet 1 must be exactly state 4 (the
    trie state for the 4-byte prefix "back")."""
    trie = build_trie_literals(["backdoor", "keylogger"])
    build_failure_links(trie)
    dfa = build_nextmove(trie, layout="dense")
    rule_of = {0: "backdoor", 1: "keylogger"}

    full_final, full_matches = scan_final_state(dfa, DEMO_PAYLOAD)
    full_hits = sorted((m.end_position, sorted(rule_of[r] for r in m.rule_ids)) for m in full_matches)
    assert full_hits == [(17, ["backdoor"]), (31, ["keylogger"])]

    split = 14
    part1, part2 = DEMO_PAYLOAD[:split], DEMO_PAYLOAD[split:]
    assert part1 == b"installed back"
    state_after_part1, hits1 = scan_final_state(dfa, part1)
    assert state_after_part1 == 4

    _, hits2 = scan_final_state(dfa, part2, start_state=state_after_part1)
    combined = [(m.end_position, sorted(rule_of[r] for r in m.rule_ids)) for m in hits1]
    combined += [(m.end_position + split, sorted(rule_of[r] for r in m.rule_ids)) for m in hits2]
    combined.sort()
    assert combined == full_hits


def test_ac_state_resumption_arbitrary_splits():
    trie = build_trie_literals(["backdoor", "keylogger"])
    build_failure_links(trie)
    dfa = build_nextmove(trie, layout="dense")
    rule_of = {0: "backdoor", 1: "keylogger"}
    full_final, full_matches = scan_final_state(dfa, DEMO_PAYLOAD)
    full_hits = sorted((m.end_position, sorted(rule_of[r] for r in m.rule_ids)) for m in full_matches)

    for split in (0, 30, 65):
        part1, part2 = DEMO_PAYLOAD[:split], DEMO_PAYLOAD[split:]
        s_mid, hits1 = scan_final_state(dfa, part1)
        _, hits2 = scan_final_state(dfa, part2, start_state=s_mid)
        combined = [(m.end_position, sorted(rule_of[r] for r in m.rule_ids)) for m in hits1]
        combined += [(m.end_position + split, sorted(rule_of[r] for r in m.rule_ids)) for m in hits2]
        combined.sort()
        assert combined == full_hits, f"split={split} mismatch"


def test_flow_eviction_bounds_memory():
    table = FlowTable()
    ttl_ns = 60_000_000_000
    base_ns = 1_000_000_000_000
    n_flows = 2000
    for i in range(n_flows):
        key = ("10.0.0.1", i, "10.0.0.2", 80, "tcp")
        table.get_or_create(key, now_ns=base_ns)
    assert len(table) == n_flows

    evicted = table.evict_stale(base_ns + ttl_ns + 1, ttl_ns)
    assert evicted == n_flows
    assert len(table) == 0


def test_alert_schema_roundtrip_content_rule():
    rules = load_rules(
        'alert tcp any any -> any 80 (msg:"test"; content:"backdoor"; sid:5001;)'
    )
    ruleset = compile_full_ruleset(rules)
    pipeline = Pipeline(ruleset=ruleset)
    alerts = pipeline.process_packet(("1.2.3.4", 1111, "5.6.7.8", 80, "tcp"), DEMO_PAYLOAD)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.tier == Tier.AC_ONLY
    assert a.rule_id == 5001
    assert a.matched_pattern == "backdoor"


def test_positional_check_worked_example_1():
    """Section 4.1 worked example 1: content:"GET";offset:0;depth:3; content:"/index.html";
    distance:1;within:20; -- must locate GET at [0,3) then /index.html starting exactly at
    position 4 (immediately after GET, distance:1)."""
    rules = load_rules(
        'alert tcp any any -> any 80 (msg:"HTTP GET to admin panel"; '
        'content:"GET"; offset:0; depth:3; '
        'content:"/index.html"; distance:1; within:20; sid:1000001;)'
    )
    rule = rules[0]
    good_payload = b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n"
    assert positional_check(rule, good_payload) is True

    bad_payload = b"POST /index.html HTTP/1.1\r\n\r\n"  # no GET at offset 0
    assert positional_check(rule, bad_payload) is False

    far_payload = b"GET /some/very/long/path/that/pushes/index.html/too/far/away.html HTTP/1.1"
    assert positional_check(rule, far_payload) is False  # /index.html not within 20 bytes


def test_full_pipeline_worked_examples_end_to_end():
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
    pipeline = Pipeline(ruleset=ruleset)
    flow_key = ("1.2.3.4", 1111, "5.6.7.8", 80, "tcp")

    # rule 1 fires: GET .../index.html, positionally valid
    alerts1 = pipeline.process_packet(flow_key, b"GET /index.html HTTP/1.1\r\n\r\n")
    assert any(a.rule_id == 1000001 for a in alerts1)

    # rule 2 fires: "UNION" AC hit + "UNION SELECT" regex verifier confirms
    alerts2 = pipeline.process_packet(flow_key, b"id=1 UNION SELECT password FROM users")
    assert any(a.rule_id == 1000002 for a in alerts2)

    # rule 2 does NOT fire on "UNION" alone without "SELECT" following (AC hits, but the
    # per-rule verifier for UNION\s+SELECT must reject)
    alerts2b = pipeline.process_packet(flow_key, b"a UNION of two things, not a query")
    assert not any(a.rule_id == 1000002 for a in alerts2b)

    # rule 3 (ReDoS-flagged) never gets a compiled verifier -- Section 5's no-anchor fallback
    # bookkeeping still tracks it in no_anchor_rule_ids, but with no verifier to run it produces
    # no alert (a REJECTED_UNBOUNDED rule is flagged for delegation, not silently "always true")
    assert 1000003 in ruleset.no_anchor_rule_ids
    assert ruleset.verifier_bank.get(1000003) is None


def test_full_pipeline_sqli_structural_tier():
    ruleset = compile_full_ruleset([])  # no content/regex rules -- SQLi tier only
    pipeline = Pipeline(ruleset=ruleset)
    flow_key = ("1.2.3.4", 2222, "5.6.7.8", 80, "tcp")

    payload = b"irrelevant-byte-tier-payload"
    static = b"SELECT * FROM t WHERE id = "
    injected = b"1 UNION SELECT a FROM b"
    slot = TaintedSlot(
        field_id="q",
        bytes_=static + injected,
        taint_mask=[False] * len(static) + [True] * len(injected),
        is_final=True,
    )
    alerts = pipeline.process_packet(flow_key, payload, value_slots=[slot])
    assert any(a.tier == Tier.SQLI_STRUCTURAL for a in alerts)


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
