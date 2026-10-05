"""
PROCESS-PACKET pseudocode from IMPLEMENTATION.md Section 5 Module 4:

    PROCESS-PACKET(flow_key, payload, value_slots):
        fcb = flow_table.get_or_create(flow_key)
        alerts = []
        # --- byte-level tier: AC prefilter + verifier dispatch (Modules 1-2) ---
        for match in AC-SCAN(nextmove_dfa, payload, start_state=fcb.ac_state):
            for rule_id in match.rule_ids:
                if POSITIONAL-CHECK(rule_id, match, payload):
                    verifier = verifier_bank.get(rule_id)
                    if verifier is None or VERIFY(verifier, payload, match.end_position):
                        alerts.append(EMIT-ALERT(match, flow_key, rule_id))
        fcb.ac_state = final_state
        for rule_id in no_anchor_fallback_rules:
            if VERIFY(verifier_bank.get(rule_id), payload, span=(0, len(payload))):
                alerts.append(EMIT-ALERT(..., flow_key, rule_id))
        # --- structural tier: SQLi lexer + DPDA (Module 3), cross-packet-safe ---
        for slot in value_slots:
            ... LEX-WITH-CARRY / PARSE-RESUMABLE ...
        return alerts

This module wires Modules 1 (ac_prefilter), 2 (rule_compiler), 3 (sqli_engine), and the rest of
Module 4 (flow_table, alert_emitter, sqli_token_buffer) together.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ac_prefilter import build_failure_links, build_nextmove, build_trie, scan_final_state
from ac_prefilter.types import NextMoveDFA
from pipeline.alert_emitter import AlertRecord, Severity, Tier, emit_alert_from_match, emit_alert_from_sqli_verdict
from pipeline.flow_table import FlowControlBlock, FlowKey, FlowTable
from pipeline.sqli_token_buffer import PartialTokenState, lex_slot_with_carry
from rule_compiler.backref import DetBackrefNFA
from rule_compiler.loader import ParsedRule
from rule_compiler.subset_construct import DFA
from rule_compiler.verifier_bank import VerifierBank, compile_ruleset
from sqli_engine.parser import SqliParser
from sqli_engine.quote_dfa import quote_scan


@dataclass
class TaintedSlot:
    """One already-extracted, user-controlled field (e.g. an HTTP query parameter value) whose
    bytes should be run through the SQLi structural recognizer. Extraction from raw
    HTTP/DB-parameter framing is explicitly out of scope (Section 3 Component 5's input
    contract) -- the orchestrator receives these pre-extracted.

    is_final=True signals this is the last chunk of this field for this flow (e.g. end of the
    HTTP request, or the flow is closing) -- forces any held-back trailing token to flush rather
    than wait for a packet that will never come (Section 5 Module 4 lexer flush semantics)."""

    field_id: str
    bytes_: bytes
    taint_mask: list[bool]
    is_final: bool = False


@dataclass
class CompiledRuleSet:
    ac_dfa: NextMoveDFA
    rules_by_id: dict[int, ParsedRule]
    verifier_bank: VerifierBank
    no_anchor_rule_ids: list[int]


def compile_full_ruleset(rules: list[ParsedRule], k_bound: int = 1) -> CompiledRuleSet:
    """Ties Modules 1 and 2 together: builds the single AC prefilter DFA over every rule's
    fast_pattern literal, and separately compiles a per-rule verifier for every regex-bearing
    rule (Section 3's "never merged" architectural fix, RDP-1)."""
    anchored = [(r.rule_id, r.fast_pattern) for r in rules if r.fast_pattern is not None]
    trie = build_trie(anchored)
    build_failure_links(trie)
    ac_dfa = build_nextmove(trie, layout="dense")

    bank, fallbacks = compile_ruleset(rules, k_bound=k_bound)
    no_anchor_ids = sorted({f.rule_id for f in fallbacks})

    return CompiledRuleSet(
        ac_dfa=ac_dfa,
        rules_by_id={r.rule_id: r for r in rules},
        verifier_bank=bank,
        no_anchor_rule_ids=no_anchor_ids,
    )


def _find_content(payload: bytes, literal: bytes, nocase: bool, lo: int, hi: int | None) -> int | None:
    window_end = hi if hi is not None else len(payload)
    hay = payload[lo:window_end]
    needle = literal.lower() if nocase else literal
    idx = (hay.lower() if nocase else hay).find(needle)
    if idx == -1:
        return None
    return lo + idx


def positional_check(rule: ParsedRule, payload: bytes) -> bool:
    """Verifier Dispatch's positional-constraint check (Section 3 Component 3): walks ALL of a
    rule's `content` options IN ORDER (not just the one auto-selected as the AC fast_pattern),
    honoring offset/depth (absolute, from the start of the payload) and distance/within (relative
    to the END of the previous content match). Returns True iff every content option can be
    located satisfying its constraints -- this is what keeps "the AC hit is a CANDIDATE, not a
    verified hit" true (Section 7's rebuttal to the strawman-selectivity attack)."""
    cursor = 0
    for i, c in enumerate(rule.contents):
        mods = c.mods
        if i == 0:
            lo = mods.offset if mods.offset is not None else 0
            hi = (lo + mods.depth) if mods.depth is not None else None
        else:
            lo = cursor + (mods.distance if mods.distance is not None else 0)
            hi = (lo + mods.within) if mods.within is not None else None
        pos = _find_content(payload, c.literal, c.nocase, lo, hi)
        if pos is None:
            return False
        cursor = pos + len(c.literal)
    return True


def verify(verifier: DFA | DetBackrefNFA | None, payload: bytes, window: tuple[int, int]) -> bool:
    """VERIFY(verifier, payload, span) -- invokes a compiled per-rule verifier (Module 2) on the
    given byte window. verifier=None means "content-only rule, the positional check IS the full
    verdict" -- always True in that case (the caller only gets here after positional_check
    already passed)."""
    if verifier is None:
        return True
    segment = payload[window[0] : window[1]]
    if isinstance(verifier, DetBackrefNFA):
        return verifier.verify(segment)
    # DFA: anchored-mode verifiers expect a full-string match against the already-bounded window;
    # search_sticky-mode verifiers (no-anchor fallback) expect "match anywhere in window".
    state = 0
    for b in segment:
        cls = None
        for i, group in enumerate(verifier.byte_classes):
            if b in group:
                cls = i
                break
        if cls is None:
            return False
        state = verifier.transitions[state][cls]
        if state in verifier.accepting:
            return True
    return state in verifier.accepting


@dataclass
class Pipeline:
    """Owns a CompiledRuleSet, a FlowTable, and a built SqliParser -- the full, callable AEGIS-AC
    engine. Owner: Integration Lead (Section 3 Component 8/9's home)."""

    ruleset: CompiledRuleSet
    flow_table: FlowTable = field(default_factory=FlowTable)
    sqli_parser: SqliParser = field(default_factory=SqliParser.build)
    flow_ttl_ns: int = 60_000_000_000  # 60s, matching Section 6.3's E3/Module 4 test default

    def process_packet(
        self,
        flow_key: FlowKey,
        payload: bytes,
        value_slots: list[TaintedSlot] | None = None,
        now_ns: int | None = None,
    ) -> list[AlertRecord]:
        now_ns = now_ns if now_ns is not None else time.time_ns()
        fcb = self.flow_table.get_or_create(flow_key, now_ns=now_ns)
        alerts: list[AlertRecord] = []

        # --- byte-level tier: AC prefilter + verifier dispatch (Modules 1-2) ---
        final_state, matches = scan_final_state(self.ruleset.ac_dfa, payload, start_state=fcb.ac_state)
        fcb.ac_state = final_state

        seen_rule_ids: set[int] = set()
        for m in matches:
            for rule_id in m.rule_ids:
                if rule_id in seen_rule_ids:
                    continue
                rule = self.ruleset.rules_by_id.get(rule_id)
                if rule is None:
                    continue
                if not positional_check(rule, payload):
                    continue
                verifier = self.ruleset.verifier_bank.get(rule_id)
                # For a verifier tied to a fast-pattern-anchored rule, "the relevant window"
                # (Section 3 Component 4) starts where the fast-pattern LITERAL actually matched,
                # not at byte 0 of the payload -- the per-rule DFA was compiled in "anchored"
                # mode, i.e. it expects to start matching exactly at the beginning of its window.
                literal_start = max(0, m.end_position - len(rule.fast_pattern) + 1) if rule.fast_pattern else 0
                span = (literal_start, len(payload)) if verifier is not None else (m.end_position, m.end_position + 1)
                if verifier is not None and not verify(verifier, payload, span):
                    continue
                seen_rule_ids.add(rule_id)
                tier = Tier.BACKREF_VERIFIED if isinstance(verifier, DetBackrefNFA) else (
                    Tier.AC_PLUS_DFA if verifier is not None else Tier.AC_ONLY
                )
                alerts.append(
                    emit_alert_from_match(
                        m, flow_key, rule_id, rule.fast_pattern.decode("latin-1"), tier, now_ns,
                        msg=rule.msg or f"rule {rule_id} matched",
                    )
                )

        for rule_id in self.ruleset.no_anchor_rule_ids:
            if rule_id in seen_rule_ids:
                continue
            rule = self.ruleset.rules_by_id.get(rule_id)
            verifier = self.ruleset.verifier_bank.get(rule_id)
            if rule is None or verifier is None:
                continue  # ReDoS-flagged/rejected rules have no verifier at all -- nothing to run
            if verify(verifier, payload, (0, len(payload))):
                alerts.append(
                    emit_alert_from_match(
                        _FakeMatch(len(payload) - 1), flow_key, rule_id, "<no-anchor>",
                        Tier.NO_ANCHOR_FALLBACK, now_ns, msg=rule.msg or f"rule {rule_id} matched",
                    )
                )

        # --- structural tier: SQLi lexer + DPDA (Module 3), cross-packet-safe ---
        for slot in value_slots or []:
            prior = (
                PartialTokenState(fcb.sqli_partial_token, quote_scan(fcb.sqli_partial_token))
                if fcb.sqli_partial_token
                else PartialTokenState.empty()
            )
            tokens, new_partial = lex_slot_with_carry(prior, slot.bytes_, slot.taint_mask, flush=slot.is_final)
            fcb.sqli_partial_token = new_partial.partial_bytes
            if not tokens:
                continue
            verdict = self.sqli_parser.parse(tokens, resume_stack=fcb.dpda_stack)
            fcb.dpda_stack = verdict.stack_snapshot or fcb.dpda_stack
            if verdict.is_attack:
                alerts.append(emit_alert_from_sqli_verdict(verdict, flow_key, now_ns))

        fcb.last_seen_ns = now_ns
        fcb.byte_count += len(payload)
        return alerts

    def evict_stale_flows(self, now_ns: int | None = None) -> int:
        now_ns = now_ns if now_ns is not None else time.time_ns()
        return self.flow_table.evict_stale(now_ns, self.flow_ttl_ns)


@dataclass
class _FakeMatch:
    """Minimal Match-shaped stand-in used only for no-anchor-fallback alert emission, where there
    is no real AC Match object (the rule never went through the AC prefilter at all -- that's the
    whole point of the fallback path, RDP-1)."""

    end_position: int
