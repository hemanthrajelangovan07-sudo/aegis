"""Flow/Stream State Manager, Alert Emitter & Pipeline Orchestrator
(IMPLEMENTATION.md Module 4, Owner: Integration Lead)."""
from .flow_table import FlowControlBlock, FlowKey, FlowTable
from .alert_emitter import AlertRecord, Severity, Tier, emit_alert_from_match, emit_alert_from_sqli_verdict
from .sqli_token_buffer import PartialTokenState, lex_slot_with_carry
from .orchestrator import CompiledRuleSet, Pipeline, TaintedSlot, compile_full_ruleset, positional_check, verify
from .http_extraction import extract_tainted_slots, parse_http_request, ParsedHttpRequest

__all__ = [
    "FlowControlBlock",
    "FlowKey",
    "FlowTable",
    "AlertRecord",
    "Severity",
    "Tier",
    "emit_alert_from_match",
    "emit_alert_from_sqli_verdict",
    "PartialTokenState",
    "lex_slot_with_carry",
    "CompiledRuleSet",
    "Pipeline",
    "TaintedSlot",
    "compile_full_ruleset",
    "positional_check",
    "verify",
    "extract_tainted_slots",
    "parse_http_request",
    "ParsedHttpRequest",
]
