"""
AlertRecord schema (IMPLEMENTATION.md Section 4.2) and emit_alert (Section 5 Module 4). Sole
writer of the alert schema (Section 3 Component 8) -- downstream consumers never see raw
AC/DFA/DPDA output directly.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum

from ac_prefilter.types import Match
from pipeline.flow_table import FlowKey
from sqli_engine.parser import SqliVerdict


class Tier(str, Enum):
    AC_ONLY = "AC_ONLY"
    AC_PLUS_DFA = "AC_PLUS_DFA"
    BACKREF_VERIFIED = "BACKREF_VERIFIED"
    NO_ANCHOR_FALLBACK = "NO_ANCHOR_FALLBACK"
    SQLI_STRUCTURAL = "SQLI_STRUCTURAL"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AlertRecord:
    alert_id: str
    timestamp_ns: int
    flow_id: FlowKey
    rule_id: int | None
    tier: Tier
    match_span: tuple[int, int]
    matched_pattern: str | None
    production_trace: list[str] | None
    severity: Severity
    msg: str


def emit_alert_from_match(
    match: Match,
    flow_key: FlowKey,
    rule_id: int,
    rule_label: str,
    tier: Tier,
    timestamp_ns: int,
    severity: Severity = Severity.MEDIUM,
    msg: str | None = None,
) -> AlertRecord:
    span_start = max(0, match.end_position - len(rule_label) + 1)
    return AlertRecord(
        alert_id=str(uuid.uuid4()),
        timestamp_ns=timestamp_ns,
        flow_id=flow_key,
        rule_id=rule_id,
        tier=tier,
        match_span=(span_start, match.end_position),
        matched_pattern=rule_label,
        production_trace=None,
        severity=severity,
        msg=msg or f"rule {rule_id} matched ({rule_label!r})",
    )


def emit_alert_from_sqli_verdict(
    verdict: SqliVerdict,
    flow_key: FlowKey,
    timestamp_ns: int,
    severity: Severity = Severity.HIGH,
) -> AlertRecord:
    assert verdict.is_attack, "emit_alert_from_sqli_verdict called on a non-attack verdict"
    latch = verdict.taint_latch_position or 0
    return AlertRecord(
        alert_id=str(uuid.uuid4()),
        timestamp_ns=timestamp_ns,
        flow_id=flow_key,
        rule_id=None,
        tier=Tier.SQLI_STRUCTURAL,
        match_span=(latch, latch),
        matched_pattern=None,
        production_trace=list(verdict.production_trace),
        severity=severity,
        msg="structural SQLi decision predicate latched: tainted token reached a "
        "structural grammar reduction (Section 2.6)",
    )
