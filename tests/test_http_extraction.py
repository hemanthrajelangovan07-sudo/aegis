from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline import Pipeline, Tier, compile_full_ruleset
from pipeline.http_extraction import extract_tainted_slots, parse_http_request


def test_parse_http_request_basic():
    raw = b"GET /search?q=hello HTTP/1.1\r\nHost: example.com\r\n\r\n"
    parsed = parse_http_request(raw)
    assert parsed is not None
    assert parsed.method == "GET"
    assert parsed.path == "/search"
    assert parsed.query_string == "q=hello"
    assert parsed.headers["host"] == "example.com"


def test_parse_http_request_non_http_returns_none():
    assert parse_http_request(b"installed backdoor and keylogger today") is None


def test_extract_query_string_percent_decoded():
    raw = b"GET /users?id=1%20UNION%20SELECT%20a%20FROM%20b HTTP/1.1\r\nHost: x\r\n\r\n"
    slots = extract_tainted_slots(raw)
    # numeric value, no quote -> exactly one candidate context (numeric-ctx)
    assert len(slots) == 1
    slot = slots[0]
    assert slot.field_id == "query:id#numeric-ctx"
    # the tainted SPAN within the embedded bytes must equal the decoded value exactly
    tainted_span = bytes(b for b, t in zip(slot.bytes_, slot.taint_mask) if t)
    assert tainted_span == b"1 UNION SELECT a FROM b"


def test_extract_form_urlencoded_body():
    body = b"username=admin&password=1%27+OR+%271%27%3D%271"
    raw = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: x\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    slots = extract_tainted_slots(raw)
    by_prefix: dict[str, list] = {}
    for s in slots:
        by_prefix.setdefault(s.field_id.split("#")[0], []).append(s)

    def tainted_bytes(slot):
        return bytes(b for b, t in zip(slot.bytes_, slot.taint_mask) if t)

    # "admin" has no quote -> only numeric-ctx tried
    assert tainted_bytes(by_prefix["form:username"][0]) == b"admin"
    # "1' OR '1'='1" has a quote -> both numeric-ctx and string-ctx tried
    assert len(by_prefix["form:password"]) == 2
    assert all(tainted_bytes(s) == b"1' OR '1'='1" for s in by_prefix["form:password"])


def test_extract_json_body_string_leaves():
    body = b'{"user": "alice", "filter": "1 UNION SELECT a FROM b", "age": 30}'
    raw = (
        b"POST /api/search HTTP/1.1\r\n"
        b"Host: x\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    slots = extract_tainted_slots(raw)
    prefixes = {s.field_id.split("#")[0] for s in slots}
    assert "json:$.user" in prefixes
    assert "json:$.filter" in prefixes
    assert "json:$.age" not in prefixes  # numeric leaf, correctly skipped


def test_full_pipeline_real_http_request_end_to_end():
    """The point of this module: a raw HTTP request goes in, a real SQLi alert comes out,
    with no hand-constructed TaintedSlot in between."""
    ruleset = compile_full_ruleset([])
    pipeline = Pipeline(ruleset=ruleset)
    flow_key = ("203.0.113.9", 55123, "198.51.100.20", 80, "tcp")

    raw = b"GET /products?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\r\nHost: shop.example\r\n\r\n"
    slots = extract_tainted_slots(raw)
    alerts = pipeline.process_packet(flow_key, raw, value_slots=slots)
    assert any(a.tier == Tier.SQLI_STRUCTURAL for a in alerts)


def test_full_pipeline_benign_real_http_request_no_alert():
    ruleset = compile_full_ruleset([])
    pipeline = Pipeline(ruleset=ruleset)
    flow_key = ("203.0.113.9", 55124, "198.51.100.20", 80, "tcp")

    raw = b"GET /products?id=42&category=shoes HTTP/1.1\r\nHost: shop.example\r\n\r\n"
    slots = extract_tainted_slots(raw)
    alerts = pipeline.process_packet(flow_key, raw, value_slots=slots)
    assert not any(a.tier == Tier.SQLI_STRUCTURAL for a in alerts)


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
