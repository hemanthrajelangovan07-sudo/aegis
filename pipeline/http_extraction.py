"""
HTTP/DB-parameter extraction (previously out of scope per IMPLEMENTATION.md Section 3 Component
5's input contract: "Extraction from raw HTTP/DB-parameter framing is explicitly out of scope --
the orchestrator receives these pre-extracted"). This module fills that gap: it turns a raw HTTP
request into the TaintedSlot objects Pipeline.process_packet actually consumes, so the engine can
run against real traffic (or a real PCAP's reassembled HTTP payload) rather than only
hand-constructed TaintedSlot objects in tests.

Covers: URL query-string parameters, application/x-www-form-urlencoded bodies, and
application/json bodies (string leaf values only -- SQLi payloads live in string values, not JSON
structure). Every extracted value is percent-decoded (and, for form bodies, '+' decoded to space)
BEFORE lexing, with the taint mask covering exactly the decoded value bytes -- the surrounding
static HTTP framing (header names, '&'/'=' delimiters, JSON punctuation) never enters a
TaintedSlot at all, matching the "static template vs tainted value slot" model Section 2.6's
decision predicate is built around.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from pipeline.orchestrator import TaintedSlot

_REQUEST_LINE_RE = re.compile(rb"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/\d\.\d\r?\n")
_HEADER_RE = re.compile(rb"([^:\r\n]+):[ \t]*([^\r\n]*)\r?\n")


@dataclass
class ParsedHttpRequest:
    method: str
    path: str
    query_string: str
    headers: dict[str, str]
    body: bytes


def parse_http_request(raw: bytes) -> ParsedHttpRequest | None:
    """Minimal, permissive HTTP/1.x request-line + header parser -- enough to locate the query
    string and body for parameter extraction. Returns None (not an exception) if `raw` doesn't
    look like an HTTP request at all, since a NIDS sees arbitrary TCP payloads and "this isn't
    HTTP" is an ordinary, expected outcome, not an error."""
    m = _REQUEST_LINE_RE.match(raw)
    if not m:
        return None
    target = m.group("target").decode("latin-1")
    path, _, query = target.partition("?")

    pos = m.end()
    headers: dict[str, str] = {}
    while True:
        hm = _HEADER_RE.match(raw, pos)
        if not hm:
            break
        name = hm.group(1).decode("latin-1").strip().lower()
        value = hm.group(2).decode("latin-1").strip()
        headers[name] = value
        pos = hm.end()

    # blank line (CRLFCRLF or LFLF) separates headers from body; be lenient about which we saw
    if raw[pos : pos + 2] == b"\r\n":
        pos += 2
    elif raw[pos : pos + 1] == b"\n":
        pos += 1
    body = raw[pos:]

    return ParsedHttpRequest(
        method=m.group("method").decode("latin-1"),
        path=path,
        query_string=query,
        headers=headers,
        body=body,
    )


def _percent_decode_with_provenance(raw: bytes) -> tuple[bytes, list[int]]:
    """Percent- and '+'-decodes `raw`, returning (decoded_bytes, source_offsets) where
    source_offsets[i] is the START offset in `raw` that decoded_bytes[i] came from -- needed so a
    downstream taint mask (aligned to the ORIGINAL encoded bytes) can be projected onto the
    decoded bytes correctly, rather than assuming a naive 1:1 length correspondence (which
    percent-decoding breaks: "%41" is 3 encoded bytes -> 1 decoded byte)."""
    out = bytearray()
    offsets: list[int] = []
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b == 0x25 and i + 2 < n:  # '%'
            hex_pair = raw[i + 1 : i + 3]
            try:
                out.append(int(hex_pair, 16))
                offsets.append(i)
                i += 3
                continue
            except ValueError:
                pass
        if b == 0x2B:  # '+' -> space (form-urlencoded convention)
            out.append(0x20)
            offsets.append(i)
            i += 1
            continue
        out.append(b)
        offsets.append(i)
        i += 1
    return bytes(out), offsets


def _parse_urlencoded(raw: bytes) -> list[tuple[str, bytes, list[int]]]:
    """Splits a x-www-form-urlencoded (or URL query) byte string on '&' and '=', percent-decoding
    each value while tracking provenance offsets (see above). Returns
    [(key, decoded_value_bytes, source_offsets), ...]."""
    results: list[tuple[str, bytes, list[int]]] = []
    if not raw:
        return results
    for pair in raw.split(b"&"):
        if not pair:
            continue
        key_raw, sep, val_raw = pair.partition(b"=")
        key_decoded, _ = _percent_decode_with_provenance(key_raw)
        val_decoded, offsets = _percent_decode_with_provenance(val_raw)
        results.append((key_decoded.decode("latin-1"), val_decoded, offsets))
    return results


def _walk_json_strings(node, path: str = "$"):
    """Yields (json_path, string_value) for every STRING leaf in a parsed JSON value -- SQLi
    payloads live in string values (a numeric/bool/null JSON leaf can't carry injection bytes)."""
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_json_strings(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_json_strings(v, f"{path}[{i}]")


def extract_tainted_slots(raw_request: bytes, is_final: bool = True) -> list[TaintedSlot]:
    """Top-level entry point: raw HTTP request bytes -> list[TaintedSlot], ready to pass straight
    into Pipeline.process_packet(..., value_slots=...).

    IMPORTANT, discovered while integration-testing this module against real requests (not a
    theoretical concern): a NIDS-layer extractor genuinely does not know the backend SQL template
    a parameter value gets concatenated into (Section 7.4's own point: "NIDS lacks query
    context... doesn't know intended query structure"). Handing the bare decoded value to the
    grammar parser as a standalone top-level Script almost always fails to parse at all -- the
    value is a FRAGMENT ("1 UNION SELECT ..."), not a complete statement, and Section 2.6's
    grammar has no top-level production for a bare Expr.

    The honest, defensible response (same one bench/sqli_corpus_eval.py arrived at when this
    exact problem showed up evaluating against the real libinjection corpus): embed each
    extracted value into a SMALL, clearly-labeled set of representative candidate SQL contexts
    (a numeric WHERE-clause position, and -- if the value contains a quote -- a quoted-string
    position), with the embedding prefix/suffix marked NON-tainted and the value itself tainted.
    This tests "would this value, dropped into a plausible query position, look structurally like
    an injection" -- which is the most a context-blind network-layer extractor can honestly claim
    to test. Each (parameter, context) pair becomes its own TaintedSlot, field_id-tagged with
    which context produced it, so a caller can see exactly what was tried."""
    parsed = parse_http_request(raw_request)
    if parsed is None:
        return []

    def slots_for(field_id: str, value_bytes: bytes) -> list[TaintedSlot]:
        return [
            TaintedSlot(
                field_id=f"{field_id}#{ctx_name}",
                bytes_=prefix.encode("latin-1") + value_bytes + suffix.encode("latin-1"),
                taint_mask=[False] * len(prefix) + [True] * len(value_bytes) + [False] * len(suffix),
                is_final=is_final,
            )
            for ctx_name, prefix, suffix in _CANDIDATE_CONTEXTS(value_bytes)
        ]

    slots: list[TaintedSlot] = []

    for key, value_bytes, _offsets in _parse_urlencoded(parsed.query_string.encode("latin-1")):
        slots.extend(slots_for(f"query:{key}", value_bytes))

    content_type = parsed.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type:
        for key, value_bytes, _offsets in _parse_urlencoded(parsed.body):
            slots.extend(slots_for(f"form:{key}", value_bytes))
    elif "application/json" in content_type:
        try:
            doc = json.loads(parsed.body.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            doc = None
        if doc is not None:
            for json_path, string_value in _walk_json_strings(doc):
                value_bytes = string_value.encode("utf-8", errors="replace")
                slots.extend(slots_for(f"json:{json_path}", value_bytes))

    return slots


def _CANDIDATE_CONTEXTS(value_bytes: bytes) -> list[tuple[str, str, str]]:
    """(context_name, static_prefix, static_suffix) triples a value gets embedded into for
    structural evaluation -- see extract_tainted_slots' docstring for why this exists."""
    contexts = [("numeric-ctx", "SELECT * FROM t WHERE id = ", "")]
    if b"'" in value_bytes:
        contexts.append(("string-ctx", "SELECT * FROM t WHERE name = '", "'"))
    return contexts
