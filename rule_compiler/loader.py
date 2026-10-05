"""
Rule/Signature Loader (IMPLEMENTATION.md Section 4.1, Section 5 Module 2, Owner: Compiler Lead).

Parses the rule grammar of Section 4.1 (Snort/Suricata-compatible surface syntax, restricted to
the keyword subset AEGIS-AC consumes) and performs fast-pattern auto-selection: among a rule's
`content` options, the LONGEST is chosen automatically unless an explicit `fast_pattern` /
`fast_pattern:only` override is present (Section 4.1, Section 3 Component 1). A rule with no
`content` option at all has fast_pattern=None and is routed to the no-anchor fallback set (RDP-1).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class PositionalMods:
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None


@dataclass
class ContentOption:
    literal: bytes
    nocase: bool
    fast_pattern: bool  # explicit `fast_pattern;` override
    fast_pattern_only: bool  # `fast_pattern:only;`
    negated: bool  # `content:!"foo";` -- match succeeds when the literal is ABSENT
    mods: PositionalMods


@dataclass
class ParsedRule:
    rule_id: int
    msg: str
    action: str
    protocol: str
    contents: list[ContentOption]
    fast_pattern: bytes | None  # None => no-anchor fallback (RDP-1)
    fast_pattern_only: bool
    positional_mods: PositionalMods
    regex_body: str | None
    regex_flags: str
    nocase: bool
    raw_text: str
    unsupported_options: dict[str, str] = field(default_factory=dict)  # parsed-but-not-consumed
    # metadata (flow, reference, metadata, flowbits, http_* sticky buffers, byte_test, etc.) --
    # kept so the loader doesn't have to be extended every time a real ruleset uses a keyword
    # AEGIS-AC doesn't act on yet. See _PASSTHROUGH_KEYWORDS below for exactly which ones.


class RuleSyntaxError(ValueError):
    pass


# Keywords real Snort/Suricata rules use that AEGIS-AC's detection pipeline does not (yet) act on
# (Section 4.1's grammar is deliberately a restricted subset), but which are common enough in
# real rule files that rejecting them outright would make the loader unable to even READ past the
# first line of most real rulesets. Parsed and stored in ParsedRule.unsupported_options rather
# than either (a) silently dropped, which would hide detection-relevant information from anyone
# inspecting a ParsedRule, or (b) raising RuleSyntaxError, which was the ONLY option before this
# expansion and meant a real rule file failed on essentially every line. This does NOT claim to
# implement byte_test/flowbits/etc. semantics -- it claims only to not crash on them, and to keep
# the raw value around for a future module to act on.
_PASSTHROUGH_KEYWORDS = {
    "flow", "reference", "metadata", "flowbits", "priority", "tag", "threshold",
    "urilen", "dsize", "flags", "byte_test", "byte_jump", "byte_extract",
    "http_uri", "http_client_body", "http_header", "http_cookie", "http_method",
    "http_raw_uri", "http_stat_code", "http_stat_msg", "http_user_agent",
    "pkt_data", "file_data", "base64_decode", "base64_data",
    "isdataat", "rawbytes", "detection_filter", "gid", "target",
}


_HEADER_RE = re.compile(
    r"^(?P<action>\w+)\s+(?P<protocol>\w+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+"
    r"(?P<dir>->|<>)\s+(?P<dst>\S+)\s+(?P<dport>\S+)\s*\((?P<options>.*)\)\s*$",
    re.DOTALL,
)


def _split_options(options_text: str) -> list[str]:
    """Split on ';' respecting quoted strings (a `content` value may itself contain ';' inside
    quotes -- not exercised by the worked examples but handled correctly regardless)."""
    parts: list[str] = []
    buf: list[str] = []
    in_quotes = False
    i = 0
    while i < len(options_text):
        c = options_text[i]
        if c == '"' and (i == 0 or options_text[i - 1] != "\\"):
            in_quotes = not in_quotes
            buf.append(c)
        elif c == ";" and not in_quotes:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(c)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p]


def _parse_content_value(raw: str) -> bytes:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        inner = raw[1:-1]
        return inner.encode().decode("unicode_escape").encode("latin-1")
    if raw.startswith("|") and raw.endswith("|"):
        hexpart = raw[1:-1].strip()
        return bytes(int(h, 16) for h in hexpart.split())
    raise RuleSyntaxError(f"unrecognized content value: {raw!r}")


def parse_rule(rule_text: str, rule_id_default: int = 0) -> ParsedRule:
    rule_text = rule_text.strip()
    m = _HEADER_RE.match(rule_text)
    if m is None:
        raise RuleSyntaxError(f"malformed rule header: {rule_text!r}")

    contents: list[ContentOption] = []
    regex_body: str | None = None
    regex_flags = ""
    msg = ""
    sid = rule_id_default
    global_mods = PositionalMods()
    pending_mods = PositionalMods()
    unsupported: dict[str, str] = {}

    for opt in _split_options(m.group("options")):
        if ":" in opt:
            key, _, value = opt.partition(":")
            key = key.strip()
            value = value.strip()
        else:
            key, value = opt.strip(), ""

        if key == "msg":
            msg = value.strip('"')
        elif key == "content":
            negated = value.strip().startswith("!")
            content_value = value.strip()[1:].strip() if negated else value.strip()
            literal = _parse_content_value(content_value)
            contents.append(
                ContentOption(
                    literal=literal,
                    nocase=False,
                    fast_pattern=False,
                    fast_pattern_only=False,
                    negated=negated,
                    mods=PositionalMods(),
                )
            )
            pending_mods = contents[-1].mods
        elif key == "nocase":
            if contents:
                contents[-1].nocase = True
        elif key == "offset":
            pending_mods.offset = int(value)
        elif key == "depth":
            pending_mods.depth = int(value)
        elif key == "distance":
            pending_mods.distance = int(value)
        elif key == "within":
            pending_mods.within = int(value)
        elif key == "fast_pattern":
            if contents:
                if value == "only":
                    contents[-1].fast_pattern_only = True
                contents[-1].fast_pattern = True
        elif key == "pcre":
            body = value.strip()
            if not (body.startswith('"/') and '"' in body[1:]):
                raise RuleSyntaxError(f"malformed pcre option: {opt!r}")
            body = body[1:-1]  # strip outer quotes
            last_slash = body.rfind("/")
            regex_body = body[1:last_slash]
            regex_flags = body[last_slash + 1 :]
        elif key == "sid":
            sid = int(value)
        elif key in ("rev", "classtype"):
            pass  # parsed-but-unused metadata, per Section 4.1's grammar
        elif key in _PASSTHROUGH_KEYWORDS:
            unsupported[key] = value
        else:
            raise RuleSyntaxError(f"unsupported rule option: {key!r}")

    fast_pattern: bytes | None = None
    fast_pattern_only = False
    if contents:
        # Negated content ("content:!\"foo\";" -- flag when ABSENT) is excluded from fast-pattern
        # auto-selection: the AC prefilter can only detect PRESENCE cheaply, so anchoring the
        # whole rule's dispatch on a negated literal would be semantically backwards (an AC "hit"
        # on a negated content means the rule should NOT fire, the opposite of every other rule's
        # dispatch condition). If every content option is negated, fast_pattern correctly stays
        # None, routing the rule to the no-anchor fallback set (RDP-1) -- evaluated per-packet,
        # which is the honest cost of a presence-based prefilter for an absence-based condition.
        positive = [c for c in contents if not c.negated]
        override = [c for c in positive if c.fast_pattern]
        if positive:
            chosen = override[0] if override else max(positive, key=lambda c: len(c.literal))
            fast_pattern = chosen.literal
            fast_pattern_only = chosen.fast_pattern_only
            mods = chosen.mods
        else:
            mods = PositionalMods()
    else:
        mods = PositionalMods()

    return ParsedRule(
        rule_id=sid,
        msg=msg,
        action=m.group("action"),
        protocol=m.group("protocol"),
        contents=contents,
        fast_pattern=fast_pattern,
        fast_pattern_only=fast_pattern_only,
        positional_mods=mods,
        regex_body=regex_body,
        regex_flags=regex_flags,
        nocase=any(c.nocase for c in contents),
        raw_text=rule_text,
        unsupported_options=unsupported,
    )


def load_rules(rule_file_text: str) -> list[ParsedRule]:
    """One ParsedRule per non-blank, non-comment line of the rule file. Comment lines start with
    '#', matching common Snort/Suricata rule-file convention."""
    rules = []
    for line in rule_file_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rules.append(parse_rule(line))
    return rules
