"""Publishable redaction path (KA-090): turn a raw kali-agent report into
a scrubbed, publishable-safe version whose eventual publish target is the
site's capabilities pipeline (bedimsecurity.com/capabilities/,
owner-gated). This module does NOT post anything anywhere: it only
transforms text, consults an owner flag, and returns data - no network,
no process spawning, no file I/O. The actual publishing is a separate,
owner-run step OUTSIDE this repo path.

FLOW
  raw report text
    -> redact_report(text, policy=None)
       scrubs every policy rule; the result is NEVER marked publishable
       (publishable=False always)
    -> publishable_report(result, owner=False)
       the owner gate: returns the refusal dict
       {published: False, reason: "owner gate"} unless the caller
       explicitly passes owner=True, which returns
       {publishable: True, artifact: <redacted markdown>} for the OWNER
       to carry to the site pipeline THEMSELVES.

POLICY (re-authored, extendable): DEFAULT_REDACTION_POLICY maps rule
name -> {"token": <deterministic replacement token>, "patterns":
[<regex strings>]}:

  lan_ips             internal LAN IPs only: RFC1918 (10/8, 172.16/12,
                      192.168/16) + IPv4 loopback 127/8 + tailnet
                      100.64/10 -> [REDACTED-LAN]
  internal_emails     any local part @wezzel.com (incl. subdomains),
                      dmrobbipens@<any domain>, and the bare
                      "@wezzel.com" mention -> [REDACTED-EMAIL]
                      (checked BEFORE the hostname rule so a house-domain
                      email redacts as one whole [REDACTED-EMAIL])
  internal_hostnames  house domains and their subdomains (wezzel.com,
                      stsgym.com, stsphotos.com) plus the bare house
                      host tokens thing1/gus2 -> [REDACTED-HOST]
  home_opt_paths      /home/wez, /home/wez/.openclaw and /opt/soc-...
                      (whole path runs consumed) -> [REDACTED-PATH]
  soc_uuids           uuid-derived identifiers: dashed canonical UUIDs
                      (SOC agents, sessions), 32-hex (uuid4().hex), and
                      12-hex (soc-tickets store ids) -> [REDACTED-UUID]

Rules apply per pattern list with patterns sorted longest-source-first,
so the most specific anchor wins where anchors differ
(e.g. /home/wez/.openclaw consumes the whole stored-config path before
the shorter /home/wez prefix is consulted). Every substitution is
deterministic: same input + same policy -> identical output (no
randomness, no clocks). `dropped` carries [{rule, count}] in policy
order with only the rules that actually fired.

EXTENSION: a passed policy REPLACES the default wholesale; compose
dict unpacking to extend:
    policy = {**DEFAULT_REDACTION_POLICY, "my_rule": {...}}

SCRUB DISCIPLINE: report_text and the policy are this module's only
external inputs; report_text must be a str and the policy is validated
strictly (ValueError naming the offender on every malformation). The
redaction itself can only ever return strings and counts - the gate op
returns a verdict dict and never performs I/O of any kind.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

__all__ = [
    "DEFAULT_REDACTION_POLICY",
    "RULE_SPEC_KEYS",
    "GATE_REFUSAL_REASON",
    "WARN_EMPTY_REPORT",
    "WARN_NO_RULES",
    "WARN_EXTRA_KEYS_FMT",
    "redact_report",
    "publishable_report",
]

# the required keys of every policy rule spec (the drift alarm; tests
# pin this tuple)
RULE_SPEC_KEYS = ("token", "patterns")

# warning messages (pinned in tests; warnings never abort the redaction)
WARN_EMPTY_REPORT = "empty report_text: nothing to redact"
WARN_NO_RULES = "policy has no rules"
WARN_EXTRA_KEYS_FMT = "rule %r ignored extra spec keys: %s"

# the refusal reason of the owner gate
GATE_REFUSAL_REASON = "owner gate"

# octet2 ranges below reuse one vocabulary: 16-31 for 172.16/12 and
# 64-127 for the tailnet 100.64/10 block
DEFAULT_REDACTION_POLICY: Dict[str, Dict[str, Any]] = {
    "lan_ips": {
        "token": "[REDACTED-LAN]",
        "patterns": [
            (r"(?<![0-9.])"
             r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
             r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
             r"|192\.168\.\d{1,3}\.\d{1,3}"
             r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
             r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\."
             r"\d{1,3})"
             r"(?![0-9.])"),
        ],
    },
    "internal_emails": {
        "token": "[REDACTED-EMAIL]",
        "patterns": [
            (r"(?i)[a-z0-9._%+-]{1,64}@"
             r"(?:[a-z0-9-]{1,63}\.)*wezzel\.com(?!\.\w)(?![\w-])"),
            r"(?i)dmrobbipens@[a-z0-9._%+-]*",
            r"(?i)@wezzel\.com(?!\.\w)(?![\w-])",
        ],
    },
    "internal_hostnames": {
        "token": "[REDACTED-HOST]",
        "patterns": [
            (r"(?i)(?<![\w-])(?:[a-z0-9-]{1,63}\.)*"
             r"(?:wezzel|stsgym|stsphotos)\.com(?!\.\w)(?![\w-])"),
            r"(?i)\b(?:thing1|gus2)\b",
        ],
    },
    "home_opt_paths": {
        "token": "[REDACTED-PATH]",
        "patterns": [
            (r"(?<![\w-])/home/wez/\.openclaw(?:/[\w@.+-]+)*"
             r"(?![\w@.+-])"),
            r"(?<![\w-])/home/wez(?:/[\w@.+-]+)*(?![\w@.+-])",
            r"(?<![\w-])/opt/soc-[\w./@+-]*(?![\w@.+-])",
        ],
    },
    "soc_uuids": {
        "token": "[REDACTED-UUID]",
        "patterns": [
            (r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
             r"-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])"),
            r"(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])",
            r"(?i)(?<![0-9a-f])[0-9a-f]{12}(?![0-9a-f])",
        ],
    },
}

CompiledRule = Tuple[str, str, List[re.Pattern]]


def _compile_rule_patterns(name: str, spec: Dict[str, Any]) -> List[re.Pattern]:
    """Compile a rule's patterns, longest source first (specificity
    order: the longest anchor consumes the most identifying span)."""
    patterns = spec["patterns"]
    if isinstance(patterns, str) or not isinstance(patterns, (list, tuple)):
        raise ValueError(
            "policy rule %r patterns must be a list of regex strings, "
            "got %r" % (name, patterns))
    if any(not isinstance(p, str) for p in patterns):
        raise ValueError(
            "policy rule %r patterns must be regex STRINGS, got %r"
            % (name, patterns))
    try:
        compiled = [re.compile(p) for p in patterns]
    except re.error as exc:
        raise ValueError(
            "policy rule %r pattern failed to compile: %s" % (name, exc)
        ) from exc
    return sorted(compiled, key=lambda rx: len(rx.pattern), reverse=True)


def _compile_policy(policy: Any) -> Tuple[List[CompiledRule], List[str]]:
    """Validate + compile a redaction policy (None -> the module
    default). Returns (ordered rules, validation warnings); malformed
    policies raise ValueError naming the offender."""
    if policy is None:
        policy = DEFAULT_REDACTION_POLICY
    if not isinstance(policy, dict):
        raise ValueError(
            "policy must be a dict mapping rule name -> spec, got %r"
            % (policy,))
    if not policy:
        return [], [WARN_NO_RULES]
    rules: List[CompiledRule] = []
    warnings: List[str] = []
    for name, spec in policy.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError(
                "policy rule names must be non-blank strings, got %r"
                % (name,))
        if not isinstance(spec, dict):
            raise ValueError(
                "policy rule %r spec must be a dict, got %r" % (name, spec))
        missing = [key for key in RULE_SPEC_KEYS if key not in spec]
        if missing:
            raise ValueError(
                "policy rule %r spec missing keys: %s" % (name, missing))
        token = spec["token"]
        if not isinstance(token, str) or not token.strip():
            raise ValueError(
                "policy rule %r token must be a non-blank string, got %r"
                % (name, token))
        extras = sorted(key for key in spec if key not in RULE_SPEC_KEYS)
        if extras:
            warnings.append(WARN_EXTRA_KEYS_FMT % (name, extras))
        rules.append((name, token, _compile_rule_patterns(name, spec)))
    return rules, warnings


def redact_report(report_text: Any, policy: Any = None) -> Dict[str, Any]:
    """Scrub every policy class out of a report; returns
    {'publishable': False, 'redacted_markdown': <str>, 'dropped':
    [{'rule', 'count'}], 'warnings': [<str>]}. The result is never
    publishable on its own - the owner gate is publishable_report."""
    if not isinstance(report_text, str):
        raise ValueError(
            "report_text must be a string, got %r" % (report_text,))
    rules, warnings = _compile_policy(policy)
    if not report_text.strip():
        warnings.append(WARN_EMPTY_REPORT)
    text = report_text
    dropped: List[Dict[str, Any]] = []
    for name, token, regexes in rules:
        count = 0
        for rx in regexes:
            text, hits = rx.subn(token, text)
            count += hits
        if count:
            dropped.append({"rule": name, "count": count})
    return {
        "publishable": False,
        "redacted_markdown": text,
        "dropped": dropped,
        "warnings": warnings,
    }


def publishable_report(redacted: Any, owner: bool = False) -> Dict[str, Any]:
    """The owner gate in front of the eventual capabilities-pipeline
    publish. Without owner=True the only possible outcome is the refusal
    dict {'published': False, 'reason': 'owner gate'}; with owner=True
    the verdict is {'publishable': True, 'artifact': <redacted
    markdown>} - the artifact the OWNER would post themselves. Nothing
    here posts, opens, or transmits anything."""
    if isinstance(redacted, str):
        artifact = redacted
    elif (isinstance(redacted, dict)
          and isinstance(redacted.get("redacted_markdown"), str)):
        artifact = redacted["redacted_markdown"]
    else:
        raise ValueError(
            "redacted must be a redact_report result dict (with a str "
            "'redacted_markdown') or a redacted markdown string, got %r"
            % (redacted,))
    if not owner:
        return {"published": False, "reason": GATE_REFUSAL_REASON}
    return {"publishable": True, "artifact": artifact}