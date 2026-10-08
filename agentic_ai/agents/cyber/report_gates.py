"""No-orphan-numbers report gate (KA-088): every number printed in a
kali-agent report must trace to an execution/parser source the report
was built from.

A pure planner module in the consent_gate shape (no chassis import,
no process spawning, no network facilities, no local I/O, no
wall-clock reads; nothing to inject - the gate is a pure text fold
over the strings the caller passes).

THE HOUSE GATE SHAPE:
- gate_no_orphan_numbers(report_text, sources, allow_tokens=None)
  returns exactly a (bool, reason) tuple and nothing else. Asserting
  any other shape (a dict, a raise, a third element) is the test's
  bug, not this module's (consent_gate precedent).
- reason is "" when the gate passes. When it fails, it lists up to
  MAX_ORPHANS orphan number tokens in canon form, "; "-joined (the
  tokens carry their own dots and commas, so semicolons separate
  them), followed by "; +N more" when the list was cut.

NUMBER TOKEN (one tokenizer, applied identically to the report AND
to the sources - the trace is form-sensitive by design):
- A token is a maximal digit run joined by thousands-separator comma
  groups (exactly-3-digit groups: "1,234"), by dot groups (versions
  and decimals: "1.2.3", "9.8"), optionally ending in a percent sign.
- Version-like tokens (x.y.z) are WHOLE tokens: never split into
  "1", "2", "3"; a decimal "9.8" is likewise never split.
- A percent-carrying number is its own token: "42%" is not the bare
  "42" (normalization never merges the two; each carries its own
  trace duty below).
- An ill-formed comma run splits at the 3-digit-group boundary
  ("1,23" -> tokens "1" and "23") instead of swallowing digits.

CANON (normalize_number_token; applied to BOTH sides identically):
- thousands separators removed: "1,234" -> "1234",
  "1,234.56" -> "1234.56"; so "1,234" and "1234" normalize to one
  number by design.
- everything else verbatim: dot groups and a trailing "%" survive,
  so "42%" and "42" stay distinct canon strings.

TRACE:
- A report token is TRACED iff its canon appears verbatim among the
  canon tokens of the source texts (the executions + parser outputs
  the report was built from). Both sides share one tokenizer and one
  canon, so a number survives iff its source spelled the same
  normalized number somewhere.
- Percent trace EITHER form: a "42%" report token is traced by a
  source-side "42%" canon OR the bare "42" canon (a parser may print
  the value bare). A bare "42" report token traces ONLY via the
  canon "42" - a source that merely said "42%" never becomes bare
  evidence for a bare claim.

EXEMPTS (the ONLY two; no invented semantic exemptions - a "port
22/80/443" well-known-constant class was rejected by design, which
is exactly what allow_tokens is for):
1. Line-leading enumeration: a line whose number is immediately
   followed by "." or ")" - "3. Findings", "- 4) item",
   "### 5. Section" - exempts exactly that leading number token
   (section/finding numbering boilerplate). Other numbers on the
   same line are NOT exempt, and a number without the marker ("3
   servers") is not enumeration either. Dotted numbering ("1.2.3.")
   counts; comma runs stay ordinary numbers ("1,234." at a line
   start is a number, not a heading).
2. allow_tokens: a set of literal token strings; a report token is
   traced when its raw text or its canon is a member (exact
   membership; no percent-form expansion). None means no allowlist;
   anything that is not a set/frozenset of str is refused.

Ids are NOT exempt by design: a report-internal or third-party id
("F-77", "CVE-2024-1234") traces like any other number - its digits
are ordinary tokens and must appear in the sources (a parser output
that lists the id carries them).

CALLER CONTRACT (errors are ValueError naming the offender):
- report_text: str (an empty report is clean: no numbers, no debt).
- sources: str or an iterable of str (each element must be str;
  list/tuple/generator all work; None/dict/non-iterables refuse).
  Empty sources empty the trace set - every report number is then an
  orphan, which is the gate working as intended, not a crash.
- allow_tokens: None or a set/frozenset of str.

Chassis wiring (running this gate on every assembled report with the
executions + parser outputs as sources) is an INTEGRATION decision;
this module carries the semantics only.
"""

from __future__ import annotations

import re
from typing import Any, List, Set, Tuple

__all__ = [
    "MAX_ORPHANS",
    "ORPHAN_REASON_PREFIX",
    "ENUM_RE",
    "NUM_TOKEN_RE",
    "normalize_number_token",
    "number_tokens",
    "gate_no_orphan_numbers",
]

# --- drift-alarm constants (the tests pin these literals) ------------------

MAX_ORPHANS = 25
ORPHAN_REASON_PREFIX = "orphan number tokens: "

# Tokenizer: digits joined by exactly-3-digit comma groups, by dot
# groups (versions/decimals), optionally ending in a percent sign.
NUM_TOKEN_RE = re.compile(
    r"(?:\d+(?:,\d{3})+(?:\.\d+)*|\d+(?:\.\d+)+|\d+)%?")

# Enumeration: line-leading number behind an optional bullet/heading
# decoration run, terminated by "." or ")".
ENUM_RE = re.compile(
    r"(?:^|\n)[ \t]*(?:[-*+>#]+[ \t]*)?"
    r"(\d+(?:\.\d+)*)[.)](?=\s|$)")


def normalize_number_token(token: Any) -> str:
    """The canon of one number token: separators gone, dots and a
    trailing "%" kept verbatim."""
    if not isinstance(token, str):
        raise ValueError(
            "number token must be a string, got: %r" % (token,))
    return token.replace(",", "")


def number_tokens(text: Any) -> List[str]:
    """The raw number tokens of a text, in scan order (both sides of
    the gate share this one tokenizer)."""
    if not isinstance(text, str):
        raise ValueError("text must be a string, got: %r" % (text,))
    return [match.group(0) for match in NUM_TOKEN_RE.finditer(text)]


def _canon_set(text: str) -> Set[str]:
    """The canon-token set of one text (same rules on both sides)."""
    return {normalize_number_token(raw) for raw in number_tokens(text)}


def _require_report_text(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError(
            "report_text must be a string, got: %r" % (value,))
    return value


def _require_sources(sources: Any) -> List[str]:
    if isinstance(sources, str):
        return [sources]
    if sources is None or isinstance(sources, dict):
        raise ValueError(
            "sources must be a string or a list of strings, got: %r"
            % (sources,))
    try:
        rows = list(sources)
    except TypeError:
        raise ValueError(
            "sources must be a string or a list of strings, got: %r"
            % (sources,)) from None
    for index, row in enumerate(rows):
        if not isinstance(row, str):
            raise ValueError(
                "sources[%d] must be a string, got: %r" % (index, row))
    return rows


def _require_allow_tokens(allow: Any) -> Set[str]:
    if allow is None:
        return set()
    if not isinstance(allow, (set, frozenset)):
        raise ValueError(
            "allow_tokens must be a set of strings, got: %r" % (allow,))
    for member in allow:
        if not isinstance(member, str):
            raise ValueError(
                "allow_tokens entries must be strings, got: %r"
                % (member,))
    return set(allow)


def gate_no_orphan_numbers(
    report_text: Any,
    sources: Any,
    allow_tokens: Any = None,
) -> Tuple[bool, str]:
    """gate_no_orphan_numbers(report_text, sources, allow_tokens=None)
    -> (bool, reason); every report number must trace to a source."""
    report = _require_report_text(report_text)
    rows = _require_sources(sources)
    allow = _require_allow_tokens(allow_tokens)

    evidence: Set[str] = set()
    for row in rows:
        evidence |= _canon_set(row)

    # Spans of line-leading enumeration tokens ("3."/"7)"/"### 5.").
    # Exemption is span equality, so only the leading number is exempt
    # and no later token can borrow the shape.
    exempt = {match.span(1) for match in ENUM_RE.finditer(report)}

    orphans: List[str] = []
    seen: Set[str] = set()
    for match in NUM_TOKEN_RE.finditer(report):
        if match.span() in exempt:
            continue
        raw = match.group(0)
        canon = normalize_number_token(raw)
        if raw in allow or canon in allow:
            continue
        if canon in evidence:
            continue
        if canon.endswith("%") and canon[:-1] in evidence:
            continue
        if canon not in seen:
            seen.add(canon)
            orphans.append(canon)
    if not orphans:
        return True, ""
    listed = orphans[:MAX_ORPHANS]
    reason = ORPHAN_REASON_PREFIX + "; ".join(listed)
    if len(orphans) > len(listed):
        reason += "; +%d more" % (len(orphans) - len(listed),)
    return False, reason
