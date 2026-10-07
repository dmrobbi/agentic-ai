"""Engagement report assembler (KA-081): folds a structured run record
{meta, executions, findings, parser_outputs} into one themed report -
markdown AND html, styled after the site's report template (dark slate
surfaces, gold accents, serif display headings - re-authored in-house
as module constants; nothing fetched, nothing verbatim). Pure planner:
assembling is string work only - no process spawning, no network
facilities, no file reads or writes. The clock is an INJECTED argument:
generated_at carries the injected stamp or None - never wall time, so
the same payload plus clock renders byte-identical output.

INPUT CONTRACT (assemble refuses only payload-level malformation; per
row/field malformation routes to "warnings" - render best-effort,
never crash):
  payload         required dict (non-dict -> ValueError)
  meta            optional dict (non-dict -> warning; defaults used)
    title         optional str - non-blank wins over DEFAULT_TITLE
    target        optional str - display-scrubbed, verbatim otherwise
    engagement_id optional str
    extra keys    absorbed silently
  executions      optional list of row dicts (non-list -> warning):
    command       optional str; absent -> the "(no command)" label
    target        optional str
    status        optional str
    extra keys    absorbed silently
  findings        optional list of row dicts (non-list -> warning):
    id            required str in the ID_RE charset; malformed ids
                  warn and render under MISSING_ID
    title         optional str; absent -> the heading shows the id
                  alone
    severity      optional; case/space-tolerant member of SEVERITIES
                  (normalized lowercase); absent -> no Severity bullet
                  (counted "unknown"); non-conforming -> warning,
                  rendered "unknown", counted "unknown"
    status        optional str
    evidence      optional str or list of str - evidence refs
    parser_summaries  optional str or list of str - parser summary
                  lines attached to the finding
    extra keys    absorbed silently
  parser_outputs  optional list of row dicts (non-list -> warning):
    parser        optional str; absent -> the "(unnamed parser)" label
    target        optional str
    summary       optional str
    extra keys    absorbed silently
Row values are str-or-None throughout: other types warn (REASON_*)
with the offending value and render nothing for the slot. Finding
sections sort by severity rank (critical first, unknown last; input
order inside a rank); executions and parser outputs keep input order.

RESULT SHAPE (assemble): {"markdown", "html", "counts", "warnings",
"generated_at"} - counts tally the section's INPUT rows, warnings are
plain deterministic strings (also rendered as the Warnings section),
and every rendered external string passes scrub_text (the module scrub
helper) then html.escape on the HTML path and md_escape (backticks +
leading "#") on the markdown path.

Traced-numbers gating is a different task (KA-088): this module is
standalone and imports nothing from the fleet.
"""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# --- contract constants (the drift alarm; the tests pin them) ------------

ID_RE = r"[A-Za-z0-9_.\-]{1,64}"
SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_UNKNOWN = "unknown"
SEVERITY_ORDER = SEVERITIES + (SEVERITY_UNKNOWN,)
SEVERITY_RANK = dict((name, rank) for rank, name in enumerate(SEVERITIES))
SEVERITY_RANK[SEVERITY_UNKNOWN] = len(SEVERITIES)
MISSING_ID = "<missing-id>"
NO_COMMAND_LABEL = "(no command)"
NO_PARSER_LABEL = "(unnamed parser)"
DEFAULT_TITLE = "Kali Agent Engagement Report"
REPORT_BRAND = "kali agent - engagement record"
EMPTY_FINDINGS = "No findings recorded."
EMPTY_EXECUTIONS = "No executions recorded."
EMPTY_PARSERS = "No parser outputs recorded."

REASON_META_TYPE = "meta must be a dict, got: %r"
REASON_LIST_TYPE = "%s must be a list, got: %r"
REASON_ROW_TYPE = "row must be a dict, got: %r"
REASON_FIELD_TYPE = "field '%s' must be a string, got: %r"
REASON_LIST_ITEM = "%s[%d] must be a string, got: %r"
REASON_ID_MISSING = "finding id missing"
REASON_ID_MALFORMED = "finding id malformed: %r"
REASON_SEVERITY = (
    "severity must be one of critical|high|medium|low, got: %r")

WARNING_FINDING = "finding %s: %s"
WARNING_EXECUTION = "execution #%d: %s"
WARNING_PARSER_ROW = "parser output #%d: %s"
WARNING_META = "meta: %s"

METAS = ("title", "target", "engagement_id")
EXECUTION_SLOTS = ("command", "target", "status")
PARSER_SLOTS = ("parser", "target", "summary")

# --- the theme (re-authored in-house: dark slate, gold, serif) -----------

THEME_BG_DARK = "#0f172a"
THEME_BG_PANEL = "#1e293b"
THEME_INK = "#e2e8f0"
THEME_MUTED = "#94a3b8"
THEME_GOLD = "#d4af37"
THEME_GOLD_SOFT = "#e8d9a6"
THEME_LINE = "#334155"
THEME_SEV_CRITICAL = "#ef6a6a"
THEME_SEV_HIGH = "#e8a052"
THEME_SEV_MEDIUM = "#d4c05e"
THEME_SEV_LOW = "#8fae8f"
THEME_HEADING_FONT = "Georgia, 'Times New Roman', serif"
THEME_BODY_FONT = "system-ui, 'Segoe UI', Arial, sans-serif"

_THEME_CSS_TEMPLATE = """\
/* report theme - re-authored in-house for the engagement reports
   (site report style: dark slate, gold accents, serif headings). */
:root {
  --paper: %(bg_dark)s;
  --surface: %(bg_panel)s;
  --ink: %(ink)s;
  --muted: %(muted)s;
  --gold: %(gold)s;
  --gold-soft: %(gold_soft)s;
  --line: %(line)s;
  --headings: %(headings)s;
  --body: %(body)s;
}
* { box-sizing: border-box; }
body { margin: 0 auto; padding: 2.5rem 1.5rem; max-width: 60rem;
  background: var(--paper); color: var(--ink);
  font: 1rem/1.55 var(--body); }
h1, h2, h3 { font-family: var(--headings); }
h1 { color: var(--gold); font-size: 1.9rem; margin: 0 0 .35rem; }
h2 { color: var(--gold-soft); font-size: 1.25rem;
  margin: 2.2rem 0 .8rem; border-bottom: 1px solid var(--line);
  padding-bottom: .3rem; }
h3 { color: var(--gold); font-size: 1.06rem; margin: 1.3rem 0 .45rem; }
a { color: var(--gold); }
.report-brand { color: var(--muted); font-size: .82rem;
  letter-spacing: .12em; text-transform: uppercase;
  margin: 0 0 .4rem; }
.report-meta { color: var(--muted); margin: .2rem 0 0; }
.report-meta .meta-item { margin-right: 1.2rem; white-space: nowrap; }
.summary-list { margin: .4rem 0; padding-left: 1.1rem; }
.finding { background: var(--surface); border: 1px solid var(--line);
  border-left: 4px solid var(--gold); border-radius: 6px;
  padding: 1rem 1.1rem; margin: 1rem 0; }
.finding-critical { border-left-color: %(sev_critical)s; }
.finding-high { border-left-color: %(sev_high)s; }
.finding-medium { border-left-color: %(sev_medium)s; }
.finding-low { border-left-color: %(sev_low)s; }
.finding-unknown { border-left-color: %(muted)s; }
.severity { font-weight: 700; letter-spacing: .04em; }
.severity-critical { color: %(sev_critical)s; }
.severity-high { color: %(sev_high)s; }
.severity-medium { color: %(sev_medium)s; }
.severity-low { color: %(sev_low)s; }
.severity-unknown { color: %(muted)s; }
.finding-fields { margin: .3rem 0 0; padding-left: 1.1rem; }
.field-label { color: var(--muted); font-size: .9rem; }
.execution-list, .parser-list { margin: .4rem 0; padding-left: 1.6rem; }
.warnings-list { color: var(--muted); font-size: .92rem;
  margin: .4rem 0; padding-left: 1.1rem; }
.empty-state { color: var(--muted); font-style: italic; }
"""

THEME_CSS = _THEME_CSS_TEMPLATE % {
    "bg_dark": THEME_BG_DARK,
    "bg_panel": THEME_BG_PANEL,
    "ink": THEME_INK,
    "muted": THEME_MUTED,
    "gold": THEME_GOLD,
    "gold_soft": THEME_GOLD_SOFT,
    "line": THEME_LINE,
    "headings": THEME_HEADING_FONT,
    "body": THEME_BODY_FONT,
    "sev_critical": THEME_SEV_CRITICAL,
    "sev_high": THEME_SEV_HIGH,
    "sev_medium": THEME_SEV_MEDIUM,
    "sev_low": THEME_SEV_LOW,
}


# --- the input gates -------------------------------------------------------


def scrub_text(value: Any) -> str:
    """The module scrub helper for every external string: strings
    only; escape-control noise is dropped and whitespace is folded so
    each rendered field stays a single clean line."""
    if not isinstance(value, str):
        raise ValueError("report text must be a string, got: %r" % (value,))
    return " ".join(value.replace("\x1b", "").split())


def md_escape(value: str) -> str:
    """The markdown path gate: backticks and a leading "#" are
    backslash-escaped so no external string adds a code span or a
    heading line."""
    escaped = value.replace("`", "\\`")
    if escaped.startswith("#"):
        escaped = "\\" + escaped
    return escaped


def _h(value: str) -> str:
    """The HTML path gate (html.escape, quotes included)."""
    return html.escape(value)


def _utc_stamp(moment: Any, slot: str) -> str:
    """An aware datetime -> the UTC +00:00 ISO stamp; anything else is
    a ValueError naming the slot."""
    if not isinstance(moment, datetime):
        raise ValueError(
            "%s must be an aware datetime, got: %r" % (slot, moment))
    if moment.utcoffset() is None:
        raise ValueError(
            "%s must be timezone-aware (reports stamp UTC +00:00), "
            "got naive: %r" % (slot, moment))
    return moment.astimezone(timezone.utc).isoformat()


# --- row field extraction --------------------------------------------------


def _field_text(row: Dict[str, Any],
                key: str) -> Tuple[Optional[str], List[str]]:
    """(text|None, reasons): a present string -> scrubbed text (blank
    reads as absent); None -> absent, silent; other types -> reason."""
    value = row.get(key)
    if value is None:
        return None, []
    if not isinstance(value, str):
        return None, [REASON_FIELD_TYPE % (key, value)]
    return (scrub_text(value) or None), []


def _field_text_list(row: Dict[str, Any], key: str
                     ) -> Tuple[Optional[List[str]], List[str]]:
    """(refs|None, reasons): a string -> [str]; a list/tuple -> the
    scrubbed non-blank strings (bad items warn with the index-tagged
    slot); None/empty/blank-only -> absent."""
    value = row.get(key)
    if value is None:
        return None, []
    if isinstance(value, str):
        text = scrub_text(value)
        return ([text] if text else None), []
    if isinstance(value, (list, tuple)):
        refs: List[str] = []
        reasons: List[str] = []
        for index, item in enumerate(value):
            if isinstance(item, str):
                text = scrub_text(item)
                if text:
                    refs.append(text)
            else:
                reasons.append(REASON_LIST_ITEM % (key, index, item))
        return ((refs or None), reasons)
    return None, [REASON_FIELD_TYPE % (key, value)]


def _row_fields(row: Any, slots: Tuple[str, ...]
                ) -> Tuple[Optional[Dict[str, Optional[str]]], List[str]]:
    """A list row -> (slot->text map|None, reasons): non-dict rows warn
    and render nothing; every slot is str-or-None."""
    if not isinstance(row, dict):
        return None, [REASON_ROW_TYPE % (row,)]
    fields: Dict[str, Optional[str]] = {}
    reasons: List[str] = []
    for slot in slots:
        text, slot_reasons = _field_text(row, slot)
        reasons.extend(slot_reasons)
        fields[slot] = text
    return fields, reasons


def _section_rows(payload: Dict[str, Any], name: str,
                  warnings_out: List[str]) -> List[Any]:
    """One payload section -> its input rows; missing -> [], mis-typed
    -> one warning and []."""
    rows = payload.get(name)
    if rows is None:
        return []
    if not isinstance(rows, (list, tuple)):
        warnings_out.append(REASON_LIST_TYPE % (name, rows))
        return []
    return list(rows)


def _finding_entry(finding: Dict[str, Any], index: int
                   ) -> Tuple[Dict[str, Any], List[str]]:
    """One findings row -> (entry, warnings). The entry carries the
    renderable fields plus severity rank/count data."""
    reasons: List[str] = []
    raw_id = finding.get("id")
    if not (isinstance(raw_id, str) and raw_id.strip()):
        label = MISSING_ID
        reasons.append(REASON_ID_MISSING)
    else:
        label = raw_id.strip()
        if not re.fullmatch(ID_RE, label):
            label = MISSING_ID
            reasons.append(REASON_ID_MALFORMED % (raw_id,))
    severity_value = finding.get("severity")
    norm_sev: Optional[str] = None
    if severity_value is not None:
        if (isinstance(severity_value, str)
                and severity_value.strip().lower() in SEVERITIES):
            norm_sev = severity_value.strip().lower()
        else:
            reasons.append(REASON_SEVERITY % (severity_value,))
    counted_as = norm_sev if norm_sev else SEVERITY_UNKNOWN
    shown = norm_sev
    if shown is None and severity_value is not None:
        shown = SEVERITY_UNKNOWN  # present-but-malformed: show unknown
    title, title_reasons = _field_text(finding, "title")
    status, status_reasons = _field_text(finding, "status")
    evidence, evidence_reasons = _field_text_list(finding, "evidence")
    parser_summaries, parser_reasons = _field_text_list(
        finding, "parser_summaries")
    reasons += title_reasons + status_reasons
    reasons += evidence_reasons + parser_reasons
    entry = {
        "label": label,
        "counted_as": counted_as,
        "shown": shown,
        "rank": SEVERITY_RANK[counted_as],
        "index": index,
        "title": title,
        "status": status,
        "evidence": evidence,
        "parser_summaries": parser_summaries,
    }
    return entry, [WARNING_FINDING % (label, r) for r in reasons]


# --- the markdown renderer -------------------------------------------------


def _severity_counts_line(by_severity: Dict[str, int]) -> str:
    """Every bucket in fixed SEVERITY_ORDER: 'critical 1, high 0, ...'"""
    return ", ".join(
        "%s %d" % (name, by_severity[name]) for name in SEVERITY_ORDER)


def _sub_line(slot: str, text: str) -> str:
    """An indented continuation bullet (executions/parser outputs)."""
    return "   - %s: %s" % (slot.capitalize(), md_escape(text))


def _finding_md_lines(entry: Dict[str, Any]) -> List[str]:
    """One finding subsection: the heading plus its present-field
    bullets (severity first, then status/evidence/parser lines)."""
    label = entry["label"]
    title = entry["title"]
    heading = label if title is None else "%s - %s" % (label, title)
    lines = ["### " + md_escape(heading)]
    if entry["shown"] is not None:
        lines.append("- Severity: %s" % (entry["shown"],))
    if entry["status"] is not None:
        lines.append("- Status: " + md_escape(entry["status"]))
    for ref in entry["evidence"] or []:
        lines.append("- Evidence: " + md_escape(ref))
    for summary in entry["parser_summaries"] or []:
        lines.append("- Parser summary: " + md_escape(summary))
    return lines


def _rows_md_lines(entries: List[Tuple[Optional[str],
                                       List[Tuple[str, str]]]],
                   number_label: str, fallback: str) -> List[str]:
    """Execution/parser entries -> numbered lines with indented
    sub-bullets (absent name/command slot renders the fallback)."""
    lines: List[str] = []
    for number, (name, sub_fields) in enumerate(entries, start=1):
        shown = name if name is not None else fallback
        lines.append("")
        lines.append("%d. %s" % (number, md_escape(shown)))
        lines.extend(
            "   - %s: %s" % (slot.capitalize(), md_escape(text))
            for slot, text in sub_fields)
    return lines


def _markdown_report(title: str, target: Optional[str],
                     engagement_id: Optional[str],
                     stamp: Optional[str],
                     counts: Dict[str, Any],
                     execution_entries: List[Tuple[
                         Optional[str], List[Tuple[str, str]]]],
                     finding_entries: List[Dict[str, Any]],
                     parser_entries: List[Tuple[
                         Optional[str], List[Tuple[str, str]]]],
                     warnings_out: List[str]) -> str:
    """The themed markdown report (byte-deterministic)."""
    blocks: List[str] = []
    header = ["# " + md_escape(title)]
    if target is not None:
        header.append("- Target: " + md_escape(target))
    if engagement_id is not None:
        header.append("- Engagement: " + md_escape(engagement_id))
    if stamp is not None:
        header.append("- Generated: " + stamp)
    blocks.append("\n".join(header))
    blocks.append("\n".join([
        "## Executive summary",
        "",
        "- Findings: %d (%s)" % (counts["findings"]["total"],
                                 _severity_counts_line(
                                     counts["findings"]["by_severity"])),
        "- Executions: %d" % (counts["executions"]["total"],),
        "- Parser outputs: %d" % (counts["parser_outputs"]["total"],),
        "- Warnings: %d" % (counts["warnings"],),
    ]))
    findings_lines = ["## Findings"]
    if not finding_entries:
        findings_lines.append("")
        findings_lines.append(EMPTY_FINDINGS)
    else:
        for entry in finding_entries:
            findings_lines.extend([""] + _finding_md_lines(entry))
    blocks.append("\n".join(findings_lines))
    executions_lines = ["## Executions"]
    if not execution_entries:
        executions_lines.extend(["", EMPTY_EXECUTIONS])
    else:
        executions_lines.extend(_rows_md_lines(
            execution_entries, "execution", NO_COMMAND_LABEL))
    blocks.append("\n".join(executions_lines))
    parsers_lines = ["## Parser outputs"]
    if not parser_entries:
        parsers_lines.extend(["", EMPTY_PARSERS])
    else:
        parsers_lines.extend(_rows_md_lines(
            parser_entries, "parser output", NO_PARSER_LABEL))
    blocks.append("\n".join(parsers_lines))
    if warnings_out:
        blocks.append("\n".join(
            ["## Warnings", ""]
            + ["- " + md_escape(warning) for warning in warnings_out]))
    return "\n\n".join(blocks) + "\n"


# --- the html renderer -----------------------------------------------------


def _finding_html_lines(entry: Dict[str, Any]) -> List[str]:
    lines = [
        '<article class="finding finding-%s">' % (entry["counted_as"],)]
    label = entry["label"]
    title = entry["title"]
    heading = label if title is None else "%s - %s" % (label, title)
    lines.append("<h3>%s</h3>" % _h(heading))
    lines.append('<ul class="finding-fields">')
    if entry["shown"] is not None:
        severity = entry["counted_as"]
        lines.append(
            '<li><span class="field-label">Severity:</span> '
            '<span class="severity severity-%s">%s</span></li>'
            % (severity, _h(severity)))
    if entry["status"] is not None:
        lines.append('<li><span class="field-label">Status:</span> %s</li>'
                     % _h(entry["status"]))
    for ref in entry["evidence"] or []:
        lines.append('<li><span class="field-label">Evidence:</span> '
                     '%s</li>' % _h(ref))
    for summary in entry["parser_summaries"] or []:
        lines.append('<li><span class="field-label">Parser summary:</span> '
                     '%s</li>' % _h(summary))
    lines.append("</ul>")
    lines.append("</article>")
    return lines


def _rows_html_lines(entries: List[Tuple[Optional[str],
                                         List[Tuple[str, str]]]],
                     list_class: str, name_class: str,
                     fallback: str) -> List[str]:
    lines = ['<ol class="%s">' % (list_class,)]
    for _number, (name, sub_fields) in enumerate(entries, start=1):
        shown = name if name is not None else fallback
        lines.append("<li>")
        lines.append('<span class="%s">%s</span>'
                     % (name_class, _h(shown)))
        if sub_fields:
            lines.append("<ul>")
            lines.extend(
                '<li><span class="field-label">%s:</span> %s</li>'
                % (slot.capitalize(), _h(text))
                for slot, text in sub_fields)
            lines.append("</ul>")
        lines.append("</li>")
    lines.append("</ol>")
    return lines


def _html_report(title: str, target: Optional[str],
                 engagement_id: Optional[str], stamp: Optional[str],
                 counts: Dict[str, Any],
                 execution_entries: List[Tuple[
                     Optional[str], List[Tuple[str, str]]]],
                 finding_entries: List[Dict[str, Any]],
                 parser_entries: List[Tuple[
                     Optional[str], List[Tuple[str, str]]]],
                 warnings_out: List[str]) -> str:
    """The themed html report (html.escape on every rendered external
    string; byte-deterministic)."""
    parts: List[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, '
        'initial-scale=1">',
        "<title>%s</title>" % _h(title),
        "<style>",
        THEME_CSS,
        "</style>",
        "</head>",
        "<body>",
        '<header class="report-header">',
        '<p class="report-brand">%s</p>' % _h(REPORT_BRAND),
        '<h1 class="report-title">%s</h1>' % _h(title),
    ]
    meta_items = []
    if target is not None:
        meta_items.append('<span class="meta-item">Target: %s</span>'
                          % _h(target))
    if engagement_id is not None:
        meta_items.append('<span class="meta-item">Engagement: %s</span>'
                          % _h(engagement_id))
    if stamp is not None:
        meta_items.append('<span class="meta-item">Generated: %s</span>'
                          % stamp)
    if meta_items:
        parts.append('<p class="report-meta">%s</p>' % "".join(meta_items))
    parts.append("</header>")
    parts.append('<section class="executive-summary">')
    parts.append("<h2>Executive summary</h2>")
    parts.append('<ul class="summary-list">')
    parts.extend(
        '<li><span class="field-label">%s</span> %s</li>' % (label, value)
        for label, value in (
            ("Findings:", "%d (%s)" % (
                counts["findings"]["total"],
                _severity_counts_line(
                    counts["findings"]["by_severity"]))),
            ("Executions:", "%d" % (counts["executions"]["total"],)),
            ("Parser outputs:",
             "%d" % (counts["parser_outputs"]["total"],)),
            ("Warnings:", "%d" % (counts["warnings"],))))
    parts.append("</ul>")
    parts.append("</section>")
    parts.append('<section class="findings">')
    parts.append("<h2>Findings</h2>")
    if not finding_entries:
        parts.append('<p class="empty-state">%s</p>' % _h(EMPTY_FINDINGS))
    else:
        for entry in finding_entries:
            parts.extend(_finding_html_lines(entry))
    parts.append("</section>")
    parts.append('<section class="executions">')
    parts.append("<h2>Executions</h2>")
    if not execution_entries:
        parts.append('<p class="empty-state">%s</p>' % _h(EMPTY_EXECUTIONS))
    else:
        parts.extend(_rows_html_lines(execution_entries,
                                      "execution-list",
                                      "execution-command",
                                      NO_COMMAND_LABEL))
    parts.append("</section>")
    parts.append('<section class="parser-outputs">')
    parts.append("<h2>Parser outputs</h2>")
    if not parser_entries:
        parts.append('<p class="empty-state">%s</p>' % _h(EMPTY_PARSERS))
    else:
        parts.extend(_rows_html_lines(parser_entries, "parser-list",
                                      "parser-name", NO_PARSER_LABEL))
    parts.append("</section>")
    if warnings_out:
        parts.append('<section class="warnings">')
        parts.append("<h2>Warnings</h2>")
        parts.append('<ul class="warnings-list">')
        parts.extend("<li>%s</li>" % _h(warning)
                     for warning in warnings_out)
        parts.append("</ul>")
        parts.append("</section>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts) + "\n"


# --- the op ----------------------------------------------------------------


def assemble(payload: Any, now: Any = None) -> Dict[str, Any]:
    """Fold the structured run record {meta, executions, findings,
    parser_outputs} into one themed engagement report; the clock is
    injected (generated_at None without one - never wall time)."""
    if not isinstance(payload, dict):
        raise ValueError(
            "report payload must be a dict, got: %r" % (payload,))
    stamp = _utc_stamp(now, "now") if now is not None else None
    warnings_out: List[str] = []

    meta_fields: Dict[str, Optional[str]] = dict(
        (slot, None) for slot in METAS)
    meta = payload.get("meta")
    if meta is not None:
        if not isinstance(meta, dict):
            warnings_out.append(REASON_META_TYPE % (meta,))
        else:
            for slot in METAS:
                text, reasons = _field_text(meta, slot)
                warnings_out.extend(
                    WARNING_META % (reason,) for reason in reasons)
                meta_fields[slot] = text
    title = meta_fields["title"] or DEFAULT_TITLE
    target = meta_fields["target"]
    engagement_id = meta_fields["engagement_id"]

    finding_rows = _section_rows(payload, "findings", warnings_out)
    finding_entries: List[Dict[str, Any]] = []
    for index, row in enumerate(finding_rows):
        if not isinstance(row, dict):
            warnings_out.append(
                WARNING_FINDING % (MISSING_ID, REASON_ROW_TYPE % (row,)))
            continue
        entry, reasons = _finding_entry(row, index)
        warnings_out.extend(reasons)
        finding_entries.append(entry)
    finding_entries.sort(key=lambda entry: (entry["rank"],
                                            entry["index"]))

    execution_entries: List[Tuple[Optional[str],
                                  List[Tuple[str, str]]]] = []
    execution_rows = _section_rows(payload, "executions", warnings_out)
    for index, row in enumerate(execution_rows):
        fields, reasons = _row_fields(row, EXECUTION_SLOTS)
        warnings_out.extend(
            WARNING_EXECUTION % (index + 1, reason) for reason in reasons)
        if fields is None:
            continue
        sub_fields = [(slot, fields[slot])
                      for slot in ("target", "status")
                      if fields[slot] is not None]
        execution_entries.append((fields["command"], sub_fields))

    parser_entries: List[Tuple[Optional[str],
                               List[Tuple[str, str]]]] = []
    parser_rows = _section_rows(payload, "parser_outputs", warnings_out)
    for index, row in enumerate(parser_rows):
        fields, reasons = _row_fields(row, PARSER_SLOTS)
        warnings_out.extend(
            WARNING_PARSER_ROW % (index + 1, reason)
            for reason in reasons)
        if fields is None:
            continue
        sub_fields = [(slot, fields[slot])
                      for slot in ("target", "summary")
                      if fields[slot] is not None]
        parser_entries.append((fields["parser"], sub_fields))

    by_severity: Dict[str, int] = dict((name, 0) for name in SEVERITIES)
    by_severity[SEVERITY_UNKNOWN] = 0
    for entry in finding_entries:
        by_severity[entry["counted_as"]] += 1
    counts = {
        "findings": {"total": len(finding_rows),
                     "by_severity": by_severity},
        "executions": {"total": len(execution_rows)},
        "parser_outputs": {"total": len(parser_rows)},
        "warnings": len(warnings_out),
    }
    return {
        "markdown": _markdown_report(
            title, target, engagement_id, stamp, counts,
            execution_entries, finding_entries, parser_entries,
            warnings_out),
        "html": _html_report(
            title, target, engagement_id, stamp, counts,
            execution_entries, finding_entries, parser_entries,
            warnings_out),
        "counts": counts,
        "warnings": warnings_out,
        "generated_at": stamp,
    }
