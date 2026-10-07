"""KA-081 tests - report assembler: the assemble() result shape, the
payload contract (payload-level refusals vs per-row/field warning
routing), mistyped-section guards, meta header rendering (title /
target / engagement_id + the default title), the severity contract
(normalization, absent-vs-malformed rendering, by-severity counts),
finding id handling (ID_RE charset, stripped tolerant forms, the
MISSING_ID fallback), field render rules (present/blank/absent),
evidence and parser_summaries str-or-list shapes, execution and
parser-output row rendering with numbered lines and absent-slot
fallback labels, the injected clock (None default, aware UTC
normalization, naive/non-datetime refusals - never wall time),
deterministic byte-identical output, html.escape coverage on the HTML
path and md_escape (backticks + leading "#") on the markdown path,
the in-house theme constants (dark slate + gold + serif headings),
JSON round-trips, and the planner-purity source scan. No network, no
fixtures, no file I/O - assembling is pure string work. Traced-number
gating (KA-088) is deliberately absent here."""

from __future__ import annotations

import importlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.report_assembler import (
    DEFAULT_TITLE,
    EMPTY_EXECUTIONS,
    EMPTY_FINDINGS,
    EMPTY_PARSERS,
    ID_RE,
    MISSING_ID,
    NO_COMMAND_LABEL,
    NO_PARSER_LABEL,
    REASON_FIELD_TYPE,
    REASON_ID_MALFORMED,
    REASON_ID_MISSING,
    REASON_LIST_ITEM,
    REASON_LIST_TYPE,
    REASON_META_TYPE,
    REASON_ROW_TYPE,
    REASON_SEVERITY,
    SEVERITIES,
    SEVERITY_ORDER,
    SEVERITY_RANK,
    SEVERITY_UNKNOWN,
    THEME_BG_DARK,
    THEME_BG_PANEL,
    THEME_BODY_FONT,
    THEME_CSS,
    THEME_GOLD,
    THEME_GOLD_SOFT,
    THEME_HEADING_FONT,
    THEME_INK,
    THEME_LINE,
    THEME_MUTED,
    THEME_SEV_CRITICAL,
    THEME_SEV_HIGH,
    THEME_SEV_LOW,
    THEME_SEV_MEDIUM,
    WARNING_EXECUTION,
    WARNING_FINDING,
    WARNING_META,
    WARNING_PARSER_ROW,
    assemble,
    md_escape,
    scrub_text,
)

UTC = timezone.utc
NOW = datetime(2026, 10, 7, 19, 48, 0, tzinfo=UTC)  # arbitrary fixed clock

EXEC_KEYS = {"markdown", "html", "counts", "warnings", "generated_at"}
SEV_BUCKETS = ("critical", "high", "medium", "low", "unknown")


def mixed_payload():
    """The canonical mixed record: two executions (one command-less),
    three findings across ranks (one missing severity, one malformed
    id, one refused list item), one parser output, hostile HTML. The
    integrator's wiring assembles this shape from agent runs."""
    return {
        "meta": {"title": "Web sweep - 10.0.0.5", "target": "10.0.0.5",
                 "engagement_id": "ENG-42"},
        "executions": [
            {"command": "nmap -sV 10.0.0.5", "target": "10.0.0.5",
             "status": "ok"},
            {"target": "10.0.0.6", "status": "auth-required"},
        ],
        "findings": [
            {"id": "F-02", "title": "SMBv1 enabled", "severity": "  HIGH  ",
             "status": "open",
             "evidence": ["gus2:~/findings/F-02.txt", 42]},
            {"id": "F-01", "title": "<script>alert(1)</script>",
             "severity": "CRITICAL",
             "parser_summaries": "nmap: 3 open ports"},
            {"id": "bad id!", "severity": "banana"},
        ],
        "parser_outputs": [
            {"parser": "nmap-json", "target": "10.0.0.5",
             "summary": "3 open ports"},
        ],
    }


MIXED_MD = "\n".join([
    "# Web sweep - 10.0.0.5",
    "- Target: 10.0.0.5",
    "- Engagement: ENG-42",
    "",
    "## Executive summary",
    "",
    "- Findings: 3 (critical 1, high 1, medium 0, low 0, unknown 1)",
    "- Executions: 2",
    "- Parser outputs: 1",
    "- Warnings: 3",
    "",
    "## Findings",
    "",
    "### F-01 - <script>alert(1)</script>",
    "- Severity: critical",
    "- Parser summary: nmap: 3 open ports",
    "",
    "### F-02 - SMBv1 enabled",
    "- Severity: high",
    "- Status: open",
    "- Evidence: gus2:~/findings/F-02.txt",
    "",
    "### <missing-id>",
    "- Severity: unknown",
    "",
    "## Executions",
    "",
    "1. nmap -sV 10.0.0.5",
    "   - Target: 10.0.0.5",
    "   - Status: ok",
    "",
    "2. (no command)",
    "   - Target: 10.0.0.6",
    "   - Status: auth-required",
    "",
    "## Parser outputs",
    "",
    "1. nmap-json",
    "   - Target: 10.0.0.5",
    "   - Summary: 3 open ports",
    "",
    "## Warnings",
    "",
    "- finding F-02: evidence[1] must be a string, got: 42",
    "- finding <missing-id>: finding id malformed: 'bad id!'",
    "- finding <missing-id>: severity must be one of "
    "critical|high|medium|low, got: 'banana'",
]) + "\n"

MIXED_COUNTS = {
    "findings": {"total": 3,
                 "by_severity": {"critical": 1, "high": 1, "medium": 0,
                                 "low": 0, "unknown": 1}},
    "executions": {"total": 2},
    "parser_outputs": {"total": 1},
    "warnings": 3,
}

MIXED_WARNINGS = [
    "finding F-02: evidence[1] must be a string, got: 42",
    "finding <missing-id>: finding id malformed: 'bad id!'",
    "finding <missing-id>: severity must be one of "
    "critical|high|medium|low, got: 'banana'",
]

EMPTY_MD = "\n".join([
    "# " + DEFAULT_TITLE,
    "",
    "## Executive summary",
    "",
    "- Findings: 0 (critical 0, high 0, medium 0, low 0, unknown 0)",
    "- Executions: 0",
    "- Parser outputs: 0",
    "- Warnings: 0",
    "",
    "## Findings",
    "",
    EMPTY_FINDINGS,
    "",
    "## Executions",
    "",
    EMPTY_EXECUTIONS,
    "",
    "## Parser outputs",
    "",
    EMPTY_PARSERS,
]) + "\n"


# --- result shape, empty payload, determinism ------------------------------


def test_result_shape_keys():
    result = assemble({})
    assert set(result) == EXEC_KEYS
    assert result["markdown"] == EMPTY_MD
    assert result["generated_at"] is None
    assert result["warnings"] == []


def test_empty_payload_counts_exact():
    assert assemble({})["counts"] == {
        "findings": {"total": 0, "by_severity": dict(
            (name, 0) for name in SEV_BUCKETS)},
        "executions": {"total": 0},
        "parser_outputs": {"total": 0},
        "warnings": 0}


def test_empty_payload_markdown_exact():
    assert assemble({})["markdown"] == EMPTY_MD
    assert assemble({})["markdown"].endswith("\n")


def test_no_clock_no_generated_line():
    # default assembly and an explicit now=None are the same call
    quiet = assemble({})
    explicit = assemble({}, now=None)
    assert quiet == explicit
    assert "Generated" not in quiet["markdown"]
    assert "Generated" not in quiet["html"]


def test_determinism_and_json_roundtrip():
    first = assemble(mixed_payload(), NOW)
    second = assemble(mixed_payload(), NOW)
    assert first["markdown"] == second["markdown"]
    assert first["html"] == second["html"]
    assert first["counts"] == second["counts"]
    assert first["warnings"] == second["warnings"]
    clone = json.loads(json.dumps(first["counts"]))
    assert clone == first["counts"]


# --- the injected clock ------------------------------------------------------


def test_injected_clock_stamps_sections():
    result = assemble(mixed_payload(), NOW)
    assert result["generated_at"] == "2026-10-07T19:48:00+00:00"
    assert "- Generated: 2026-10-07T19:48:00+00:00" in result["markdown"]
    assert ("Generated: 2026-10-07T19:48:00+00:00" in result["html"])


def test_clock_non_utc_normalized():
    now2h = datetime(2026, 10, 7, 21, 48, 0,
                     tzinfo=timezone(timedelta(hours=2)))
    result = assemble(mixed_payload(), now2h)
    assert result["generated_at"] == "2026-10-07T19:48:00+00:00"


@pytest.mark.parametrize("bad_now", [
    datetime(2026, 10, 7, 19, 48), "now-ish"])
def test_clock_refused(bad_now):
    with pytest.raises(ValueError, match="must be an aware datetime|"
                                         "must be timezone-aware"):
        assemble({}, now=bad_now)


# --- payload-level refusals + section guards --------------------------------


@pytest.mark.parametrize("bad_payload", [None, 42])
def test_payload_non_dict_refused(bad_payload):
    with pytest.raises(ValueError, match="report payload must be a dict"):
        assemble(bad_payload)


@pytest.mark.parametrize("section", ["meta", "executions", "findings",
                                     "parser_outputs"])
def test_mistyped_sections_warn_treated_empty(section):
    bad = [] if section == "meta" else 42
    result = assemble({section: bad})
    if section == "meta":
        assert result["warnings"] == [REASON_META_TYPE % ([],)]
    else:
        assert result["warnings"] == [REASON_LIST_TYPE % (section, 42)]
    assert result["counts"]["warnings"] == 1
    assert result["markdown"] == "\n".join([
        "# " + DEFAULT_TITLE, "",
        "## Executive summary", "",
        "- Findings: 0 (critical 0, high 0, medium 0, low 0, "
        "unknown 0)",
        "- Executions: 0",
        "- Parser outputs: 0",
        "- Warnings: 1", "",
        "## Findings", "", EMPTY_FINDINGS, "",
        "## Executions", "", EMPTY_EXECUTIONS, "",
        "## Parser outputs", "", EMPTY_PARSERS, "",
        "## Warnings", "",
    ] + ["- " + w for w in result["warnings"]]) + "\n"
    assert result["generated_at"] is None


def test_non_dict_rows_warn_not_rendered():
    result = assemble({"findings": [42], "executions": ["x"],
                       "parser_outputs": [None]})
    assert result["warnings"] == [
        WARNING_FINDING % (MISSING_ID, REASON_ROW_TYPE % (42,)),
        WARNING_EXECUTION % (1, REASON_ROW_TYPE % ("x",)),
        WARNING_PARSER_ROW % (1, REASON_ROW_TYPE % (None,))]
    # input rows still tally; garbage rows render nothing
    assert result["counts"]["findings"]["total"] == 1
    assert result["counts"]["executions"]["total"] == 1
    assert result["counts"]["parser_outputs"]["total"] == 1
    assert result["markdown"] == "\n".join([
        "# " + DEFAULT_TITLE, "",
        "## Executive summary", "",
        "- Findings: 1 (critical 0, high 0, medium 0, low 0, "
        "unknown 0)",
        "- Executions: 1",
        "- Parser outputs: 1",
        "- Warnings: 3", "",
        "## Findings", "", EMPTY_FINDINGS, "",
        "## Executions", "", EMPTY_EXECUTIONS, "",
        "## Parser outputs", "", EMPTY_PARSERS, "",
        "## Warnings", "",
    ] + ["- " + w for w in result["warnings"]]) + "\n"


# --- meta contract ------------------------------------------------------------


def test_meta_header_and_default_title():
    titled = assemble({"meta": {"title": "Web sweep", "target": "10.0.0.5",
                                "engagement_id": "ENG-42",
                                "unheard": "absorbed"}})
    lines = titled["markdown"].splitlines()
    assert lines[0] == "# Web sweep"
    assert lines[1] == "- Target: 10.0.0.5"
    assert lines[2] == "- Engagement: ENG-42"
    assert '<h1 class="report-title">Web sweep</h1>' in titled["html"]
    assert ('<span class="meta-item">Target: 10.0.0.5</span>'
            in titled["html"])
    assert ('<span class="meta-item">Engagement: ENG-42</span>'
            in titled["html"])

    plain = assemble({})
    assert plain["markdown"].startswith("# " + DEFAULT_TITLE + "\n")
    assert "- Target:" not in plain["markdown"]
    assert 'class="report-meta"' not in plain["html"]


@pytest.mark.parametrize("slot,bad", [("title", 42), ("target", [])])
def test_meta_field_type_warnings(slot, bad):
    result = assemble({"meta": {slot: bad}})
    assert result["warnings"] == [
        WARNING_META % (REASON_FIELD_TYPE % (slot, bad))]
    assert result["counts"]["warnings"] == 1


# --- the finding severity contract ---------------------------------------------


def test_severity_contract_rendering():
    # valid: case/space tolerant, normalized lowercase, no warning
    norm = assemble({"findings": [{"id": "F-1", "severity": "  HIGH  "}]})
    assert "- Severity: high" in norm["markdown"]
    assert norm["warnings"] == []
    assert norm["counts"]["findings"]["by_severity"]["high"] == 1

    # malformed: warning + rendered unknown + unknown bucket
    bad = assemble({"findings": [{"id": "F-1", "severity": "banana"}]})
    assert "- Severity: unknown" in bad["markdown"]
    assert bad["warnings"] == [WARNING_FINDING % ("F-1", REASON_SEVERITY
                                                % ("banana",))]
    assert bad["counts"]["findings"]["by_severity"]["unknown"] == 1

    blank = assemble({"findings": [{"id": "F-1", "severity": ""}]})
    assert blank["warnings"] == [WARNING_FINDING
                                 % ("F-1", REASON_SEVERITY % ("",))]

    # absent: no Severity bullet at all, counted unknown, no warning
    absent = assemble({"findings": [{"id": "F-1", "status": "open"}]})
    assert "- Severity:" not in absent["markdown"]
    assert absent["warnings"] == []
    assert absent["counts"]["findings"]["by_severity"]["unknown"] == 1


@pytest.mark.parametrize("bad_id,expected", [
    (None, [REASON_ID_MISSING]),
    ("   ", [REASON_ID_MISSING]),
    ("bad id!", [REASON_ID_MALFORMED % ("bad id!",)]),
    ("x" * 65, [REASON_ID_MALFORMED % ("x" * 65,)]),
    ("  F-9  ", []),  # surrounding whitespace is stripped, then valid
])
def test_finding_id_contract(bad_id, expected):
    result = assemble({"findings": [{"id": bad_id, "title": "t"}]})
    label = (bad_id.strip() if isinstance(bad_id, str) and bad_id.strip()
             else MISSING_ID) if expected == [] else MISSING_ID
    assert result["warnings"] == [WARNING_FINDING % (label, r)
                                  for r in expected]
    assert any(line == "### %s - t" % (label,)
               for line in result["markdown"].splitlines())


def test_finding_field_rules():
    # present strings render; blank strings read as absent; absent
    # fields omit their bullet; junk types warn and render nothing
    result = assemble({"findings": [{
        "id": "F-1", "title": "  spaced title ", "status": "  open  ",
        "evidence": "gus2:~/ref.txt"}]})
    lines = result["markdown"].splitlines()
    start = lines.index("## Findings")
    assert lines[start:start + 5] == [
        "## Findings", "",
        "### F-1 - spaced title",
        "- Status: open",
        "- Evidence: gus2:~/ref.txt"]
    assert not any(line.startswith("- Severity") for line in lines)
    assert result["warnings"] == []

    blanky = assemble({"findings": [{
        "id": "F-1", "title": "   ", "status": "", "evidence": []}]})
    blines = blanky["markdown"].splitlines()
    bstart = blines.index("## Findings")
    assert blines[bstart:bstart + 3] == ["## Findings", "", "### F-1"]
    assert blanky["warnings"] == []

    junk = assemble({"findings": [{
        "id": "F-1", "title": 42, "status": ["open"]}]})
    assert junk["warnings"] == [
        WARNING_FINDING % ("F-1", REASON_FIELD_TYPE % ("title", 42)),
        WARNING_FINDING % ("F-1", REASON_FIELD_TYPE % ("status",
                                                       ["open"]))]
    assert "### F-1" in junk["markdown"]
    assert "- Status:" not in junk["markdown"]


@pytest.mark.parametrize("slot", ["evidence", "parser_summaries"])
def test_evidence_parser_summaries_shapes(slot):
    label = {"evidence": "Evidence",
             "parser_summaries": "Parser summary"}[slot]
    prefix = "- %s: " % (label,)

    single = assemble({"findings": [{"id": "F-1", slot: "single ref"}]})
    assert prefix + "single ref" in single["markdown"].splitlines()
    assert single["warnings"] == []

    multi = assemble({"findings": [{"id": "F-1",
                                    slot: ["one", 42, "two"]}]})
    assert multi["warnings"] == [
        WARNING_FINDING % ("F-1", REASON_LIST_ITEM % (slot, 1, 42))]
    assert prefix + "one" in multi["markdown"].splitlines()
    assert prefix + "two" in multi["markdown"].splitlines()

    blank = assemble({"findings": [{"id": "F-1", slot: "   "}]})
    assert blank["warnings"] == []
    assert not any(line.startswith(prefix)
                   for line in blank["markdown"].splitlines())


# --- executions + parser outputs ------------------------------------------------


def test_execution_rows_rendering():
    rows = [
        {"command": "nmap -sV 10.0.0.5", "target": "10.0.0.5",
         "status": "ok"},
        {"zzz": "absorbed"},                     # extra keys; (no command)
        42,                                      # garbage row, warns
        {"command": "id", "target": "", "status": "  ok  "},
    ]
    result = assemble({"executions": rows})
    assert result["warnings"] == [
        WARNING_EXECUTION % (3, REASON_ROW_TYPE % (42,))]
    lines = result["markdown"].splitlines()
    start = lines.index("## Executions")
    assert lines[start:start + 10] == [
        "## Executions",
        "",
        "1. nmap -sV 10.0.0.5",
        "   - Target: 10.0.0.5",
        "   - Status: ok",
        "",
        "2. " + NO_COMMAND_LABEL,
        "",
        "3. id",
        "   - Status: ok"]
    assert result["counts"]["executions"]["total"] == 4
    # input numbering survives the garbage row; blank fields omitted
    assert "Target:" not in result["markdown"].split("3. id")[1]


def test_parser_output_rows_rendering():
    rows = [
        {"parser": "nmap-json", "target": "10.0.0.5",
         "summary": "3 open ports"},
        {"summary": "orphan"},                   # unnamed parser
    ]
    result = assemble({"parser_outputs": rows})
    assert result["warnings"] == []
    lines = result["markdown"].splitlines()
    start = lines.index("## Parser outputs")
    assert lines[start:start + 8] == [
        "## Parser outputs",
        "",
        "1. nmap-json",
        "   - Target: 10.0.0.5",
        "   - Summary: 3 open ports",
        "",
        "2. " + NO_PARSER_LABEL,
        "   - Summary: orphan"]


# --- escaping gates ---------------------------------------------------------------


@pytest.mark.parametrize("hostile,rendered", [
    ("<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;"),
    ("<img src=x onerror=y>", "&lt;img src=x onerror=y&gt;"),
])
def test_html_escapes_external_strings(hostile, rendered):
    result = assemble({"meta": {"title": hostile},
                       "findings": [{"id": "F-1", "status": hostile}]})
    assert rendered in result["html"]
    assert "<script" not in result["html"]
    assert "<img" not in result["html"]
    assert hostile in result["markdown"]  # markdown path: spec allows


def test_markdown_escape_gates_and_scrub_units():
    # direct unit pins: scrub folds ESC + whitespace; md_escape
    # backslash-escapes backticks and a LEADING # (mid-# stays verbatim)
    assert scrub_text("  a\x1b[31mred\nb  ") == "a[31mred b"
    with pytest.raises(ValueError):
        scrub_text(42)
    assert md_escape("a`b`c") == "a\\`b\\`c"
    assert md_escape("# top") == "\\# top"
    assert md_escape("mid # hash") == "mid # hash"
    assert md_escape("") == ""

    # end-to-end: scrubbed, then escaped through the markdown path
    result = assemble({"meta": {"title": "# leaked `whoami`"},
                       "findings": [{"id": "F-1",
                                     "evidence": "#ref-`1`"}],
                       "executions": [{"command": "`ps aux`"}]})
    assert result["markdown"].splitlines()[0] == "# \\# leaked \\`whoami\\`"
    assert "- Evidence: \\#ref-\\`1\\`" in result["markdown"]
    assert "1. \\`ps aux\\`" in result["markdown"]
    assert "\\" not in result["html"]  # html path: no markdown escapes


# --- the theme constants ------------------------------------------------------------


def test_theme_serif_and_tokens():
    assert THEME_HEADING_FONT == "Georgia, 'Times New Roman', serif"
    assert THEME_GOLD == "#d4af37"
    assert THEME_BG_DARK == "#0f172a"
    assert THEME_BG_PANEL == "#1e293b"
    # every token name survives into the rendered stylesheet
    assert "--paper: %s" % THEME_BG_DARK in THEME_CSS
    assert "--surface: %s" % THEME_BG_PANEL in THEME_CSS
    assert "--gold: %s" % THEME_GOLD in THEME_CSS
    assert "--gold-soft: %s" % THEME_GOLD_SOFT in THEME_CSS
    assert "--ink: %s" % THEME_INK in THEME_CSS
    assert "--muted: %s" % THEME_MUTED in THEME_CSS
    assert "--line: %s" % THEME_LINE in THEME_CSS
    assert "--headings: %s" % THEME_HEADING_FONT in THEME_CSS
    assert "--body: %s" % THEME_BODY_FONT in THEME_CSS
    for token in (THEME_SEV_CRITICAL, THEME_SEV_HIGH, THEME_SEV_MEDIUM,
                  THEME_SEV_LOW):
        assert token in THEME_CSS
    # serif display headings + the gold accent on h1/h3
    assert THEME_CSS.count("font-family: var(--headings)") == 1
    assert "h1 { color: var(--gold);" in THEME_CSS


def test_theme_css_embedded_in_html():
    html_doc = assemble({})["html"]
    assert html_doc.count("<style>") == 1
    assert THEME_CSS in html_doc
    assert "</style>" in html_doc


# --- contract constants (the drift alarm) ---------------------------------------------


def test_contract_constants_pinned():
    assert DEFAULT_TITLE == "Kali Agent Engagement Report"
    assert MISSING_ID == "<missing-id>"
    assert NO_COMMAND_LABEL == "(no command)"
    assert NO_PARSER_LABEL == "(unnamed parser)"
    assert SEVERITIES == ("critical", "high", "medium", "low")
    assert SEVERITY_UNKNOWN == "unknown"
    assert SEVERITY_ORDER == SEVERITIES + (SEVERITY_UNKNOWN,)
    assert SEVERITY_RANK == {"critical": 0, "high": 1, "medium": 2,
                             "low": 3, "unknown": 4}
    assert ID_RE == r"[A-Za-z0-9_.\-]{1,64}"
    assert REASON_ID_MISSING == "finding id missing"
    assert WARNING_FINDING == "finding %s: %s"
    assert WARNING_EXECUTION == "execution #%d: %s"
    assert WARNING_PARSER_ROW == "parser output #%d: %s"
    assert WARNING_META == "meta: %s"


# --- planner purity ---------------------------------------------------------------------


def test_planner_purity_source_scan():
    module = importlib.import_module(
        "agentic_ai.agents.cyber.report_assembler")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("from agentic_ai", "import agentic_ai",
                   "utcnow", "time.time", "today()", "datetime.now",
                   "subprocess", "popen", "os.system",
                   "eval(", "exec(",
                   "urllib", "socket", "requests", "http.client",
                   "open(", "Path(", "write_text"):
        assert banned not in source, banned


# --- the mixed payload: exact pins across the three render surfaces ----------------------


def test_mixed_counts_and_warnings_exact():
    result = assemble(mixed_payload())
    assert result["counts"] == MIXED_COUNTS
    assert result["warnings"] == MIXED_WARNINGS
    assert result["generated_at"] is None


def test_mixed_markdown_exact():
    assert assemble(mixed_payload())["markdown"] == MIXED_MD


def test_mixed_html_markers():
    html_doc = assemble(mixed_payload())["html"]
    assert html_doc.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in html_doc
    for klass in ("executive-summary", "findings", "executions",
                  "parser-outputs", "warnings"):
        assert '<section class="%s">' % (klass,) in html_doc
    # severity rank ordering: critical article first, unknown last
    assert html_doc.index("finding-critical") < html_doc.index(
        "finding-high") < html_doc.index("finding-unknown")
    assert ('<h3>F-01 - &lt;script&gt;alert(1)&lt;/script&gt;</h3>'
            in html_doc)
    assert ('<span class="severity severity-critical">critical</span>'
            in html_doc)
    assert '<span class="execution-command">' in html_doc
    assert NO_COMMAND_LABEL in html_doc
    assert "<script" not in html_doc
    assert "<img" not in html_doc
