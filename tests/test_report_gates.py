"""KA-088 tests - report gates: the no-orphan-numbers gate in the
house consent_gate shape (exactly a (bool, reason) tuple, reason ""
when clean), the shared tokenizer's raw-token shapes (thousands comma
groups, dotted versions/decimals, percent tokens kept distinct, the
3-digit comma-group split rule, slash-separated digits), canon
normalization, the trace contract (canon membership among the source
texts' canon tokens; a percent token traced by EITHER form, a bare
token only by bare), the enumeration exemptions (line-leading
"."/"-)"-terminated numbers, decorated bullets/headings, dotted
numbering; only the leading token is exempt and the marker is
required), the allow_tokens escape hatch (set-typed, exact raw/canon
membership), caller validation (str report, str-or-iterable sources,
refusals naming the offender) and the planner-purity source scan.
No network, no file fixtures, no clocks - every input is an inline
string by design."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.report_gates import (
    MAX_ORPHANS,
    ORPHAN_REASON_PREFIX,
    gate_no_orphan_numbers,
    normalize_number_token,
    number_tokens,
)

GATE = gate_no_orphan_numbers


# --- the gate shape + clean paths -----------------------------------------


def test_gate_returns_house_tuple_and_clean_reason():
    ok, reason = GATE("probed 42 hosts, found 1337 listeners",
                      "42 hosts reported\n1337 listeners heard")
    assert ok is True
    assert reason == ""
    assert (ok, reason) == (True, "")


def test_report_without_numbers_is_clean_with_no_sources():
    assert GATE("nothing numeric here", "") == (True, "")
    assert GATE("", []) == (True, "")


def test_orphan_exact_reason_wording():
    assert GATE("found 999 listeners", "heard 7 hosts") == (
        False, "orphan number tokens: 999")


def test_orphans_semicolon_joined_deduped_first_order():
    # one wording covers the join, the dedup, and first-occurrence
    # order: two distinct orphans, the repeat collapses
    assert GATE("12 apples and 34 pears then 12 again", "") == (
        False, "orphan number tokens: 12; 34")


def test_reason_capped_at_25_with_remainder_note():
    nums = [str(1000 + i) for i in range(30)]
    report = "row " + ", ".join(nums)
    ok, reason = GATE(report, "")
    assert ok is False
    assert reason == (ORPHAN_REASON_PREFIX
                      + "; ".join(nums[:MAX_ORPHANS])
                      + "; +5 more")


def test_any_source_text_traces_its_numbers():
    ok, reason = GATE("42 then 77", ("42 found here", "77 found there"))
    assert (ok, reason) == (True, "")


# --- thousands separators ---------------------------------------------------


def test_thousands_separator_equivalent_both_directions():
    assert GATE("1,234 events", "1234 events total") == (True, "")
    assert GATE("1234 events", "1,234 events total") == (True, "")


def test_thousands_with_decimal_canon_survives_both_sides():
    assert GATE("took 1,234.56 ms", "avg 1234.56 ms") == (True, "")


# --- percent tokens: kept distinct, traced by EITHER form -------------------


def test_percent_token_traced_by_percent_source_form():
    assert GATE("blocked 42%", "42% blocked at the edge") == (True, "")


def test_percent_token_traced_by_bare_source_form():
    assert GATE("blocked 42%", "sent 42 and lost 8") == (True, "")


def test_bare_number_never_traced_by_percent_only_source():
    # the kept-distinct contract, the load-bearing direction: a
    # source that only said "42%" is not bare evidence
    assert GATE("blocked 42", "42% blocked at the edge") == (
        False, "orphan number tokens: 42")


# --- version-like and decimal tokens ----------------------------------------


def test_version_like_token_traced_whole():
    assert GATE("nginx 1.2.3 detected", "banner nginx/1.2.3") == (True, "")


def test_version_like_token_refuses_split_component_traces():
    # "1" and "2.3" individually present in the source do NOT trace
    # the whole "1.2.3" token
    assert GATE("nginx 1.2.3 observed", "server 1 ran 2.3 minutes") == (
        False, "orphan number tokens: 1.2.3")


def test_decimal_token_is_whole_not_split():
    assert GATE("cvss 9.8", "score 9.8") == (True, "")
    assert GATE("cvss 9.8", "score 9") == (
        False, "orphan number tokens: 9.8")


# --- enumeration exemptions ---------------------------------------------------


def test_line_leading_enumeration_exempt():
    assert GATE("3. Findings\n7) Conclusion", "") == (True, "")


def test_enumeration_exempts_only_the_leading_token():
    assert GATE("3. Found 42 stale rows here", "") == (
        False, "orphan number tokens: 42")


def test_decorated_enumeration_exempt():
    report = "### 3. Probe lanes\n- 4. Cookie flags\n> 5. Header notes"
    assert GATE(report, "") == (True, "")


def test_dotted_enumeration_exempt():
    assert GATE("1.2.3. Nested subsection", "") == (True, "")


def test_non_enumeration_numbers_still_trace():
    # mid-line numbers are never exempt ...
    assert GATE("in phase 3 of 9 lanes ran", "") == (
        False, "orphan number tokens: 3; 9")
    # ... and a marker-less line-leading number is not enumeration
    assert GATE("3 servers reported down", "") == (
        False, "orphan number tokens: 3")


# --- allow_tokens: the escape hatch ------------------------------------------


def test_allow_tokens_licenses_unsourced_ports():
    ok, reason = GATE("left ports 22/80/443 reachable", "",
                      allow_tokens={"22", "80", "443"})
    assert (ok, reason) == (True, "")


def test_allow_tokens_partial_license_leaves_rest_orphan():
    assert GATE("left ports 22/80/443 reachable", "",
                allow_tokens={"22"}) == (
        False, "orphan number tokens: 80; 443")


def test_allow_tokens_matches_canon_too():
    assert GATE("1,234 rows", "", allow_tokens={"1234"}) == (True, "")


@pytest.mark.parametrize("bad", [["22"], "22", 22])
def test_allow_tokens_must_be_a_set(bad):
    with pytest.raises(ValueError, match="allow_tokens must be a set"):
        GATE("42", "", allow_tokens=bad)


def test_allow_tokens_entries_must_be_strings():
    with pytest.raises(ValueError,
                       match="allow_tokens entries must be strings"):
        GATE("42", "", allow_tokens={42})


# --- caller validation ---------------------------------------------------------


@pytest.mark.parametrize("bad", [None, 42, b"42"])
def test_report_text_must_be_str(bad):
    with pytest.raises(ValueError, match="report_text must be a string"):
        GATE(bad, "42 found")


def test_sources_str_and_tuple_forms_accepted():
    assert GATE("42 events", "42 events recorded") == (True, "")
    assert GATE("42 events", ("42 events recorded",)) == (True, "")


@pytest.mark.parametrize("bad", [None, {"k": "42 events"}])
def test_sources_none_and_dict_refused(bad):
    with pytest.raises(ValueError,
                       match="sources must be a string or a list"):
        GATE("42 events", bad)


@pytest.mark.parametrize("mixed", [["42 events", 42], ["42 events", None]])
def test_sources_elements_must_be_strings(mixed):
    with pytest.raises(ValueError,
                       match=r"sources\[1\] must be a string"):
        GATE("42 events", mixed)


def test_empty_sources_orphan_every_report_number():
    assert GATE("42 events", []) == (
        False, "orphan number tokens: 42")


# --- the tokenizer + canon helpers (public surface) -----------------------------


def test_number_tokens_scan_order():
    assert number_tokens("probes 1,234, port 80 and 4.2.1") == [
        "1,234", "80", "4.2.1"]


def test_number_tokens_ill_formed_comma_run_splits():
    assert number_tokens("1,23") == ["1", "23"]


def test_normalize_number_token_rules():
    assert normalize_number_token("1,234") == "1234"
    assert normalize_number_token("1,234.56") == "1234.56"
    assert normalize_number_token("42%") == "42%"
    assert normalize_number_token("1.2.3") == "1.2.3"
    assert normalize_number_token("1234") == "1234"


# --- constants as drift alarms ----------------------------------------------------


def test_reason_constants_are_drift_alarms():
    assert MAX_ORPHANS == 25
    assert ORPHAN_REASON_PREFIX == "orphan number tokens: "


# --- planner purity -----------------------------------------------------------------


def test_planner_purity_source_scan():
    module = importlib.import_module(
        "agentic_ai.agents.cyber.report_gates")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("from agentic_ai", "import agentic_ai",
                   "utcnow", "time.time", "today()",
                   "subprocess", "popen", "os.system",
                   "eval(", "exec(",
                   "urllib", "socket", "requests", "http.client",
                   "open(", "Path(", "write_text"):
        assert banned not in source, banned