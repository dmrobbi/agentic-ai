"""KA-069 tests - tickets bridge: the soc-tickets open/close/state
payload shapes (exact dict equality), the engagement contract
(id/target/findings guards), per-finding skip routing (NO crash),
severity normalization, resolved-finding suppression, the UTC +00:00
stamp contract (aware normalized, naive refused), ticket-id handling
(auto shape + validated overrides), close consistency (id/kind/target
from the open line) and close refusals, the per-id latest-line-wins
state fold, JSON round-trips, unknown-finding-key absorption, and the
planner-purity source scan. The soc-tickets contract is MOCKED dict
shapes from the OPT-69 design: no network, no live SOC calls, no file
I/O - by design."""

from __future__ import annotations

import importlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.tickets_bridge import (
    DETAIL_SOURCE,
    ID_RE,
    KIND_REMEDIATION,
    MISSING_ID,
    REASON_ID_MALFORMED,
    REASON_ID_MISSING,
    REASON_NOT_DICT,
    REASON_SEVERITY,
    REASON_TEXT,
    STATUS_DONE,
    STATUS_RUNNING,
    TICKET_ID_RE,
    close_ticket_payload,
    new_ticket_id,
    open_ticket,
    scrub_target,
    ticket_states,
    tickets_for_engagement,
)

UTC = timezone.utc
NOW = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)  # arbitrary fixed clock
LATER = datetime(2026, 10, 6, 13, 0, 0, tzinfo=UTC)  # one hour after NOW

TICKET = "a1b2c3d4e5f6"          # 12 lowercase hex
TICKET2 = "ffff0000aaaa"

ENGAGEMENT_ID = "ENG-42"
TARGET = "wks-a01.lab.example"

FINDING = {"id": "F-01", "summary": "SMBv1 enabled on the host",
           "severity": "high"}

OPEN_KEYS = {"id", "ts", "kind", "target", "status", "ended", "details"}
DETAIL_KEYS = {"source", "engagement_id", "finding_id", "severity",
               "summary", "evidence"}
CLOSE_DETAIL_KEYS = {"source", "engagement_id", "finding_id", "outcome",
                     "evidence"}


def engagement(findings):
    """An engagement record with the given findings and provenance."""
    return {"engagement_id": ENGAGEMENT_ID, "target": TARGET,
            "findings": findings}


def ts_of(moment):
    return moment.astimezone(UTC).isoformat()


def open_line(ticket_id=TICKET, **overrides):
    """A canonical open payload (module output, deterministic ids)."""
    row = open_ticket(ENGAGEMENT_ID, FINDING, TARGET, NOW,
                      ticket_id=ticket_id)
    row.update(overrides)
    return row


# --- the open bundle: shapes ---------------------------------------------


def test_open_payload_exact_shape():
    bundle = tickets_for_engagement(engagement([FINDING]), NOW,
                                    ticket_ids={"F-01": TICKET})
    assert bundle["tickets"] == [{
        "id": TICKET,
        "ts": "2026-10-06T12:00:00+00:00",
        "kind": "kali_remediate",
        "target": TARGET,
        "status": "running",
        "ended": None,
        "details": {
            "source": "kali-agent-engagement",
            "engagement_id": ENGAGEMENT_ID,
            "finding_id": "F-01",
            "severity": "high",
            "summary": "SMBv1 enabled on the host",
            "evidence": None,
        },
    }]
    assert bundle["skipped"] == []
    assert bundle["summary"] == {
        "total": 1, "tickets": 1, "skipped": 0, "already_resolved": 0}


def test_bundle_shape_key_sets():
    findings = [
        FINDING,
        {"id": "AF-77", "summary": "stale service account",
         "severity": "Medium",
         "evidence": "gus2:~/eng/ENG-42/findings/AF-77.txt"},
        {"id": "F-02", "severity": "critical", "resolved": True},
    ]
    bundle = tickets_for_engagement(
        engagement(findings), NOW,
        ticket_ids={"F-01": TICKET, "AF-77": TICKET2})
    assert set(bundle) == {"tickets", "skipped", "summary"}
    assert bundle["summary"] == {
        "total": 3, "tickets": 2, "skipped": 0, "already_resolved": 1}
    t1, t2 = bundle["tickets"]
    assert t1["id"] == TICKET and t2["id"] == TICKET2
    for row in (t1, t2):
        assert set(row) == OPEN_KEYS
        assert set(row["details"]) == DETAIL_KEYS
        assert row["ts"] == "2026-10-06T12:00:00+00:00"
        assert row["kind"] == KIND_REMEDIATION
        assert row["target"] == TARGET
        assert row["status"] == "running"
        assert row["ended"] is None
        assert row["details"]["source"] == DETAIL_SOURCE
        assert row["details"]["engagement_id"] == ENGAGEMENT_ID
    assert t2["details"]["finding_id"] == "AF-77"
    assert t2["details"]["severity"] == "medium"  # normalized lowercase
    assert t2["details"]["evidence"] == (
        "gus2:~/eng/ENG-42/findings/AF-77.txt")


def test_af_style_finding_ids_pass_id_pattern():
    bundle = tickets_for_engagement(
        engagement([{"id": "AF-1.2", "severity": "low", "summary": "x"}]),
        NOW, ticket_ids={"AF-1.2": TICKET})
    assert bundle["summary"]["tickets"] == 1
    assert bundle["tickets"][0]["details"]["finding_id"] == "AF-1.2"


def test_finding_id_surrounding_whitespace_tolerated_in_bundle():
    # the bundle route carries the STRIPPED id (soc_bridge
    # precedent); the direct open op stays exact
    opened = open_ticket(ENGAGEMENT_ID, FINDING, TARGET, NOW,
                         ticket_id=TICKET)
    row = {"id": "  F-01  ", "summary": FINDING["summary"],
           "severity": "high"}
    bundle = tickets_for_engagement(engagement([row]), NOW,
                                    ticket_ids={"F-01": TICKET})
    assert bundle["tickets"] == [opened]
    strict = tickets_for_engagement(engagement([row]), NOW)
    assert strict["summary"]["tickets"] == 1


def test_empty_findings_zero_bundle():
    bundle = tickets_for_engagement(engagement([]), NOW)
    assert bundle == {
        "tickets": [], "skipped": [],
        "summary": {"total": 0, "tickets": 0, "skipped": 0,
                    "already_resolved": 0}}


# --- resolved findings ----------------------------------------------------


@pytest.mark.parametrize("resolved", [True, "yes", 1, ["yes"]])
def test_resolved_truthy_finding_gets_no_ticket(resolved):
    row = dict(FINDING, resolved=resolved)
    bundle = tickets_for_engagement(engagement([row]), NOW,
                                    ticket_ids={"F-01": TICKET})
    assert bundle["tickets"] == []
    assert bundle["summary"]["already_resolved"] == 1


def test_resolved_ignored_when_malformed_finding():
    # malformation outranks the resolved shortcut: a garbage row lands
    # in skipped and is NOT counted as resolved
    bundle = tickets_for_engagement(
        engagement([{"id": "F-01", "severity": "banana",
                     "resolved": True}]), NOW)
    assert bundle["tickets"] == []
    assert bundle["skipped"] == [{
        "finding_id": "F-01",
        "reasons": [REASON_SEVERITY % ("banana",)]}]
    assert bundle["summary"]["already_resolved"] == 0


# --- skip routing: malformed findings never crash the flow ----------------


def test_skip_route_exact_reasons():
    rows = [
        {},                                   # id missing
        {"id": "bad id!", "severity": "low"},  # id malformed
        {"id": "F-903"},                      # severity missing
        {"id": "F-904", "severity": "high", "summary": 42},
        {"id": "F-905", "severity": "high", "evidence": ["x"]},
        "not-a-dict",                          # row not a dict
    ]
    bundle = tickets_for_engagement(engagement(rows), NOW)
    got = [(row["finding_id"], list(row["reasons"]))
           for row in bundle["skipped"]]
    assert got == [
        # the empty row collects EVERY applicable reason
        (MISSING_ID, [REASON_ID_MISSING, REASON_SEVERITY % (None,)]),
        ("bad id!", [REASON_ID_MALFORMED % ("bad id!",)]),
        ("F-903", [REASON_SEVERITY % (None,)]),
        ("F-904", [REASON_TEXT % ("summary", 42)]),
        ("F-905", [REASON_TEXT % ("evidence", ["x"])]),
        (MISSING_ID, [REASON_NOT_DICT]),
    ]
    assert bundle["tickets"] == []
    assert bundle["summary"] == {
        "total": 6, "tickets": 0, "skipped": 6, "already_resolved": 0}


@pytest.mark.parametrize("bad_id", ["", "   ", None, 42, "id with space",
                                    "bad/id", "x" * 65])
def test_malformed_finding_id_routes_to_skipped(bad_id):
    row = {"id": bad_id, "severity": "high"}
    bundle = tickets_for_engagement(engagement([row]), NOW)
    assert bundle["tickets"] == []
    # the stripped id stays the row label whenever a non-blank id
    # exists; only an unavailable id collapses to <missing-id>
    label = (bad_id.strip()
             if isinstance(bad_id, str) and bad_id.strip()
             else MISSING_ID)
    expected_reason = (
        REASON_ID_MALFORMED % (bad_id,)
        if label != MISSING_ID
        else REASON_ID_MISSING)
    assert bundle["skipped"] == [{"finding_id": label,
                                  "reasons": [expected_reason]}]


@pytest.mark.parametrize("bad_severity", [None, "", "  ",
                                          "banana", 42])
def test_malformed_severity_routes_to_skipped(bad_severity):
    bundle = tickets_for_engagement(
        engagement([{"id": "F-01", "severity": bad_severity}]), NOW)
    assert bundle["tickets"] == []
    assert bundle["skipped"] == [{
        "finding_id": "F-01",
        "reasons": [REASON_SEVERITY % (bad_severity,)]}]


def test_valid_severity_is_case_and_space_tolerant():
    bundle = tickets_for_engagement(
        engagement([{"id": "F-01", "severity": "  HIGH  "}]), NOW,
        ticket_ids={"F-01": TICKET})
    assert bundle["tickets"][0]["details"]["severity"] == "high"


@pytest.mark.parametrize("non_str", [42, ["x"], {"k": 1}])
@pytest.mark.parametrize("slot", ["summary", "evidence"])
def test_non_string_free_text_routes_to_skipped(slot, non_str):
    row = {"id": "F-01", "severity": "high", slot: non_str}
    bundle = tickets_for_engagement(engagement([row]), NOW)
    assert bundle["skipped"] == [{
        "finding_id": "F-01", "reasons": [REASON_TEXT % (slot, non_str)]}]


def test_blank_free_text_normalizes_to_none_in_details():
    bundle = tickets_for_engagement(
        engagement([{"id": "F-01", "severity": "low", "summary": "   ",
                     "evidence": ""}]), NOW, ticket_ids={"F-01": TICKET})
    row = bundle["tickets"][0]
    assert row["details"]["summary"] is None
    assert row["details"]["evidence"] is None


# --- the engagement contract: caller errors raise -------------------------


@pytest.mark.parametrize("bad_engagement", [None, 42, "ENG-42", []])
def test_engagement_must_be_dict(bad_engagement):
    with pytest.raises(ValueError, match="engagement must be a dict"):
        tickets_for_engagement(bad_engagement, NOW)


def test_engagement_missing_keys():
    for partial in ({}, {"engagement_id": ENGAGEMENT_ID},
                    {"engagement_id": ENGAGEMENT_ID, "target": TARGET},
                    {"target": TARGET, "findings": []}):
        with pytest.raises(ValueError, match="missing required keys"):
            tickets_for_engagement(partial, NOW)


@pytest.mark.parametrize("bad_id", [None, "", "   ", "a b", "bad/id",
                                    "x" * 65, 42])
def test_malformed_engagement_id_refused(bad_id):
    with pytest.raises(ValueError, match="engagement_id malformed"):
        tickets_for_engagement(
            {"engagement_id": bad_id, "target": TARGET, "findings": []},
            NOW)


def test_engagement_id_is_exact_not_trimmed():
    with pytest.raises(ValueError, match="engagement_id malformed"):
        tickets_for_engagement(
            {"engagement_id": "  ENG-42  ", "target": TARGET,
             "findings": []}, NOW)


@pytest.mark.parametrize("bad_target", ["", "   ", None, 42, "two spaces",
                                        "h; rm -rf", "a|b", "a&b", "a`b",
                                        "a$b", "a(b", "a)b", "a\nb",
                                        "a\rb", "a<b", "a>b", 'a"b', "a'b",
                                        "a..b"])
def test_hostile_target_refused_by_scrub(bad_target):
    with pytest.raises(ValueError):
        tickets_for_engagement(
            {"engagement_id": ENGAGEMENT_ID, "target": bad_target,
             "findings": []}, NOW)


@pytest.mark.parametrize("bad_findings", [None, 42, "rows", {"a": 1}])
def test_findings_must_be_list(bad_findings):
    with pytest.raises(ValueError, match="findings must be a list"):
        tickets_for_engagement(
            {"engagement_id": ENGAGEMENT_ID, "target": TARGET,
             "findings": bad_findings}, NOW)


def test_tuple_findings_rows_accepted():
    bundle = tickets_for_engagement(
        {"engagement_id": ENGAGEMENT_ID, "target": TARGET,
         "findings": tuple([FINDING])}, NOW, ticket_ids={"F-01": TICKET})
    assert bundle["summary"]["tickets"] == 1


def test_scrub_target_module_level():
    assert scrub_target("  host-a01.lab.example ") == "host-a01.lab.example"
    with pytest.raises(ValueError):
        scrub_target("h; rm -rf")
    with pytest.raises(ValueError):
        scrub_target("")
    with pytest.raises(ValueError):
        scrub_target("two spaces")


# --- the open-line clock contract ----------------------------------------


def test_naive_now_refused():
    with pytest.raises(ValueError, match="timezone-aware"):
        open_ticket(ENGAGEMENT_ID, FINDING, TARGET,
                    datetime(2026, 10, 6, 12, 0, 0), ticket_id=TICKET)


def test_aware_non_utc_now_is_normalized_to_utc():
    now2h = datetime(2026, 10, 6, 14, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    row = open_ticket(ENGAGEMENT_ID, FINDING, TARGET, now2h,
                      ticket_id=TICKET)
    assert row["ts"] == "2026-10-06T12:00:00+00:00"


def test_non_datetime_now_refused():
    with pytest.raises(ValueError, match="now must be an aware datetime"):
        open_ticket(ENGAGEMENT_ID, FINDING, TARGET, "now-ish",
                    ticket_id=TICKET)


# --- ticket-id handling ----------------------------------------------------


def test_auto_ticket_id_shape_and_uniqueness():
    rows = [{"id": "F-%d" % i, "severity": "high"} for i in range(5)]
    bundle = tickets_for_engagement(engagement(rows), NOW)
    ids = [row["id"] for row in bundle["tickets"]]
    assert all(re.fullmatch(TICKET_ID_RE, value) for value in ids)
    assert len(set(ids)) == 5


def test_new_ticket_id_matches_store_pattern():
    assert re.fullmatch(TICKET_ID_RE, new_ticket_id())


@pytest.mark.parametrize("bad_ticket_id", ["", "a1b2c3d4e5f",
                                           "a1b2c3d4e5f78", "G1B2C3D4E5F6",
                                           "a1b2c3d4e5g6", 42, []])
def test_malformed_ticket_id_override_refused(bad_ticket_id):
    with pytest.raises(ValueError, match="ticket id must be 12 lowercase"):
        open_ticket(ENGAGEMENT_ID, FINDING, TARGET, NOW,
                    ticket_id=bad_ticket_id)


def test_ticket_id_override_used_verbatim():
    row = open_ticket(ENGAGEMENT_ID, FINDING, TARGET, NOW,
                      ticket_id="0123456789ab")
    assert row["id"] == "0123456789ab"


def test_unknown_finding_keys_absorbed():
    noisy = dict(FINDING, cvss=9.8, cve_id="CVE-2024-99999", machina="note")
    row = open_ticket(ENGAGEMENT_ID, noisy, TARGET, NOW, ticket_id=TICKET)
    clean = open_ticket(ENGAGEMENT_ID, FINDING, TARGET, NOW,
                        ticket_id=TICKET)
    assert row == clean


def test_open_ticket_direct_contract():
    row = open_ticket(ENGAGEMENT_ID, FINDING, TARGET, NOW, ticket_id=TICKET)
    assert set(row) == OPEN_KEYS
    assert set(row["details"]) == DETAIL_KEYS


@pytest.mark.parametrize("bad_finding", [None, 42, "F-01", ["F-01"]])
def test_open_ticket_refuses_non_dict_finding(bad_finding):
    with pytest.raises(ValueError, match="finding must be a dict"):
        open_ticket(ENGAGEMENT_ID, bad_finding, TARGET, NOW,
                    ticket_id=TICKET)


def test_open_ticket_refuses_resolved_finding():
    with pytest.raises(ValueError, match="already resolved"):
        open_ticket(ENGAGEMENT_ID, dict(FINDING, resolved=True), TARGET,
                    NOW, ticket_id=TICKET)


def test_open_ticket_refuses_malformed_finding_id_and_severity():
    with pytest.raises(ValueError, match="finding id malformed"):
        open_ticket(ENGAGEMENT_ID, {"id": "bad id!", "severity": "high"},
                    TARGET, NOW, ticket_id=TICKET)
    with pytest.raises(ValueError, match="severity must be one of"):
        open_ticket(ENGAGEMENT_ID, {"id": "F-01", "severity": "nope"},
                    TARGET, NOW, ticket_id=TICKET)


@pytest.mark.parametrize("bad_kind", ["", "   ", "kind with space", 42])
def test_open_ticket_refuses_bad_kind(bad_kind):
    with pytest.raises(ValueError, match="kind malformed"):
        open_ticket(ENGAGEMENT_ID, FINDING, TARGET, NOW, kind=bad_kind,
                    ticket_id=TICKET)


def test_custom_kind_flows_through_open_and_close():
    row = open_ticket(ENGAGEMENT_ID, FINDING, TARGET, NOW,
                      kind="stig_remediate", ticket_id=TICKET)
    assert row["kind"] == "stig_remediate"
    done = close_ticket_payload(row, "fixed", LATER)
    assert done["kind"] == "stig_remediate"


# --- the close payload -----------------------------------------------------


def test_close_payload_exact_shape():
    done = close_ticket_payload(open_line(), "fixed: SMBv1 disabled",
                                LATER)
    assert done == {
        "id": TICKET,
        "ts": "2026-10-06T13:00:00+00:00",
        "kind": KIND_REMEDIATION,
        "target": TARGET,
        "status": "done",
        "ended": "2026-10-06T13:00:00+00:00",
        "details": {
            "source": DETAIL_SOURCE,
            "engagement_id": ENGAGEMENT_ID,
            "finding_id": "F-01",
            "outcome": "fixed: SMBv1 disabled",
            "evidence": None,
        },
    }
    assert done["ts"] == done["ended"]


def test_close_carries_evidence_path():
    done = close_ticket_payload(
        open_line(), "partially fixed", LATER,
        evidence_path="gus2:~/verify-aai/stig-eval-results/wks/after.txt")
    assert done["details"]["evidence"] == (
        "gus2:~/verify-aai/stig-eval-results/wks/after.txt")


def test_close_id_kind_target_come_from_the_open_line():
    for other_target, other_kind in (
            ("host-b01.lab.example", "stig_remediate"),
            ("dc01.corp.example", KIND_REMEDIATION)):
        opened = open_line(ticket_id=TICKET2, target=other_target,
                           kind=other_kind)
        done = close_ticket_payload(opened, "fixed", LATER)
        assert done["id"] == TICKET2
        assert done["kind"] == other_kind
        assert done["target"] == other_target
        assert done["status"] == "done"


def test_close_details_echo_non_blank_provenance_only():
    opened = open_line()
    opened["details"] = {"engagement_id": "", "finding_id": 42,
                         "unrelated": "ignored"}
    done = close_ticket_payload(opened, "fixed", LATER)
    assert done["details"]["engagement_id"] is None
    assert done["details"]["finding_id"] is None
    assert "unrelated" not in done["details"]


def test_close_details_absent_is_tolerated():
    opened = open_line()
    del opened["details"]
    done = close_ticket_payload(opened, "fixed", LATER)
    assert done["details"]["engagement_id"] is None
    assert done["details"]["finding_id"] is None


# --- close refusals ---------------------------------------------------------


def test_close_refuses_non_dict_line():
    with pytest.raises(ValueError, match="needs a dict open line"):
        close_ticket_payload("nope", "fixed", LATER)


@pytest.mark.parametrize("bad_id", [None, "a1b2c3d4e5f", "G1B2C3D4E5F6",
                                    "a1b2 c3d4e5f6", 42])
def test_close_refuses_malformed_id(bad_id):
    opened = open_line()
    opened["id"] = bad_id
    with pytest.raises(ValueError, match="ticket id malformed"):
        close_ticket_payload(opened, "fixed", LATER)


def test_close_refuses_already_done_line():
    done_once = close_ticket_payload(open_line(), "fixed", LATER)
    with pytest.raises(ValueError, match="not an open running line"):
        close_ticket_payload(done_once, "fixed again", LATER)


def test_close_refuses_running_line_with_ended_stamp():
    opened = open_line(ended=LATER.isoformat())  # schema-violating line
    with pytest.raises(ValueError, match="not an open running line"):
        close_ticket_payload(opened, "fixed", LATER)


@pytest.mark.parametrize("bad_outcome", ["", "   ", None, 42])
def test_close_refuses_blank_or_non_string_outcome(bad_outcome):
    with pytest.raises(ValueError, match="outcome must be a non-blank"):
        close_ticket_payload(open_line(), bad_outcome, LATER)


def test_close_refuses_non_string_evidence_path():
    with pytest.raises(ValueError, match="evidence_path must be a string"):
        close_ticket_payload(open_line(), "fixed", LATER,
                             evidence_path=["nope"])


@pytest.mark.parametrize("bad_ended", ["now", datetime(2026, 10, 6, 13, 0)])
def test_close_refuses_bad_ended(bad_ended):
    with pytest.raises(ValueError, match="ended must be an aware datetime|timezone-aware"):
        close_ticket_payload(open_line(), "fixed", bad_ended)


@pytest.mark.parametrize("missing_target", [None])
def test_close_refuses_missing_target(missing_target):
    opened = open_line()
    del opened["target"]
    with pytest.raises(ValueError, match="open line missing target"):
        close_ticket_payload(opened, "fixed", LATER)


def test_close_refuses_hostile_target_in_open_line():
    opened = open_line(target="h; rm -rf")
    with pytest.raises(ValueError, match="disallowed characters"):
        close_ticket_payload(opened, "fixed", LATER)


def test_close_ended_non_utc_is_normalized():
    ended2h = datetime(2026, 10, 6, 15, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    done = close_ticket_payload(open_line(), "fixed", ended2h)
    assert done["ts"] == done["ended"] == "2026-10-06T13:00:00+00:00"


# --- the state fold: latest line per id wins --------------------------------


def test_states_basic_shape():
    opened = open_line()
    closed = close_ticket_payload(opened, "fixed", LATER)
    held = {"id": TICKET2, "ts": ts_of(NOW), "kind": KIND_REMEDIATION,
            "target": TARGET, "status": "held", "ended": None,
            "details": {}}
    result = ticket_states([opened, closed, held])
    assert set(result) == {"states", "open_ids", "closed_ids",
                           "bad_lines", "counts"}
    assert result["states"] == {TICKET: "closed", TICKET2: "unknown"}
    assert result["open_ids"] == []  # the done line is TICKET's latest
    assert result["closed_ids"] == [TICKET]
    assert result["bad_lines"] == []
    assert result["counts"] == {"lines": 3, "open": 0, "closed": 1,
                                "unknown": 1, "bad": 0}


def test_latest_line_wins_run_then_done():
    opened = open_line()
    closed = close_ticket_payload(opened, "fixed", LATER)
    result = ticket_states([opened, closed])
    assert result["states"] == {TICKET: "closed"}
    assert result["open_ids"] == []
    assert result["closed_ids"] == [TICKET]


def test_latest_line_wins_reopen():
    opened = open_line()
    closed = close_ticket_payload(opened, "fixed", LATER)
    reopened = dict(opened)  # a later running line (store-side anomaly; the
                             # fold reports reality: latest wins)
    result = ticket_states([closed, reopened])
    assert result["states"] == {TICKET: "open"}
    assert result["open_ids"] == [TICKET]
    assert result["closed_ids"] == []


def test_states_bad_lines():
    opened = open_line()
    result = ticket_states([opened, "not-a-line", {"id": "nope", "ts": 1},
                            {"status": "running"}])
    assert result["bad_lines"] == [
        {"index": 1, "id": None, "reason": "line must be a dict"},
        {"index": 2, "id": "nope", "reason":
         "line id malformed: %r" % "nope"},
        {"index": 3, "id": None, "reason": "line id malformed: None"}]
    assert result["states"] == {TICKET: "open"}
    assert result["counts"]["lines"] == 4
    assert result["counts"]["bad"] == 3


def test_states_open_ids_and_closed_ids_sorted():
    ids = ["c1b2c3d4e5f6", "a1b2c3d4e5f6", "b1b2c3d4e5f6"]
    lines = [open_line(ticket_id=tid) for tid in ids]
    lines += [close_ticket_payload(open_line(ticket_id="e1b2c3d4e5f6"),
                                   "fixed", LATER)]
    result = ticket_states(lines)
    assert result["open_ids"] == sorted(ids)
    assert result["closed_ids"] == ["e1b2c3d4e5f6"]


def test_states_empty_and_none():
    empty = {"states": {}, "open_ids": [], "closed_ids": [], "bad_lines": [],
             "counts": {"lines": 0, "open": 0, "closed": 0, "unknown": 0,
                        "bad": 0}}
    assert ticket_states([]) == empty
    assert ticket_states(None) == empty


def test_states_running_line_with_ended_is_unknown():
    opened = open_line(ended=LATER.isoformat())
    result = ticket_states([opened])
    assert result["states"] == {TICKET: "unknown"}


def test_states_counts_lines_including_duplicates():
    opened = open_line()
    reopened = dict(opened)
    result = ticket_states([opened, reopened])
    assert result["counts"]["lines"] == 2
    assert result["counts"]["open"] == 1  # one DISTINCT id


# --- json-safety round-trips -------------------------------------------------


def test_payloads_survive_json_roundtrip():
    opened = open_line()
    closed = close_ticket_payload(opened, "fixed", LATER,
                                  evidence_path="gus2:~/after.txt")
    fold = ticket_states([opened, closed])
    clone = json.loads(json.dumps(
        {"opened": opened, "closed": closed, "fold": fold}))
    assert clone["opened"] == opened
    assert clone["closed"] == closed
    assert clone["fold"]["states"] == fold["states"]


# --- lifecycle smoke: open -> close -> states through module outputs only -----
def test_open_close_roundtrip_through_module_outputs():
    bundle = tickets_for_engagement(engagement([FINDING]), NOW,
                                    ticket_ids={"F-01": TICKET})
    opened = bundle["tickets"][0]
    done = close_ticket_payload(opened, "fixed and verified", LATER)
    fold = ticket_states([opened, done])
    assert fold["states"] == {TICKET: "closed"}


# --- planner purity -----------------------------------------------------------


def test_planner_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.tickets_bridge")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("from agentic_ai", "import agentic_ai",
                   "utcnow", "time.time", "today()",
                   "subprocess", "popen", "os.system",
                   "eval(", "exec(",
                   "urllib", "socket", "requests", "http.client",
                   "open(", "Path(", "write_text"):
        assert banned not in source, banned


def test_status_constants_match_store_words():
    assert STATUS_RUNNING == "running"
    assert STATUS_DONE == "done"
    assert KIND_REMEDIATION == "kali_remediate"
    assert MISSING_ID == "<missing-id>"
    assert re.fullmatch(ID_RE, KIND_REMEDIATION)
