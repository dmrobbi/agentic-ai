"""KA-083 tests - timeline builder: the build_timeline four-key result
shape, normalized event shape, ISO-8601/unix stamp parsing (Z suffix,
offsets, naive-as-UTC, fractional seconds, milliseconds, numeric and
raw-datetimes accepted), malformed-ts tolerance into the unparsed tail
(never raising, exact warning strings), stable sort ties + unparsed
tail behavior, the fixed keyword->phase table (first match wins in the
fixed PHASES order, unknown -> other), first-appearance chronology
buckets (exact shape, row-index references, unparsed excluded),
per-target gap detection with the injectable strictly-greater
threshold and the documented row cap, caller-level contract refusals
(list-ness, max_events, threshold, the injected now), scrub_text
sanitize semantics, tolerant non-dict / non-string row routing, JSON
round-trips, constants pinning, and the planner-purity source scan.
No network, no file I/O, no live clock - the now argument is always
explicit when present."""

from __future__ import annotations

import importlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.timeline_builder import (
    DEFAULT_GAP_SECONDS,
    MAX_EVENTS,
    MAX_FIELD_CHARS,
    MAX_MESSAGE_CHARS,
    PHASES,
    PHASE_KEYWORDS,
    PHASE_OTHER,
    REASON_CAPPED,
    REASON_FIELD_TYPE,
    REASON_FUTURE,
    REASON_NOT_DICT,
    REASON_TS_MISSING,
    REASON_TS_TYPE,
    REASON_TS_UNPARSED,
    build_timeline,
    scrub_text,
)

UTC = timezone.utc
T0 = "2026-10-07T09:00:00+00:00"
T0_EPOCH = datetime(2026, 10, 7, 9, 0, 0, tzinfo=UTC).timestamp()
T1 = "2026-10-07T12:00:00+00:00"
T1_EPOCH = datetime(2026, 10, 7, 12, 0, 0, tzinfo=UTC).timestamp()
NOW_AWARE = datetime(2026, 10, 7, 12, 0, 0, tzinfo=UTC)


def evt(ts, action="port scan", **over):
    """A canonical audit row with the given stamp/action."""
    row = {"ts": ts, "action": action}
    row.update(over)
    return row


# --- the result shape -----------------------------------------------------


def test_empty_result_exact_shape():
    assert build_timeline([]) == {
        "chronology": [], "events": [], "gaps": [], "warnings": []}


@pytest.mark.parametrize("bad", [None, 42, "rows", {"ts": T0}])
def test_events_must_be_list(bad):
    with pytest.raises(ValueError, match="events must be a list"):
        build_timeline(bad)


def test_normalized_event_exact_shape():
    result = build_timeline([evt(T0, "ran nmap port scan",
                                 actor="kali-agent",
                                 target="host-a.lab",
                                 source="audit.log")])
    assert set(result) == {"chronology", "events", "gaps", "warnings"}
    assert result["events"] == [{
        "index": 0,
        "ts_raw": T0,
        "ts_utc": T0,
        "ts_epoch": T0_EPOCH,
        "ts_status": "parsed",
        "actor": "kali-agent",
        "action": "ran nmap port scan",
        "target": "host-a.lab",
        "source": "audit.log",
        "phase": "recon",
    }]
    assert result["gaps"] == []
    assert result["warnings"] == []


# --- stamp parsing: ISO / unix / raw --------------------------------------


@pytest.mark.parametrize("raw", [
    "2026-10-07T09:00:00+00:00",
    "2026-10-07T09:00:00Z",
    "2026-10-07T09:00:00z",
    "2026-10-07T09:00:00",            # naive -> read as UTC
    "2026-10-07T11:00:00+02:00",      # offset normalized to UTC
    "2026-10-07T09:00:00.000",        # fractional seconds
    "  2026-10-07T09:00:00+00:00 ",   # surrounding whitespace
])
def test_iso_stamp_variants_parse_to_one_instant(raw):
    row = build_timeline([evt(raw)])["events"][0]
    assert row["ts_status"] == "parsed"
    assert row["ts_epoch"] == T0_EPOCH
    assert row["ts_utc"] == T0


def test_unix_stamp_strings_parse():
    result = build_timeline([evt("1696118400"), evt("1696118400.5"),
                             evt("1696118400000")])  # 13 digits: ms
    assert [row["ts_utc"] for row in result["events"]] == [
        "2023-10-01T00:00:00+00:00",
        "2023-10-01T00:00:00+00:00",
        "2023-10-01T00:00:00.500000+00:00",
    ]
    assert [row["index"] for row in result["events"]] == [0, 2, 1]


def test_numeric_and_datetime_ts_accepted():
    two_hours_east = datetime(2026, 10, 7, 14, 0, 0,
                              tzinfo=timezone(timedelta(hours=2)))
    rows = build_timeline([evt(1696118400), evt(1696118400.5),
                           evt(NOW_AWARE), evt(two_hours_east)])["events"]
    assert [row["index"] for row in rows] == [0, 1, 2, 3]
    assert rows[0]["ts_utc"] == "2023-10-01T00:00:00+00:00"
    assert rows[0]["ts_raw"] == "1696118400"
    assert rows[1]["ts_epoch"] == 1696118400.5
    assert rows[2]["ts_epoch"] == T1_EPOCH


def test_naive_datetime_ts_reads_as_utc():
    row = build_timeline([evt(datetime(2026, 10, 7, 9, 0, 0))])["events"][0]
    assert row["ts_utc"] == T0
    assert row["ts_epoch"] == T0_EPOCH


# --- malformed stamps: the unparsed bucket, never a raise ------------------


def test_missing_ts_routes_to_unparsed_tail():
    result = build_timeline([{"actor": "root"}])
    assert result["events"][0]["ts_raw"] is None
    assert result["events"][0]["ts_status"] == "unparsed"
    assert result["events"][0]["ts_utc"] is None
    assert result["events"][0]["ts_epoch"] is None
    assert result["warnings"] == [REASON_TS_MISSING % (0,)]


@pytest.mark.parametrize("bad_ts, warning", [
    ("garbage", REASON_TS_UNPARSED % (0, "garbage")),
    ("", REASON_TS_UNPARSED % (0, "")),
    ("   ", REASON_TS_UNPARSED % (0, "   ")),
    (10 ** 30, REASON_TS_UNPARSED % (0, str(10 ** 30))),
    (True, REASON_TS_TYPE % (0, True)),
    ({"x": 1}, REASON_TS_TYPE % (0, {"x": 1})),
    (["x"], REASON_TS_TYPE % (0, ["x"])),
    ("2026-13-40T99:00:00",
     REASON_TS_UNPARSED % (0, "2026-13-40T99:00:00")),
])
def test_malformed_ts_routes_to_unparsed_tail(bad_ts, warning):
    result = build_timeline([evt(bad_ts)])
    row = result["events"][0]
    assert row["ts_status"] == "unparsed"
    assert row["ts_utc"] is None
    assert row["ts_epoch"] is None
    # the phase is time-independent: classify first, place later
    assert row["phase"] == "recon"
    assert result["chronology"] == []
    assert result["gaps"] == []
    assert result["warnings"] == [warning]


# --- the stable sort --------------------------------------------------------


def test_stable_sort_ties_then_unparsed_tail():
    events = [
        evt("2026-10-07T10:00:00+00:00", "exploit attempt"),  # input 0
        evt("2026-10-07T09:00:00+00:00", "port scan"),        # input 1
        evt("2026-10-07T10:00:00+00:00", "port scan"),        # input 2
        evt("garbage-ish", "clear log"),                      # input 3
        {"ts": "2026-10-07T09:00:00+00:00"},                  # input 4
    ]
    result = build_timeline(events)
    assert [(row["index"], row["ts_status"])
            for row in result["events"]] == [
        (1, "parsed"), (4, "parsed"), (0, "parsed"), (2, "parsed"),
        (3, "unparsed")]
    assert [row["phase"] for row in result["events"]] == [
        "recon", "other", "initial-access", "recon", "defense-evasion"]
    assert result["warnings"] == [REASON_TS_UNPARSED % (3, "garbage-ish")]


# --- the fixed keyword -> phase table ----------------------------------------


def test_phase_first_match_in_fixed_order_wins():
    got = build_timeline([
        evt(T0, "cron job to enumerate the network"),          # recon wins
        evt(T0, "scan the network then install a cron job"),   # recon wins
        evt(T0, "spawn powershell after an rdp session"),      # exec wins
    ])["events"]
    assert [row["phase"] for row in got] == [
        "recon", "recon", "execution"]


def test_unknown_and_missing_action_route_to_other():
    got = build_timeline([evt(T0, "made coffee"), evt(T0, None)])["events"]
    assert [row["phase"] for row in got] == [PHASE_OTHER, PHASE_OTHER]


@pytest.mark.parametrize("action, phase", [
    ("nmap port scan of the flat network", "recon"),
    ("exploited smb login with stolen credentials", "initial-access"),
    ("spawned powershell process", "execution"),
    ("installed cron job", "persistence"),
    ("rdp session to dc02", "lateral-movement"),
    ("hashdump via mimikatz", "post-exploitation"),
    ("event log clearing attempt", "defense-evasion"),
    ("wiped the staging directory", "cleanup"),
])
def test_each_phase_routes_from_action_text(action, phase):
    row = build_timeline([evt(T0, action)])["events"][0]
    assert row["phase"] == phase


# --- the chronology -----------------------------------------------------------


def test_chronology_buckets_exact_shape_and_appearance_order():
    events = [
        evt(T0, "port scan", target="host-a"),
        evt("2026-10-07T09:30:00+00:00", "brute login", target="host-a"),
        evt("2026-10-07T10:00:00+00:00", "spawned shell",
            target="host-a"),
        evt("2026-10-07T11:00:00+00:00", "port scan", target="host-b"),
    ]
    result = build_timeline(events)
    assert result["chronology"] == [
        {"phase": "recon", "count": 2, "started_at": T0,
         "ended_at": "2026-10-07T11:00:00+00:00",
         "event_indexes": [0, 3]},
        {"phase": "initial-access", "count": 1,
         "started_at": "2026-10-07T09:30:00+00:00",
         "ended_at": "2026-10-07T09:30:00+00:00",
         "event_indexes": [1]},
        {"phase": "execution", "count": 1,
         "started_at": "2026-10-07T10:00:00+00:00",
         "ended_at": "2026-10-07T10:00:00+00:00",
         "event_indexes": [2]},
    ]
    assert result["gaps"] == []
    assert result["warnings"] == []


def test_chronology_ignores_unparsed_rows():
    result = build_timeline([evt(T0, "port scan"),
                             evt("garbage", "port scan")])
    assert len(result["chronology"]) == 1
    assert result["chronology"][0]["event_indexes"] == [0]
    assert result["chronology"][0]["count"] == 1


# --- gap detection --------------------------------------------------------------


def test_gap_record_exact_shape():
    events = [
        evt("2026-10-07T09:00:00+00:00", "login attempt",
            target="host-a"),
        evt("2026-10-07T10:30:00+00:00", "login attempt",
            target="host-b"),
        evt("2026-10-07T11:30:00+00:00", "login attempt",
            target="host-a"),
    ]
    result = build_timeline(events)
    assert result["gaps"] == [{
        "target": "host-a",
        "earlier_index": 0,
        "later_index": 2,
        "earlier_ts": "2026-10-07T09:00:00+00:00",
        "later_ts": "2026-10-07T11:30:00+00:00",
        "delta_seconds": 9000.0,
    }]


def test_gap_threshold_injectable_and_strictly_greater():
    events = [
        evt(T0, "login attempt", target="host-a"),
        evt("2026-10-07T10:30:00+00:00", "login attempt",
            target="host-a"),
    ]
    equal = build_timeline(events, gap_threshold_seconds=5400.0)
    assert equal["gaps"] == []  # delta == threshold is NOT above it
    above = build_timeline(events, gap_threshold_seconds=5399.0)
    assert [row["delta_seconds"] for row in above["gaps"]] == [5400.0]


def test_gap_threshold_zero_accepted():
    result = build_timeline(
        [evt(T0, target="h"), evt("2026-10-07T09:00:01+00:00",
                                  target="h")],
        gap_threshold_seconds=0)
    assert result["gaps"] == [{
        "target": "h", "earlier_index": 0, "later_index": 1,
        "earlier_ts": T0, "later_ts": "2026-10-07T09:00:01+00:00",
        "delta_seconds": 1.0}]


def test_gaps_require_a_nonblank_target():
    result = build_timeline([
        evt(T0, target=None),
        evt("2026-10-07T19:00:00+00:00", target=""),
        evt("2026-10-07T20:00:00+00:00", target="   "),
    ])
    assert result["gaps"] == []


# --- caps ------------------------------------------------------------------------


def test_row_cap_processes_first_rows_and_warns_once():
    events = [evt("2026-10-07T09:0%d:00+00:00" % i, "port scan")
              for i in range(5)]
    result = build_timeline(events, max_events=3)
    assert [row["index"] for row in result["events"]] == [0, 1, 2]
    assert result["warnings"] == [REASON_CAPPED % (3, 5)]
    # a tuple of rows is accepted; under the cap there is no notice
    assert build_timeline(
        tuple(events), max_events=MAX_EVENTS)["warnings"] == []


# --- caller-level contract ----------------------------------------------------------


@pytest.mark.parametrize("bad", [0, -3, "3", 3.5, None, True])
def test_max_events_must_be_positive_int(bad):
    with pytest.raises(ValueError, match="max_events must be a positive int"):
        build_timeline([], max_events=bad)


@pytest.mark.parametrize("bad", [-1, -0.5, "x", None, True, float("nan")])
def test_gap_threshold_must_be_nonnegative_number(bad):
    with pytest.raises(ValueError, match="non-negative number"):
        build_timeline([], gap_threshold_seconds=bad)


def test_injected_now_contract():
    with pytest.raises(ValueError, match="now must be an aware datetime"):
        build_timeline([], now=datetime(2026, 10, 7, 12, 0, 0))  # naive
    with pytest.raises(ValueError, match="now must be an aware datetime"):
        build_timeline([], now="now-ish")


def test_future_events_warn_only_with_injected_now():
    events = [evt("2026-10-07T11:00:00+00:00"),
              evt("2026-10-07T13:00:00+00:00")]
    flagged = build_timeline(events, now=NOW_AWARE)
    assert flagged["warnings"] == [REASON_FUTURE % (1,)]
    assert build_timeline(events)["warnings"] == []
    # an aware non-UTC now compares by instant
    skew = build_timeline(
        [evt("2026-10-07T12:30:00+00:00")],
        now=datetime(2026, 10, 7, 14, 0, 0,
                     tzinfo=timezone(timedelta(hours=2))))
    assert skew["warnings"] == [REASON_FUTURE % (0,)]


# --- scrubbing ------------------------------------------------------------------------


def test_scrub_text_sanitize_semantics():
    assert scrub_text("  audit log row ") == "audit log row"
    assert scrub_text("a\x00b\x7fc") == "abc"
    assert scrub_text("a\tb") == "ab"
    assert scrub_text("caf\xc3\xa9 no") == "caf\xc3\xa9 no"
    assert scrub_text("   ") is None
    assert scrub_text("") is None
    assert scrub_text(None) is None
    assert scrub_text(42) is None
    assert scrub_text("x" * 6000) == "x" * MAX_FIELD_CHARS


def test_event_text_fields_sanitize_without_refusal():
    raw = "h\x00\n st\x1f | a`b"
    result = build_timeline([evt(T0, raw * 100, target=raw)])
    row = result["events"][0]
    assert row["ts_raw"] == T0
    assert row["target"] == "h st | a`b"
    assert row["action"] == ("h st | a`b" * 100)[:MAX_FIELD_CHARS]
    assert row["actor"] is None
    assert row["source"] is None
    assert row["phase"] == "other"
    assert result["warnings"] == []  # sanitize is silent, refusal is not


def test_non_string_text_fields_warn_and_null_out():
    result = build_timeline([evt(T0, "port scan", actor=42,
                                 source=["x"], target="host-a")])
    row = result["events"][0]
    assert row["actor"] is None
    assert row["source"] is None
    assert row["target"] == "host-a"
    assert row["phase"] == "recon"
    assert result["warnings"] == [
        REASON_FIELD_TYPE % (0, "actor", 42),
        REASON_FIELD_TYPE % (0, "source", ["x"]),
    ]


# --- tolerant row routing ---------------------------------------------------------------


def test_non_dict_rows_warn_and_never_raise():
    result = build_timeline([evt(T0, "port scan"), 42, "junk"])
    assert len(result["events"]) == 1
    assert result["events"][0]["index"] == 0
    assert result["warnings"] == [
        REASON_NOT_DICT % (1, 42), REASON_NOT_DICT % (2, "junk")]


# --- json round-trip --------------------------------------------------------------------


def test_result_survives_json_roundtrip():
    events = [
        evt(T0, "port scan", target="host-a"),
        evt("garbage", "clear log", target="host-a"),
        evt("2026-10-07T20:00:00+00:00", "login attempt",
            target="host-a"),
    ]
    result = build_timeline(events, now=NOW_AWARE)
    assert result["gaps"][0]["delta_seconds"] == 39600.0
    assert json.loads(json.dumps(result)) == result


# --- planner purity ------------------------------------------------------------------------


def test_planner_purity_source_scan():
    module = importlib.import_module(
        "agentic_ai.agents.cyber.timeline_builder")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("from agentic_ai", "import agentic_ai", "utcnow",
                   "time.time", "today()", "datetime.now",
                   "subprocess", "popen", "os.system", "eval(", "exec(",
                   "urllib", "socket", "requests", "http.client",
                   "open(", "Path(", "write_text"):
        assert banned not in source, banned


def test_contract_constants_pinned():
    assert PHASES == ("recon", "initial-access", "execution",
                      "persistence", "lateral-movement",
                      "post-exploitation", "defense-evasion", "cleanup")
    assert PHASE_OTHER == "other"
    assert set(PHASE_KEYWORDS) == set(PHASES)
    # benign classifier vocabulary only: lowercase alphanumerics,
    # spaces, and dashes - never payload-ish strings
    for keywords in PHASE_KEYWORDS.values():
        for keyword in keywords:
            assert re.fullmatch(r"[a-z0-9 \-]+", keyword), keyword
    assert MAX_EVENTS == 5000
    assert MAX_FIELD_CHARS == 512
    assert MAX_MESSAGE_CHARS == 240
    assert DEFAULT_GAP_SECONDS == 3600.0