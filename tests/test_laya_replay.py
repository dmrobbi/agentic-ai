"""KA-021 tests - laya-loop replay: modeled audit rows (the real
laya_gated_decision shape per the SOC's facts) replayed through the
matcher + planner; the measured precision (4 rows / 3 cve-cargo / 2
matched), exact per-row outputs, the matcher-injection isolation, the
report render, and the purity scan (exec facilities banned; the lazy
engine default allowed). No network; no live SOC calls."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.laya_replay import (
    precision,
    replay_flagged,
    render_report,
)

# modeled audit rows: the real laya_gated_decision shape (ts/kind/
# alert_id/severity/model/outcome/duration_ms/detail); hosts RFC 5737;
# the "credentials"/details = synthetic; no live SOC data
AUDIT_ROWS = [
    {"ts": "2026-10-04T18:20:31Z", "kind": "laya_gated_decision",
     "alert_id": "ALT-2026-001", "severity": 12, "model": "laya-typed-decisions",
     "outcome": "ok", "duration_ms": 997,
     "detail": "rule 31151 web-400 flood flagged; CVE-2021-44228 suspect"},
    {"ts": "2026-10-04T18:21:02Z", "kind": "laya_gated_decision",
     "alert_id": "ALT-2026-002", "severity": 4, "model": "laya-typed-decisions",
     "outcome": "ok", "duration_ms": 1001,
     "detail": "rule 31314 ssh brute; no cve cargo"},
    {"ts": "2026-10-04T18:22:07Z", "kind": "laya_gated_decision",
     "alert_id": "ALT-2026-003", "severity": 7, "model": "laya-typed-decisions",
     "outcome": "ok", "duration_ms": 1035,
     "detail": "smb anomaly; CVE-2017-0144 flagged by the scanner"},
    {"ts": "2026-10-04T18:23:44Z", "kind": "laya_gated_decision",
     "alert_id": "ALT-2026-004", "severity": 3, "model": "laya-typed-decisions",
     "outcome": "ok", "duration_ms": 1009,
     "detail": "kernel noise; CVE-2026-9999-shaped unknown cargo"},
]


def test_replay_shape_per_row():
    result = replay_flagged(AUDIT_ROWS)
    rows = result["rows"]
    assert [r["alert_id"] for r in rows] == [
        "ALT-2026-001", "ALT-2026-002", "ALT-2026-003", "ALT-2026-004"]
    assert rows[0]["cves"] == ["CVE-2021-44228"]
    assert rows[1]["cves"] == []
    assert rows[2]["cves"] == ["CVE-2017-0144"]
    assert rows[3]["cves"] == ["CVE-2026-9999"]


def test_precision_measured():
    numbers = precision(replay_flagged(AUDIT_ROWS))
    assert numbers == {
        "rows": 4, "rows_with_cve_cargo": 3, "rows_matched": 2,
        "match_rate": 2 / 3,
        "overall_flag_rate": 0.5,
    }


def test_matched_rows_carry_planner_steps():
    result = replay_flagged(AUDIT_ROWS)
    row1 = next(r for r in result["rows"] if r["alert_id"] == "ALT-2026-001")
    assert row1["matches"] == [{
        "cve": "CVE-2021-44228", "exploit_name": "Log4Shell",
        "metasploit_module": "exploit/multi/http/log4shell_header_injection",
        "port": None, "rank": 5}]
    assert any(s.startswith("searchsploit Log4Shell")
               for s in row1["suggested_next_steps"])
    assert any("verify CVE-2021-44228" in s
               for s in row1["suggested_next_steps"])


def test_unknown_cargo_rows_carry_nulls():
    result = replay_flagged(AUDIT_ROWS)
    row = next(r for r in result["rows"] if r["alert_id"] == "ALT-2026-004")
    assert row["matches"] == []  # unknown to the DB
    assert any("KA-029" in s for s in row["suggested_next_steps"])


def test_no_cargo_rows_unmatched():
    result = replay_flagged(AUDIT_ROWS)
    row = next(r for r in result["rows"] if r["alert_id"] == "ALT-2026-002")
    assert row["cves"] == [] and row["matches"] == []
    assert row["suggested_next_steps"] == []


def test_matcher_injection_is_the_only_call():
    class RecordingMatcher:
        def __init__(self):
            self.cves = []

        def match_cve(self, cve):
            self.cves.append(cve)
            return None

    matcher = RecordingMatcher()
    result = replay_flagged(AUDIT_ROWS, matcher=matcher)
    # only the cve-cargo rows' cves reach the matcher, once each:
    assert sorted(matcher.cves) == ["CVE-2017-0144", "CVE-2021-44228",
                                    "CVE-2026-9999"]
    assert all(r["matches"] == [] for r in result["rows"])


def test_report_template_renders():
    result = replay_flagged(AUDIT_ROWS)
    report = render_report(result)
    assert report.startswith("# laya-loop replay precision report")
    assert "rows replayed: 4" in report
    assert "rows with a DB-known match: 2" in report
    assert report.count("| ALT-2026-") == 2  # only the matched rows
    assert "| ALT-2026-001 | CVE-2021-44228 | Log4Shell |" in report
    assert "| ALT-2026-003 | CVE-2017-0144 | EternalBlue |" in report
    assert "KA-029 expansion queue" in report


def test_module_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.laya_replay")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned
