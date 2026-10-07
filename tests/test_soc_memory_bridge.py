"""KA-075 tests - engagement -> SOC memory bridge: the push_summaries
output schema (exact), record payload semantics, tenant routing and the
in-call duplicate route, the store put-ack protocol (recording mock,
exploding store, non-dict acks, plan-only mode), the validate_target
gate consult, the scrub helpers over hostile inputs, the tenant read
plan (planner strings only), and the module purity source scan (no
exec/IO/wall-clock facilities; the live SOC tree is never referenced).
Fixtures embody every shape; no network, no live SOC calls - by design.

Fixture provenance: tests/fixtures/findings/soc_memory_engagements.json
is a synthetic corpus modeling engagement summaries filed into
tenant-scoped SOC memory records (KA-075 / OPT-75); its schema is
pinned here and nowhere else."""
from __future__ import annotations

import importlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.soc_memory_bridge import (
    EngagementMemoryBridge,
    MAX_FINDING_REFS,
    MAX_TAGS,
    RECORD_KIND,
    scrub_summary_text,
    scrub_tenant_id,
)

CORPUS_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "findings" / "soc_memory_engagements.json"
)
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
ENGAGEMENTS = CORPUS["engagements"]

BANNED_SOURCE_TOKENS = (
    "subprocess", "os.system", "os.environ", "getenv", "eval(", "exec(",
    "urllib", "requests", "socket", "open(", "Path(", "os.path",
    ".openclaw", "openclaw",
)
WALL_CLOCK_TOKENS = ("datetime.now", "utcnow", "time.time", "perf_counter")


def test_output_schema_exact_shape():
    result = EngagementMemoryBridge().push_summaries(ENGAGEMENTS)
    assert set(result) == {"records", "stored", "rejected", "summary"}
    assert set(result["summary"]) == {
        "total", "built", "stored", "rejected", "tenants", "store_present"}
    for record in result["records"]:
        assert set(record) == {
            "record_id", "tenant_id", "engagement_id", "kind",
            "created_at", "summary", "severity", "tags", "findings",
            "target"}
    for row in result["rejected"]:
        assert set(row) == {"engagement_id", "tenant_id", "reasons"}
        assert row["reasons"]


def test_fixture_rows_all_build_and_route():
    result = EngagementMemoryBridge().push_summaries(ENGAGEMENTS)
    assert result["summary"] == {
        "total": 12, "built": 8, "stored": 0, "rejected": 4,
        "tenants": 3, "store_present": False}
    rejected_ids = {row["engagement_id"] for row in result["rejected"]}
    assert rejected_ids == set(CORPUS["meta"]["invalid_ids"])
    assert result["stored"] == {}


def test_record_payload_semantics():
    clock = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)
    record, reasons = EngagementMemoryBridge().build_record(
        ENGAGEMENTS[0], seq=1, now=clock)
    assert reasons == []
    assert record["record_id"] == "soc-primary:E-01:0001"
    assert record["kind"] == RECORD_KIND == "engagement_summary"
    assert record["severity"] == "high"
    assert record["created_at"] == "2026-10-06T12:00:00+00:00"
    assert record["target"] == "range-a.lab.example"
    assert record["tags"] == ["battery", "web"]
    assert record["findings"] == ["F-01", "F-02"]


def test_severity_semantics_default_and_casefold():
    bridge = EngagementMemoryBridge()
    record, _ = bridge.build_record(ENGAGEMENTS[3])  # E-04: no severity
    assert record["severity"] == "info"
    assert record["created_at"] is None
    assert record["target"] is None
    record, reasons = bridge.build_record(ENGAGEMENTS[6])  # E-07: "Medium"
    assert reasons == []
    assert record["severity"] == "medium"


def test_findings_refs_dedupe_preserving_order():
    record, reasons = EngagementMemoryBridge().build_record(ENGAGEMENTS[5])
    assert reasons == []
    assert record["findings"] == ["F-03", "F-04"]


def test_record_ids_embed_input_position_with_gap_semantics():
    result = EngagementMemoryBridge().push_summaries(ENGAGEMENTS)
    assert [rec["record_id"] for rec in result["records"]] == [
        "soc-primary:E-01:0001", "soc-primary:E-02:0002",
        "soc-secondary:E-03:0003", "soc-secondary:E-04:0004",
        "soc-primary:E-05:0005", "lab-fleet:E-06:0006",
        "lab-fleet:E-07:0007", "soc-primary:E-08:0008"]


def test_duplicate_engagement_rejected_within_call():
    result = EngagementMemoryBridge().push_summaries(ENGAGEMENTS + ENGAGEMENTS)
    summary = result["summary"]
    assert summary["total"] == 24
    assert summary["built"] == 8
    # invalid rows re-reject on repeat batch: 4 invalid + 8 dups, x2 batches
    assert summary["rejected"] == 16
    dups = [row for row in result["rejected"]
            if row["reasons"] == ["duplicate engagement summary for tenant"]]
    assert len(dups) == 8


def test_repeat_call_rebuilds_statelessly():
    first = EngagementMemoryBridge().push_summaries(ENGAGEMENTS)
    second = EngagementMemoryBridge().push_summaries(ENGAGEMENTS)
    assert first["summary"]["built"] == second["summary"]["built"] == 8
    assert ([r["record_id"] for r in first["records"]]
            == [r["record_id"] for r in second["records"]])


def test_route_invariant_total_is_built_plus_rejected():
    result = EngagementMemoryBridge().push_summaries(
        ENGAGEMENTS + ENGAGEMENTS + [{}])
    summary = result["summary"]
    assert summary["total"] == summary["built"] + summary["rejected"]


class RecordingStore:
    """Mock store: records every put, optional boom, verbatim ack."""

    def __init__(self, ack=None, boom=None):
        self.puts = []
        self._ack = ack if ack is not None else {"written": True}
        self._boom = boom

    def put(self, record):
        self.puts.append(record)
        if self._boom is not None:
            raise self._boom
        return self._ack


def test_injected_store_receives_put_per_record():
    store = RecordingStore()
    result = EngagementMemoryBridge(store=store).push_summaries(ENGAGEMENTS)
    assert [rec["engagement_id"] for rec in store.puts] == [
        "E-01", "E-02", "E-03", "E-04", "E-05", "E-06", "E-07", "E-08"]
    assert result["summary"]["store_present"] is True
    assert result["summary"]["stored"] == result["summary"]["built"] == 8
    assert set(result["stored"]) == {
        rec["record_id"] for rec in result["records"]}


def test_store_absent_is_plan_only():
    store = RecordingStore()
    result = EngagementMemoryBridge().push_summaries(ENGAGEMENTS)
    assert result["stored"] == {}
    assert result["summary"]["store_present"] is False
    assert result["summary"]["built"] == 8
    assert store.puts == []


def test_constructor_store_is_the_default_route():
    store = RecordingStore()
    result = EngagementMemoryBridge(store=store).push_summaries(
        ENGAGEMENTS[:1])
    assert result["summary"]["stored"] == 1
    assert store.puts == [result["records"][0]]


def test_store_ack_echoed_verbatim():
    ack = {"written": True, "memory_path": "tenants/soc-primary/E-01.md"}
    store = RecordingStore(ack=ack)
    result = EngagementMemoryBridge(store=store).push_summaries(
        ENGAGEMENTS[:1])
    assert result["stored"]["soc-primary:E-01:0001"] == ack


def test_non_dict_store_ack_routes_rejected():
    store = RecordingStore(ack="ok")
    result = EngagementMemoryBridge(store=store).push_summaries(
        ENGAGEMENTS[:1])
    assert result["records"] == []
    assert result["stored"] == {}
    assert result["rejected"][0]["reasons"] == ["store ack not a dict: 'ok'"]
    summary = result["summary"]
    assert summary["total"] == summary["built"] + summary["rejected"] == 1


def test_exploding_store_never_crashes_flow():
    store = RecordingStore(boom=RuntimeError("disk"))
    result = EngagementMemoryBridge(store=store).push_summaries(
        ENGAGEMENTS[:1])
    assert result["records"] == []
    assert result["rejected"][0]["reasons"] == ["store put failed: disk"]
    assert result["summary"]["total"] == result["summary"]["rejected"] == 1


class GatedBridge(EngagementMemoryBridge):
    def validate_target(self, target):
        return (False, "outside scope")


def test_validate_target_gate_rejects_hostile_target():
    result = GatedBridge().push_summaries([dict(ENGAGEMENTS[0])])
    reasons = result["rejected"][0]["reasons"]
    assert any("rejected by host agent gate: outside scope" in r
               for r in reasons)
    assert result["summary"]["built"] == 0


def test_validate_target_silent_when_chassis_absent():
    assert not hasattr(EngagementMemoryBridge(), "validate_target")
    result = EngagementMemoryBridge().push_summaries([ENGAGEMENTS[0]])
    assert result["summary"]["built"] == 1


@pytest.mark.parametrize("bad", ["", "   ", None, 5, ["x"], "a\x00b",
                                 "a\u200bb", "line\nbreak", "a\u2028b"])
def test_scrub_summary_text_rejects_hostile(bad):
    with pytest.raises(ValueError):
        scrub_summary_text(bad)


def test_scrub_summary_text_collapses_space_runs():
    assert scrub_summary_text("  spaced   out  text ") == "spaced out text"


def test_scrub_summary_text_oversize_rejected():
    with pytest.raises(ValueError):
        scrub_summary_text("x" * 2001)


@pytest.mark.parametrize("tenant", [None, 5, "", " ", "SOC-PRIMARY",
                                    "has space", "has.dot", "a" * 65])
def test_scrub_tenant_id_rejects_hostile(tenant):
    with pytest.raises(ValueError):
        scrub_tenant_id(tenant)


def test_scrub_tenant_id_accepts_slug():
    assert scrub_tenant_id("  soc-primary_1a ") == "soc-primary_1a"


def test_single_dict_and_hostile_top_level():
    result = EngagementMemoryBridge().push_summaries(ENGAGEMENTS[0])
    assert result["summary"]["total"] == result["summary"]["built"] == 1
    for bad in (None, "E-01", 5):
        with pytest.raises(ValueError):
            EngagementMemoryBridge().push_summaries(bad)


def test_tag_and_finding_caps_and_malformed():
    bridge = EngagementMemoryBridge()
    row = {"engagement_id": "E-90", "tenant_id": "soc-primary",
           "summary": "oversize label run",
           "tags": ["t%d" % i for i in range(MAX_TAGS + 1)]}
    reasons = bridge.push_summaries([row])["rejected"][0]["reasons"]
    assert "tags exceed cap 10" in reasons
    row["tags"] = ["good", None]
    reasons = bridge.push_summaries([row])["rejected"][0]["reasons"]
    assert "tags must be a list of strings" in reasons
    row = {"engagement_id": "E-91", "tenant_id": "soc-primary",
           "summary": "refs",
           "findings": ["F-01; drop"] + ["F-%02d" % i for i in range(2, 26)]}
    reasons = bridge.push_summaries([row])["rejected"][0]["reasons"]
    assert any(r.startswith("finding reference malformed") for r in reasons)
    assert any(r.startswith("finding reference malformed: 'F-01; drop'")
               for r in reasons)
    row["findings"] = ["F-%02d" % i for i in range(MAX_FINDING_REFS + 1)]
    reasons = bridge.push_summaries([row])["rejected"][0]["reasons"]
    assert "findings references exceed cap 25" in reasons


def test_rejected_rows_carry_all_reasons_never_crash():
    rows = [
        {"tenant_id": "SOC-PRIMARY", "engagement_id": "bad;id!"},
        {"tenant_id": "soc-primary", "engagement_id": "E-93", "summary": None},
        {"engagement_id": "E-94", "summary": "no tenant"},
        {"tenant_id": "soc-primary", "engagement_id": "E-95"},  # no summary
        {"tenant_id": "soc-primary", "engagement_id": "E-96",
         "summary": "bad target", "target": "h; drop"},
        {"tenant_id": "soc-primary", "engagement_id": "E-965",
         "summary": "nonstring target", "target": 5},
        None, 5, {},
    ]
    result = EngagementMemoryBridge().push_summaries(rows)
    assert result["summary"]["rejected"] == len(rows) == 9
    by_text = json.dumps(result["rejected"], default=str)
    assert "engagement id malformed" in by_text
    assert "text must be a non-empty string" in by_text
    assert "rejected tenant_id" in by_text
    assert "rejected by host agent gate" not in by_text
    assert "rejected host with disallowed characters" in by_text
    assert "host must be a non-empty string" in by_text
    unusable = next(row for row in result["rejected"]
                    if row["engagement_id"] == "<missing-id>")
    assert unusable["tenant_id"] == "<missing-tenant>"


def test_tenant_read_plan_is_planner_strings_only():
    plan = EngagementMemoryBridge().tenant_read_plan("soc-primary")
    assert set(plan) == {"tenant_id", "steps", "notes"}
    assert plan["tenant_id"] == "soc-primary"
    assert len(plan["steps"]) == 3
    assert all(isinstance(s, str) for s in plan["steps"] + plan["notes"])
    assert any("soc-primary" in s for s in plan["steps"])
    assert plan["notes"][0].startswith("planner strings only")


def test_tenant_read_plan_hostile_tenant_error_shape():
    plan = EngagementMemoryBridge().tenant_read_plan("NOT-A-TENANT")
    assert set(plan) == {"tenant_id", "error", "steps", "notes"}
    assert plan["steps"] == [] and plan["notes"] == []
    assert plan["error"].startswith("rejected tenant_id")


def test_tenant_index_layout_view():
    result = EngagementMemoryBridge().push_summaries(ENGAGEMENTS)
    index = EngagementMemoryBridge().tenant_index(result["records"])
    assert set(index) == {"lab-fleet", "soc-primary", "soc-secondary"}
    assert index["soc-primary"] == [
        "soc-primary:E-01:0001", "soc-primary:E-02:0002",
        "soc-primary:E-05:0005", "soc-primary:E-08:0008"]
    assert index["lab-fleet"] == [
        "lab-fleet:E-06:0006", "lab-fleet:E-07:0007"]
    assert EngagementMemoryBridge().tenant_index([None, {"tenant_id": 5}]) == {}


def test_planner_purity_and_pinned_source_scan():
    module = importlib.import_module(
        "agentic_ai.agents.cyber.soc_memory_bridge")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in BANNED_SOURCE_TOKENS:
        assert banned not in source.lower(), banned
    for token in WALL_CLOCK_TOKENS:
        assert token not in source, token


def test_fixture_contract_and_uniqueness():
    assert CORPUS["meta"]["schema"] == "soc_memory_engagements/v1"
    ids = [row["engagement_id"] for row in ENGAGEMENTS
           if isinstance(row.get("engagement_id"), str)]
    assert len(set(ids)) == len(ids)
    valid = [i for i in ids if i not in CORPUS["meta"]["invalid_ids"]]
    invalid = [i for i in ids if i in CORPUS["meta"]["invalid_ids"]]
    assert len(valid) == CORPUS["meta"]["valid_count"] == 8
    assert set(invalid) == set(CORPUS["meta"]["invalid_ids"])


def test_unknown_legacy_kwargs_absorbed():
    record, reasons = EngagementMemoryBridge().build_record(
        ENGAGEMENTS[0], junk=True, extra="x")
    assert reasons == []
    assert record["record_id"].endswith(":E-01:0001")
    result = EngagementMemoryBridge().push_summaries(
        ENGAGEMENTS[:1], legacy_mode="old")
    assert result["summary"]["built"] == 1
    plan = EngagementMemoryBridge().tenant_read_plan("soc-primary", junk=2)
    assert plan["tenant_id"] == "soc-primary"


def test_empty_summaries_zero_counts():
    result = EngagementMemoryBridge().push_summaries([])
    assert result == {
        "records": [], "stored": {}, "rejected": [],
        "summary": {"total": 0, "built": 0, "stored": 0, "rejected": 0,
                    "tenants": 0, "store_present": False},
    }
