"""KA merge A2 tests - the CVE dossier ops over the transplanted
defensive workspaces (both CVEs verified real externally): pinned
catalog schema/rows, defense-only content (no PoC/exploit artifacts),
no data literals in the module source (the catalog lives in the data
file), index/outline shapes, closed refusal on unknown/hostile ids,
scrub hygiene with the content-vs-echo split, determinism, stamp
injection, and the purity/laziness source scan."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber import cve_dossiers as dossiers_mod
from agentic_ai.agents.cyber.cve_dossiers import (
    DETECTION_SURFACES,
    DOSSIERS_FILE,
    DOSSIER_FIELDS,
    cve_dossier_outline,
    cve_dossiers_index,
)

DOSSIER_EXPECTED_IDS = ("CVE-2026-41089", "CVE-2026-46243")

INDEX_ROW_KEYS = {"cve_id", "cvss", "published", "product", "one_liner"}


def test_data_file_parses_with_the_pinned_schema():
    catalog = json.loads(DOSSIERS_FILE.read_text(encoding="utf-8"))
    assert sorted(catalog) == list(DOSSIER_EXPECTED_IDS)
    for key, row in catalog.items():
        assert set(row) == set(DOSSIER_FIELDS)
        assert (isinstance(row["cvss"], (int, float))
                and not isinstance(row["cvss"], bool)
                and 0 <= row["cvss"] <= 10)
        for field in ("published", "product", "cwe", "one_liner",
                      "summary", "patch", "provenance"):
            assert isinstance(row[field], str) and row[field].strip()
        assert (isinstance(row["affected"], list)
                and len(row["affected"]) >= 3)
        assert (isinstance(row["mitigation"], list)
                and len(row["mitigation"]) >= 3)
        assert all(isinstance(x, str) and x.strip()
                   for x in row["affected"] + row["mitigation"])
        assert isinstance(row["detection"], list) and row["detection"]
        for det in row["detection"]:
            assert set(det) == {"surface", "what", "artifact"}
            assert det["surface"] in DETECTION_SURFACES
            assert det["what"].strip() and det["artifact"].strip()
        links = row["links"]
        assert isinstance(links, dict) and 1 <= len(links) <= 25
        for name, url in links.items():
            assert name.strip() and url.startswith("https://")


def test_data_file_is_defense_only():
    text = DOSSIERS_FILE.read_text(encoding="utf-8")
    # the PoC/exploit FILE artifacts never transposed (repo links okay)
    for forbidden in (
        "poc.py", "poc_annotated.py", "libnss_pwn.c", "trigger.c",
        "exploit_chain",
    ):
        assert forbidden not in text, forbidden
    catalog = json.loads(text)
    # the detection rows map DEFENSIVE artifacts only
    for row in catalog.values():
        for det in row["detection"]:
            assert not det["artifact"].endswith("poc.py")
            assert det["surface"] in ("suricata", "yara", "shell")


def test_module_carries_no_data_literal():
    # the dossier content lives in the data file, never duplicated into
    # the module (binding stays lazy; the module stays small)
    source = Path(dossiers_mod.__file__).read_text(encoding="utf-8")
    for data_token in ("KB5089549", "3da1fdf4efbc", "2026041089",
                       "RHSB-2026-005"):
        assert data_token not in source, data_token


def test_index_shape_and_determinism():
    one = cve_dossiers_index()
    assert set(one) == {"dossiers", "count", "generated_at"}
    assert one["count"] == 2
    assert one["generated_at"] is None
    ids = [row["cve_id"] for row in one["dossiers"]]
    assert ids == list(DOSSIER_EXPECTED_IDS)  # sorted order
    for row in one["dossiers"]:
        assert set(row) == INDEX_ROW_KEYS
    two = cve_dossiers_index()
    assert one == two
    assert json.loads(json.dumps(one)) == one


def test_index_rows_have_clean_echoes():
    for row in cve_dossiers_index()["dossiers"]:
        for field in ("published", "product", "one_liner"):
            value = row[field]
            assert isinstance(value, str)
            assert all(ord(char) >= 0x20 for char in value)


def test_outline_41089_full_row():
    result = cve_dossier_outline(
        "CVE-2026-41089", generated_at="2026-10-08T09:30:00+00:00")
    assert set(result) == {"cve_id", "generated_at", "dossier"}
    assert result["cve_id"] == "CVE-2026-41089"
    assert result["generated_at"] == "2026-10-08T09:30:00+00:00"
    dossier = result["dossier"]
    assert set(dossier) == set(DOSSIER_FIELDS)
    assert dossier["cvss"] == 9.8
    assert "KB5089549" in dossier["patch"]
    assert dossier["detection"][0]["surface"] == "suricata"
    assert "2026041089" in dossier["detection"][0]["what"]
    assert any(det["surface"] == "yara"
               for det in dossier["detection"])
    assert any("KB5089549" in step for step in dossier["mitigation"])
    assert dossier["links"]["nvd"].startswith("https://")
    # content survives the scrub (beyond the 128-char echo cap)
    assert "Securonix" in dossier["summary"]
    assert "RtlStringCbCopyExW" in dossier["detection"][1]["what"]


def test_outline_46243_full_row():
    result = cve_dossier_outline("CVE-2026-46243")
    dossier = result["dossier"]
    assert dossier["cvss"] == 7.8
    assert "3da1fdf4efbc" in dossier["patch"]
    assert "3da1fdf4efbc" in dossier["summary"]  # no truncation
    assert dossier["detection"][0]["surface"] == "shell"
    assert any("keyctl" in step for step in dossier["mitigation"])
    assert any("user namespaces" in step
               for step in dossier["mitigation"])
    assert "RHSB-2026-005" in dossier["links"]["red_hat_rhsb"]
    assert "oss_security" in dossier["links"]
    assert "local root" in dossier["summary"]


@pytest.mark.parametrize(
    "bad_id",
    [None, "", "   ", "CVE-0000-00000", "\x01\x02CVE",
     "cve-2026-41089"],  # lowercase never resolves: ids are exact
    ids=["none", "empty", "blank", "absent-id", "control-chars",
         "wrong-case"])
def test_unknown_or_hostile_ids_refuse_closed(bad_id):
    with pytest.raises(ValueError):
        cve_dossier_outline(bad_id)


def test_purity_and_laziness_source_scan():
    source = Path(dossiers_mod.__file__).read_text(encoding="utf-8")
    for forbidden in (
        # no process spawning or dynamic execution
        "subprocess", "popen", "os.system", "eval(", "exec(",
        # no network facilities
        "urllib", "socket", "requests", "http.client",
        # no clock reads: the stamp arrives by injection
        "utcnow", "time.time", "today(", "gmtime", "localtime",
    ):
        assert forbidden not in source, forbidden
    # no chassis coupling at all, and exactly one lazy data-file read
    assert "agentic_ai" not in source
    assert source.count("read_text(") == 1
