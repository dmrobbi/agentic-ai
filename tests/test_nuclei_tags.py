"""KA-027 - nuclei template tags + severity mapping, pinned against the
committed conventions snapshot (the anti-drift reference). The parser's
severity buckets and the no-bucket unknown behavior are EXACTLY the
snapshot's contract; the tags pass through verbatim. The v1 automated
class documents its no-nuclei reality; the v2 nuclei DB-row + the
recommendation presence land here. No network."""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import KaliAgent
from agentic_ai.agents.cyber.kali_v2 import (
    ENHANCED_KALI_TOOLS_DB,
    KaliAgentV2,
)
from agentic_ai.agents.cyber.kali_v2 import OutputParsers

REPO = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO / "tests" / "fixtures" / "parsers" / "nuclei_tags.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
SCALE = FIXTURE["severity_scale"]
TAGS = FIXTURE["template_tags"]


def _stream(rows):
    return "\n".join(json.dumps(row) for row in rows)


def test_fixture_shape():
    assert set(FIXTURE) == {"meta", "severity_scale", "template_tags"}
    legal = {s for s, spec in SCALE.items() if spec["counted"]}
    assert legal == {"critical", "high", "medium", "low", "info"}
    assert SCALE["unknown"]["counted"] is False
    assert SCALE["unknown"]["bucket_key"] is None


@pytest.mark.parametrize("severity,counted", [
    (s, SCALE[s]["counted"]) for s in sorted(SCALE)
])
def test_parser_severity_mapping_matches_snapshot(severity, counted):
    row = {"template-id": "demo/tag", "info": {"name": "row",
            "severity": severity, "tags": [], "description": ""},
           "host": "192.0.2.10", "matched-at": "192.0.2.10"}
    result = OutputParsers.parse_nuclei_output(_stream([row]))
    assert result["total_findings"] == 1  # listed regardless
    if counted:
        assert result["by_severity"][SCALE[severity]["bucket_key"]] == 1
    else:
        assert sum(result["by_severity"].values()) == 0
        assert result["vulnerabilities"][0]["severity"] == "unknown"


def test_tags_preserved_verbatim():
    tags = ["cve", "jndi", "java"]
    row = {"template-id": "cves/2021/CVE-2021-44228",
           "info": {"name": "Log4Shell", "severity": "critical",
                    "tags": tags, "description": "d"},
           "host": "http://192.0.2.30", "matched-at": "http://192.0.2.30/app"}
    result = OutputParsers.parse_nuclei_output(_stream([row]))
    assert result["vulnerabilities"][0]["tags"] == tags  # order intact
    # a multi-tag row keeps every tag verbatim too:
    weird = ["cve", "%s", "zero\\u200bwidth-ish", "demo"]
    row2 = {"template-id": "demo/weird", "info": dict(row["info"], tags=weird),
            "host": "h", "matched-at": "h:1"}
    result2 = OutputParsers.parse_nuclei_output(_stream([row2]))
    assert result2["vulnerabilities"][0]["tags"] == weird


def test_v1_automated_class_no_nuclei_documented(tmp_path):
    """PINNED HONESTY GAP: the v1 web_vuln 'automated' class carries the
    nikto scanner one-liner, NOT nuclei; nuclei surfaces on the v2
    chassis only (the DB row + the recommendations)."""
    agent = KaliAgent(agent_id="ka027", workspace=str(tmp_path / "ws"),
                      log_dir=str(tmp_path / "logs"))
    rows = agent.web_vuln_commands("lab-host1.lab.example", "automated")
    blob = json.dumps(rows)
    assert "nikto" in blob and "nuclei" not in blob


def test_v2_nuclei_db_row_shape():
    row = ENHANCED_KALI_TOOLS_DB["nuclei"]
    assert row.command == "nuclei"
    assert row.category.value == "web_application"
    assert row.timeout_seconds == 1800
    assert set(row.args_schema) == {"target", "templates", "severity",
                                    "tags", "output", "rate_limit"}
    assert row.args_schema["severity"]["description"] == (
        "critical,high,medium,low,info")
    assert row.args_schema["target"]["required"] is True
    assert row.args_schema["rate_limit"]["default"] == 150


def test_recommendation_presence_nuclei_first():
    engine = KaliAgentV2().recommendation_engine
    assert engine.recommendations["web_server"][0] == "nuclei"
    tool_names = [t["name"] for t in engine.recommend_tools(
        {"type": "web server", "services": [{"name": "http", "port": 80}]})]
    assert "nuclei" in tool_names


def test_tag_families_reference_real_template_paths():
    """The cve tag's convention = the cves/<year>/<id> template path; the
    recorded corpus rows (KA-003) follow it - the snapshot and the
    corpus stay one vocabulary."""
    from agentic_ai.agents.cyber.kali_v2 import OutputParsers as P
    repo_rows = P.parse_nuclei_output(
        (REPO / "tests/fixtures/parsers/nuclei.sample.jsonl").read_text())
    for row in repo_rows["vulnerabilities"]:
        if row["template"] and "cves/" in row["template"]:
            assert re.search(r"cves/(\d{4})/", row["template"]), row["template"]
        if row["tags"]:
            for tag in row["tags"]:
                assert tag in TAGS, tag  # the corpus stays inside the snapshot
