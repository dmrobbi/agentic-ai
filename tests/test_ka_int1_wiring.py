"""KA-INT-1 wiring verification: the P1 standalone modules surface as
agent ops on BOTH chassis and actually drive through the wired surfaces;
set_authorization stores expiry (the KA-052 discard fix); revoke clears
it; check_authorization sweeps expired engagement auths and audits the
revocations. No network; all file work under tmp_path."""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from agentic_ai.agents.cyber.kali import AuthorizationLevel, KaliAgent
from agentic_ai.agents.cyber.kali_v2 import KaliAgentV2
from agentic_ai.agents.cyber.auth_expiry import EVENT_KIND
from agentic_ai.infrastructure.utils import utcnow

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
SOC_FINDINGS = json.loads(
    (FIXTURES / "findings" / "soc_findings.json").read_text())["findings"]
KEV_COVERAGE = json.loads(
    (FIXTURES / "scans" / "kev_bridge_coverage.json").read_text())["coverage"]

OPS = (
    "authorize_tool", "role_allows_dry_run", "create_evidence_bundle",
    "verify_evidence_bundle", "verify_soc_findings", "kevstig_fan_out",
)


def _agent(tmp_path):
    return KaliAgent(
        agent_id="ka-int1", workspace=str(tmp_path / "ws"),
        log_dir=str(tmp_path / "logs"))


def test_v1_agent_drives_the_module_ops(tmp_path):
    agent = _agent(tmp_path)
    for op in OPS:
        assert callable(getattr(agent, op)), op
    ok, reason = agent.authorize_tool("nmap", "operator")
    assert ok is True and "permits level 1" in reason
    ok, reason = agent.authorize_tool("nmap", "verify_only")
    assert ok is False and "does not permit" in reason
    result = agent.verify_soc_findings(SOC_FINDINGS)
    assert result["summary"]["planned"] == 8
    assert result["summary"]["unplannable"] == 4
    fan = agent.kevstig_fan_out(KEV_COVERAGE)
    assert fan["counts"]["catalog_count"] == 1734
    assert len(fan["recommendations"]) == 7
    src = tmp_path / "ev"
    src.mkdir()
    (src / "note.txt").write_bytes(b"wired evidence")
    bundle = agent.create_evidence_bundle(str(src), str(tmp_path / "b.tgz"))
    assert bundle["file_count"] == 1
    assert agent.verify_evidence_bundle(str(tmp_path / "b.tgz")) == {
        "ok": True, "problems": []}


def test_v2_agent_drives_the_module_ops(tmp_path):
    agent = KaliAgentV2(workspace=str(tmp_path / "ws2"))
    for op in OPS:
        assert callable(getattr(agent, op)), op
    ok, _ = agent.authorize_tool("nmap", "operator")
    assert ok is True
    result = agent.verify_soc_findings(SOC_FINDINGS)
    assert result["summary"]["planned"] == 8
    fan = agent.kevstig_fan_out(KEV_COVERAGE)
    assert fan["counts"]["routed_count"] == 273
    src = tmp_path / "ev2"
    src.mkdir()
    (src / "note.txt").write_bytes(b"v2 wired")
    bundle = agent.create_evidence_bundle(
        str(src), str(tmp_path / "b2.tgz"), engagement_id="ENG-V2")
    assert bundle["manifest"]["engagement_id"] == "ENG-V2"
    assert agent.verify_evidence_bundle(str(tmp_path / "b2.tgz"))["ok"] is True


def test_set_authorization_stores_expiry_and_revoke_clears_it(tmp_path):
    agent = _agent(tmp_path)
    expires_at = utcnow() + timedelta(hours=1)
    ok = agent.set_authorization(
        AuthorizationLevel.CRITICAL, engagement_id="E1", expires_at=expires_at)
    assert ok is True
    assert agent.engagement_auth_expiry["E1"] == expires_at  # the discard FIX
    agent.revoke_authorization(engagement_id="E1")
    assert "E1" not in agent.engagement_authorizations
    assert "E1" not in agent.engagement_auth_expiry          # both cleaned


def test_expired_engagement_auth_revoked_and_audited(tmp_path):
    agent = _agent(tmp_path)
    agent.set_authorization(
        AuthorizationLevel.CRITICAL, engagement_id="E2",
        expires_at=utcnow() + timedelta(hours=1))
    # simulate elapsed time (set_authorization refuses past expiries):
    agent.engagement_auth_expiry["E2"] = utcnow() - timedelta(seconds=5)
    ok, reason = agent.check_authorization("mimikatz")
    assert ok is False
    assert "Authorization level 3 required, have 0" in reason  # swept out
    assert "E2" not in agent.engagement_authorizations
    assert "E2" not in agent.engagement_auth_expiry
    audit = Path(agent.log_dir) / "audit_log.jsonl"
    lines = audit.read_text().strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["event"] == EVENT_KIND
    assert event["engagement_id"] == "E2"
