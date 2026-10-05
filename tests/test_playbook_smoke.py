"""KA-007 - playbook smoke battery: the five audit playbooks dry-run
against a real agent (dry mode = the stubbed registry: no processes, no
network). Pinned: result-DICT shapes, DETERMINISTIC step order (the
insertion order of each body's calls), the conditional branches (domain,
custom wordlist, capture/BSSID, the nmap-port-marker nikto), the
aircrack-ng orphan's REAL consequence inside the wireless flow, and the
safe-mode gate's playbook visibility on the AD flow (bloodhound
refused). No network; no real processes."""

from __future__ import annotations

import pytest

from agentic_ai.agents.cyber.kali import AuthorizationLevel, KaliAgent

BENIGN = "lab-host1.lab.example"  # RFC 6761-style lab host
DOMAIN = "lab.example"


@pytest.fixture()
def agent(tmp_path):
    a = KaliAgent(agent_id="ka007-smoke", workspace=str(tmp_path / "ws"),
                  log_dir=str(tmp_path / "logs"))
    a.set_authorization(AuthorizationLevel.CRITICAL)
    a.enable_dry_run()
    return a


def test_recon_playbook_bare_minimal_flow(agent):
    results = agent.run_recon_playbook(target=BENIGN)
    # domain absent -> harvesting block skipped; the dry stdout carries no
    # "80/open" -> the nikto conditional skips too: exactly one step
    assert list(results) == ["nmap"]
    assert results["nmap"].status == "completed"
    assert results["nmap"].tool_name == "nmap"


def test_recon_playbook_domain_unlocks_ordered_steps(agent):
    results = agent.run_recon_playbook(target=BENIGN, domain=DOMAIN)
    # deterministic body order: nmap -> theharvester -> amass -> dnsrecon
    assert list(results) == ["nmap", "theharvester", "amass", "dnsrecon"]
    assert all(ex.status == "completed" for ex in results.values())
    assert results["theharvester"].arguments["domain"] == DOMAIN
    assert results["amass"].arguments["domain"] == DOMAIN


def test_recon_playbook_nikto_conditionals_true_branch(agent, monkeypatch):
    """The nikto fires only when the nmap record shows 80/open: pin the
    conditional's TRUE branch by mutating the dry record's stdout."""
    probe = agent.nmap_scan(target=BENIGN, ports="1-10000",
                            version_detect=True, os_detect=True)
    probe.stdout = "Nmap scan report for x\nPORT    STATE\n80/open  tcp"
    probe.__class__  # ToolExecution is a mutable dataclass (not frozen)
    monkeypatch.setattr(agent, "nmap_scan", lambda **kw: probe)
    results = agent.run_recon_playbook(target=BENIGN)
    assert list(results) == ["nmap", "nikto"]
    assert results["nikto"].tool_name == "nikto"
    assert results["nikto"].arguments["host"] == BENIGN


def test_web_playbook_shape_and_scheme_aware_args(agent):
    results = agent.run_web_audit_playbook(
        url="https://lab.example:8443/app", target=BENIGN)
    # deterministic order: gobuster -> nikto -> wpscan -> sqlmap
    assert list(results) == ["gobuster", "nikto", "wpscan", "sqlmap"]
    assert all(ex.status == "completed" for ex in results.values())
    nikto_args = results["nikto"].arguments
    assert nikto_args == {"host": "lab.example", "port": 8443, "ssl": True}
    assert results["gobuster"].arguments["target"] == "https://lab.example:8443/app"
    assert results["sqlmap"].arguments["url"] == "https://lab.example:8443/app"


def test_password_playbook_hashcat_branch(agent):
    bare = agent.run_password_audit_playbook(hash_file="hashes.txt")
    assert list(bare) == ["john"]
    full = agent.run_password_audit_playbook(
        hash_file="hashes.txt", custom_wordlist="custom.txt")
    assert list(full) == ["john", "hashcat"]
    assert full["hashcat"].arguments["wordlist"] == "custom.txt"


def test_wireless_playbook_conditionals(agent):
    bare = agent.run_wireless_audit_playbook(interface="wlan0")
    assert list(bare) == ["wifite"]
    with_capture = agent.run_wireless_audit_playbook(
        interface="wlan0", capture_file="cap.cap")
    # the aircrack orphan FIXED at KA-INT-2: the wrapper carries the DB
    # key (aircrack_ng); the step plans + completes in dry-run now.
    assert list(with_capture) == ["wifite", "aircrack"]
    aircrack = with_capture["aircrack"]
    assert aircrack.status == "completed"
    assert aircrack.stderr == ""
    assert aircrack.tool_name == "aircrack_ng"
    with_both = agent.run_wireless_audit_playbook(
        interface="wlan0", capture_file="cap.cap", target_bssid="01:23:45:67:89:AB")
    assert list(with_both) == ["wifite", "aircrack", "reaver"]
    assert with_both["reaver"].status == "completed"


def test_ad_playbook_respects_safe_mode_gate(agent):
    """The safe-mode gate (KA-INT-1) is visible through playbooks: the AD
    flow's bloodhound (POST_EXPLOITATION) is refused while safe_mode is
    on - the playbook returns the refused execution."""
    assert agent.safe_mode is True
    results = agent.run_ad_audit_playbook(
        domain=DOMAIN, username="svc_scan", password="labpass")
    assert list(results) == ["bloodhound"]
    bloodhound = results["bloodhound"]
    assert bloodhound.status == "failed"
    assert "safe mode" in bloodhound.stderr.lower()
