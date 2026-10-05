"""KA-025 - playbook-vs-DB consistency: every tool the playbooks can
reference exists in KALI_TOOLS_DB (or in the mixin catalogs) - no orphans
in principle. The MEASURED reality is pinned: exactly ONE orphan exists
(aircrack_crack carries "aircrack-ng"; the DB key is aircrack_ng), and
the AD playbook's docstring promises more steps than its body implements
(bloodhound -> enum4linux -> ldapsearch; the body runs bloodhound only).
Both are flagged for KA-INT-2. Dynamic dry-run sanity included."""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from agentic_ai.agents.cyber.kali import KALI_TOOLS_DB

import pytest

from agentic_ai.agents.cyber.kali import AuthorizationLevel, KaliAgent

# the playbooks' referenceable tool sets (derived from the bodies at
# 2026-10-05; conditionals included: these are the tools a run MAY call)
PLAYBOOK_TOOLSETS = {
    "run_recon_playbook": {"nmap", "theHarvester", "amass", "dnsrecon",
                           "nikto"},
    "run_web_audit_playbook": {"gobuster", "nikto", "wpscan", "sqlmap"},
    "run_password_audit_playbook": {"john", "hashcat"},
    "run_wireless_audit_playbook": {"wifite", "aircrack-ng", "reaver"},
    "run_ad_audit_playbook": {"bloodhound"},
}
# PINNED ORPHAN (reported; KA-INT-2 candidate): the wrapper carries the
# hyphenated name while the DB key is aircrack_ng - the wrapper can only
# ever return "Unknown tool". Everything else resolves.
DOCUMENTED_ORPHANS = {"aircrack-ng"}


@pytest.fixture(scope="module")
def dry_agent(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ka025")
    agent = KaliAgent(agent_id="ka025-pb", workspace=str(ws / "ws"),
                      log_dir=str(ws / "logs"))
    agent.set_authorization(AuthorizationLevel.CRITICAL)
    agent.disable_safe_mode()  # bloodhound (POST_EXPLOITATION) must flow:
    # this task pins tool MEMBERSHIP, not the KA-061 gate
    agent.enable_dry_run()
    return agent


def test_all_execute_tool_refs_resolve():
    """The static extraction over the whole chassis class: every
    execute_tool reference is a DB key - except the documented orphan."""
    source = inspect.getsource(KaliAgent)
    refs = set(re.findall(r"execute_tool\(\s*[\"\x27]([^\"\x27]+)[\"\x27]",
                          source))
    assert len(refs) == 25  # measured 2026-10-05
    orphans = {r for r in refs if r not in KALI_TOOLS_DB}
    assert orphans == DOCUMENTED_ORPHANS, orphans


def test_playbook_toolsets_exist_in_databases():
    db = KALI_TOOLS_DB
    allowed = set(db) | DOCUMENTED_ORPHANS
    for playbook, toolset in PLAYBOOK_TOOLSETS.items():
        for tool in toolset:
            assert tool in allowed, (playbook, tool)
    # the mixin catalogs are additional allowed families (none referenced
    # by the playbooks today - pinned so additions stay conscious):
    import json
    catalog = json.loads((Path(__file__).resolve().parents[1]
                          / "agentic_ai/agents/cyber/data/xss_tools.json"
                          ).read_text())
    xss_names = {t["name"] for e in catalog["phases"].values()
                 for t in e["tools"]}
    assert xss_names  # the catalog family loads; the union stays allowed


def test_ad_playbook_docstring_honesty(dry_agent):
    """PINNED HONESTY GAP (reported): the docstring promises
    bloodhound -> enum4linux -> ldapsearch; the body executes
    bloodhound only."""
    doc = inspect.getdoc(KaliAgent.run_ad_audit_playbook) or ""
    assert "enum4linux" in doc and "ldapsearch" in doc  # the promise
    source = inspect.getsource(KaliAgent.run_ad_audit_playbook)
    # the body references bloodhound only (static): no enum4linux/ldap
    assert "bloodhound" in source
    assert "enum4linux" not in source.split('"""', 2)[2]
    assert "ldapsearch" not in source.split('"""', 2)[2]
    # dynamic: the run returns exactly the bloodhound execution
    results = dry_agent.run_ad_audit_playbook(
        domain="lab.example", username="svc_scan", password="labpass")
    assert set(results) == {"bloodhound"}
    assert results["bloodhound"].status == "completed"


def test_dry_playbook_runs_reference_only_known_tools(dry_agent):
    web = dry_agent.run_web_audit_playbook(
        url="http://lab-host1.lab.example", target="lab-host1.lab.example")
    pw = dry_agent.run_password_audit_playbook(hash_file="hashes.txt")
    pw_hashcat = dry_agent.run_password_audit_playbook(
        hash_file="hashes.txt", custom_wordlist="custom.txt")
    results = list(web.values()) + list(pw.values()) + list(pw_hashcat.values())
    assert results  # gobuster/nikto/wpscan/sqlmap + john + john/hashcat
    for ex in results:
        assert ex.status == "completed", ex.tool_name
        assert ex.tool_name in KALI_TOOLS_DB, ex.tool_name  # NO orphans live


def test_report_method_shape(dry_agent):
    web = dry_agent.run_web_audit_playbook(
        url="http://lab-host1.lab.example", target="lab-host1.lab.example")
    report = dry_agent.generate_playbook_report("web-audit", web)
    assert isinstance(report, str)
    assert "# Playbook Report: web-audit" in report
    assert "## Execution Summary" in report
    assert "Tools Executed: 4" in report
