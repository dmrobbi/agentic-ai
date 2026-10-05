"""KA-031 tests - PrivescMixin: the index sanity, the 6-phase plan per
platform (+ the aliases + the unknown-platform ValueError), the scrub
and host-gate behavior, the lookup (found / cross-platform / miss /
invalid), and the command-syntax policy pin. No network; no execution."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import AuthorizationLevel, KaliAgent
from agentic_ai.agents.cyber.privesc import PrivescMixin

BENIGN = "lab-host1.lab.example"
REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def chassis(tmp_path_factory):
    ws = tmp_path_factory.mktemp("ka031")
    agent = KaliAgent(agent_id="ka031", workspace=str(ws / "ws"),
                      log_dir=str(ws / "logs"))
    agent.set_authorization(AuthorizationLevel.CRITICAL)
    return agent


def test_index_shape_and_vocab(tmp_path):
    index = PrivescMixin().privesc_index()
    assert set(index) == {"meta", "capability_vocab", "platforms"}
    assert set(index["platforms"]) == {"unix", "windows"}
    vocab = set(index["capability_vocab"])
    total = 0
    for plat, rows in index["platforms"].items():
        for row in rows:
            assert set(row) == {"binary", "capabilities", "syntax",
                                "detection"}, (plat, row.get("binary"))
            assert set(row["capabilities"]) <= vocab, row["binary"]
            assert row["syntax"] and row["detection"]
            total += 1
    assert total == index["meta"]["totals"]["rows"] == 29
    assert index["meta"]["totals"]["platforms"] == 2
    # the index file itself = the committed data (not a test artifact):
    data_path = REPO / "agentic_ai/agents/cyber/data/privesc_index.json"
    assert data_path.is_file()


@pytest.mark.parametrize("platform", ["unix", "linux", "macos", "windows"])
def test_plan_privesc_full_structure(platform):
    # the mixin is STANDALONE until KA-INT-3 composes it: bare subject
    plan = PrivescMixin().plan_privesc(BENIGN, platform)
    assert plan["target"] == BENIGN
    canonical = "windows" if platform == "windows" else "unix"
    assert plan["platform"] == canonical
    assert len(plan["phases"]) == 6
    ids = [p["phase"] for p in plan["phases"]]
    assert ids == ["1-scope", "2-enumerate", "3-capability-fit",
                   "4-strategy", "5-evidence", "6-hardening"]
    for phase in plan["phases"]:
        assert phase["activities"] and phase["sample_commands"]
        assert phase["policy"] == {"command_syntax_only": True}
    enum_cmds = plan["phases"][1]["sample_commands"]
    if canonical == "unix":
        assert "sudo -l" in enum_cmds
        assert "find / -perm -4000 -type f 2>/dev/null" in enum_cmds
    else:
        assert "whoami /priv" in enum_cmds


def test_plan_privesc_unknown_platform_actionable():
    with pytest.raises(ValueError) as err:
        PrivescMixin().plan_privesc(BENIGN, "solaris")
    assert "known: unix, linux, macos, windows" in str(err.value)


def test_plan_scrubs_and_consults_gate(chassis):
    """the mixin is standalone until KA-INT-3 composes it; the
    host-gate consult is exercised via a local composite mirroring
    the composed shape (a gate-carrying host + the mixin)."""
    class HostWithGate(PrivescMixin):
        def __init__(self, agent):
            self._agent = agent

        def validate_target(self, target):
            return self._agent.validate_target(target)

    host = HostWithGate(chassis)
    with pytest.raises(ValueError):
        host.plan_privesc("192.0.2.1; calc", "unix")
    chassis.add_to_blacklist("192.0.2.66")
    try:
        with pytest.raises(ValueError) as err:
            host.plan_privesc("192.0.2.66", "unix")
        assert "target rejected by host agent gate" in str(err.value)
    finally:
        chassis.remove_from_blacklist("192.0.2.66")


def test_lookup_found_and_shape():
    out = PrivescMixin().privesc_capability_lookup("awk", platform="unix")
    assert out["found"] is True and out["binary"] == "awk"
    row = out["rows"][0]
    assert row["platform"] == "unix"
    assert "shell" in row["capabilities"]
    assert "awk 'BEGIN {system(\"/bin/sh\")}'" in row["syntax"]


def test_lookup_cross_platform_and_case_insensitive():
    out = PrivescMixin().privesc_capability_lookup("Python3")
    plats = [r["platform"] for r in out["rows"]]
    assert plats == ["unix"]  # the index carries python3 only on unix


def test_lookup_miss_and_invalid():
    out = PrivescMixin().privesc_capability_lookup("nonexistent-bin")
    assert out == {"binary": "nonexistent-bin", "rows": [], "found": False}
    with pytest.raises(ValueError):
        PrivescMixin().privesc_capability_lookup("")
    with pytest.raises(ValueError):
        PrivescMixin().privesc_capability_lookup("awk;sh")
    with pytest.raises(ValueError):
        PrivescMixin().privesc_capability_lookup("x" * 65)


def test_commands_stay_command_syntax():
    """THE POLICY PIN: every command = short shell syntax; no encoded
    blobs, no hex-shellcode, no base64-decode tricks."""
    index = PrivescMixin().privesc_index()
    for plat, rows in index["platforms"].items():
        for row in rows:
            for cmd in row["syntax"]:
                assert len(cmd) <= 160, (plat, row["binary"], cmd)
                assert "-d" not in cmd.split() or "base64" not in cmd.split()[0]
                assert not re.search(r"[A-Za-z0-9+/]{80,}", cmd), cmd
                assert "Invoke-" not in cmd or "powershell" in cmd


def test_module_never_executes():
    import importlib
    module = importlib.import_module("agentic_ai.agents.cyber.privesc")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket", "base64"):
        assert banned not in source, banned
