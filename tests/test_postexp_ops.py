"""KA-044 tests - PostExploitMixin: the arcs (+ aliases + the unknown-arc
ValueError), the per-arc read-only catalogs, the credential-class rows
(locations only), the 5-phase evidence-only plans (policy on every
phase), the command classifier, the gate refusing mutation-class steps
on synthetic plans, the scrub + host-gate consult, and the
never-executes scan. No network; no execution."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.postexp import (CREDENTIAL_CLASSES,
                                             MUTATION_RULES, POSTEXP_POLICY,
                                             PostExploitMixin)

BENIGN = "lab-host1.lab.example"
PIN_ARCS = ["credential-surface", "host-enum", "lateral-map",
            "persistence-discovery"]
PIN_PHASES = ["1-boundary", "2-enumerate", "3-evidence", "4-detect",
              "5-handoff"]
PIN_STEPS = {
    "host-enum": ["identity", "privilege-context", "services", "network",
                  "scheduled", "artifacts"],
    "credential-surface": ["os-credential-managers", "ssh-key-surfaces",
                           "ticket-caches", "history-surfaces"],
    "persistence-discovery": ["service-audit", "task-audit", "startup-audit",
                              "registry-autorun-audit"],
    "lateral-map": ["network-context", "established-peers",
                    "trusts-and-suffixes", "share-surface"],
}
PIN_ARC_ALIASES = [("host-enum", "system"), ("credential-surface",
                                             "credentials"),
                   ("persistence-discovery", "persistence"),
                   ("lateral-map", "lateral")]
PIN_HOSTILE_TARGETS = [
    "",
    None,
    5,
    "127.0.0.1; touch /tmp/x",
    "a b",
    "a|b",
    "a&b",
    "a$(x)b",
    "a`b`c",
    "a..b",
    "a\nb",
]


def test_policy_rows_and_forbidden_classes():
    out = PostExploitMixin().postexp_policy()
    assert out["policy"] == POSTEXP_POLICY == {"evidence_only": True,
                                               "mutation_forbidden": True}
    assert out["forbidden_classes"] == [cls for cls, _ in MUTATION_RULES]
    assert len(set(out["forbidden_classes"])) == len(out["forbidden_classes"])
    assert all(line.strip() for line in out["doc"])


def test_arcs_list_and_modes():
    out = PostExploitMixin().postexp_arcs()
    assert out["arcs"] == PIN_ARCS
    assert out["modes"] == {"host-enum": "audit",
                            "credential-surface": "audit",
                            "persistence-discovery": "audit",
                            "lateral-map": "report"}
    assert out["policy"] == POSTEXP_POLICY


@pytest.mark.parametrize("arc,alias", PIN_ARC_ALIASES)
def test_plan_postexp_full_structure(arc, alias):
    plan = PostExploitMixin().plan_postexp(BENIGN, alias)
    assert plan["target"] == BENIGN
    assert plan["arc"] == arc
    assert plan["policy"] == POSTEXP_POLICY
    assert plan["meta"]["mode"] in {"audit", "report"}
    assert [p["phase"] for p in plan["phases"]] == PIN_PHASES
    for phase in plan["phases"]:
        assert phase["policy"] == POSTEXP_POLICY
        assert phase["activities"] and phase["sample_commands"]
        for cmd in phase["sample_commands"]:
            assert "{target}" not in cmd


def test_plan_unknown_arc_refused():
    with pytest.raises(ValueError) as err:
        PostExploitMixin().plan_postexp(BENIGN, "exfil")
    assert ("known: credential-surface, host-enum, lateral-map, "
            "persistence-discovery") in str(err.value)


@pytest.mark.parametrize("value", PIN_HOSTILE_TARGETS)
def test_plan_target_scrub_rejects_hostile(value):
    with pytest.raises(ValueError):
        PostExploitMixin().plan_postexp(value, "host-enum")


def test_host_gate_consult_and_silent_fallback():
    """A composed host passes its gate through this mixin; the standalone
    mixin (no validate_target attribute) still plans - silent fallback."""
    class _GateHost(PostExploitMixin):
        def __init__(self, refusals):
            self._refusals = refusals

        def validate_target(self, target):
            ok, msg = self._refusals.get(target, (True, "in scope"))
            return ok, msg

    host = _GateHost(refusals={"192.0.2.66": (False,
                                              "not inside the lab scope")})
    with pytest.raises(ValueError) as err:
        host.plan_postexp("192.0.2.66", "host-enum")
    assert "target rejected by host agent gate: not inside the lab scope" \
        in str(err.value)
    ok_plan = _GateHost(refusals={}).plan_postexp("192.0.2.66", "lateral-map")
    assert ok_plan["target"] == "192.0.2.66"
    fallback = PostExploitMixin()
    assert not hasattr(fallback, "validate_target")
    assert fallback.plan_postexp(BENIGN, "host-enum")["target"] == BENIGN


def test_catalog_steps_per_arc():
    mixin = PostExploitMixin()
    for arc, names in PIN_STEPS.items():
        out = mixin.postexp_step_catalog(arc)
        assert out["arc"] == arc
        assert out["policy"] == POSTEXP_POLICY
        assert [s["step"] for s in out["steps"]] == names
        assert all(s["commands"] for s in out["steps"])
    none_out = mixin.postexp_step_catalog(None)
    assert none_out == {"arcs": PIN_ARCS, "policy": POSTEXP_POLICY}
    with pytest.raises(ValueError):
        mixin.postexp_step_catalog("")


def test_persistence_arc_is_discovery_not_install():
    """THE EVIDENCE-ONLY PIN: the persistence arc audits what exists
    (query forms) and never plans an install/mutation step."""
    out = PostExploitMixin().postexp_step_catalog("persistence-discovery")
    assert out["mode"] == "audit"
    commands = [c for s in out["steps"] for c in s["commands"]]
    banned_starters = ("schtasks /create", "schtasks /delete", "sc create",
                       "sc delete", "systemctl enable", "systemctl start",
                       "crontab -e", "reg add")
    for cmd in commands:
        assert not any(cmd.lower().startswith(b) or b in cmd.lower()
                       for b in banned_starters), cmd
    gate = PostExploitMixin().postexp_gate({"steps": out["steps"]})
    assert gate["verdict"] == "allow" and gate["refused"] == []


def test_lateral_arc_is_report_only_mapping():
    """THE MAPPING PIN: the lateral arc maps/reports and plans no
    remote-execution step class."""
    out = PostExploitMixin().postexp_step_catalog("lateral-map")
    assert out["mode"] == "report"
    commands = [c for s in out["steps"] for c in s["commands"]]
    exec_markers = ("psexec", "smbexec", "winrs", "wmic /node", "impacket-",
                    "xfreerdp", "mstsc", "ssh ")
    for cmd in commands:
        assert not any(m in cmd.lower() for m in exec_markers), cmd
    gate = PostExploitMixin().postexp_gate({"steps": out["steps"]})
    assert gate["verdict"] == "allow" and gate["refused"] == []


def test_credential_classes_locations_only():
    out = PostExploitMixin().postexp_credential_classes()
    assert out["policy"] == POSTEXP_POLICY
    assert sorted(out["classes"]) == sorted(CREDENTIAL_CLASSES)
    dump_markers = ("mimikatz", "secretsdump", "procdump", "ntdsutil",
                    "hashdump", "reg save", "lsass")
    for name, row in out["classes"].items():
        assert set(row) == {"surface", "discovery_commands", "evidence_role",
                            "policy"}
        assert row["policy"] == POSTEXP_POLICY
        for cmd in row["discovery_commands"]:
            assert not any(m in cmd.lower() for m in dump_markers), (name, cmd)
            assert cmd.split()[0] in {"cmdkey", "vaultcmd", "ls", "klist",
                                     "dir"}, (name, cmd)


def test_credential_arc_matches_class_rows():
    """No drift between the credential arc's steps and the class rows."""
    arc = PostExploitMixin().postexp_step_catalog("credential-surface")
    classes = PostExploitMixin().postexp_credential_classes()["classes"]
    assert [s["step"] for s in arc["steps"]] == PIN_STEPS[
        "credential-surface"]
    for entry in arc["steps"]:
        assert entry["commands"] == classes[entry["step"]][
            "discovery_commands"]


@pytest.mark.parametrize("command,expected", [
    ("net user backdoor Str0ng! /add", "account-mutation"),
    ("NET USER hacker /add", "account-mutation"),
    ("usermod -aG sudo evil", "account-mutation"),
    ("schtasks /create /tn evil /tr cmd", "persistence-install"),
    ("systemctl enable evil.service", "persistence-install"),
    ("crontab -e", "persistence-install"),
    ("sc config evilsvc binPath= cmd", "persistence-install"),
    ("reg add HKCU\\Run /v b /d cmd", "registry-write"),
    ("cat /home/u/.ssh/id_rsa | tee stolen", "file-mutation"),
    ("echo row >> /var/log/audit.log", "file-mutation"),
    ("ssh-keygen -q -f /tmp/k", "file-mutation"),
    ("apt install evilpkg", "package-install"),
    ("mimikatz sekurlsa::logonpasswords", "credential-extraction"),
    ("reg save HKLM\\SAM sam.hive", "credential-extraction"),
    ("psexec \\\\10.0.0.8 cmd", "lateral-exec"),
    ("ssh 10.0.0.9", "lateral-exec"),
    ("iptables -P INPUT DROP", "network-tamper"),
    ("route add 10.0.0.0/8 via gw", "network-tamper"),
    ("taskkill /f /pid 1", "service-kill"),
    ("net stop wazuh-agent", "service-kill"),
    ("wevtutil cl Security", "log-tamper"),
    ("history -c", "log-tamper"),
])
def test_classify_refuses_mutation_classes(command, expected):
    out = PostExploitMixin().classify_postexp_command(command)
    assert out["class"] == expected
    assert out["verdict"] == "refuse"
    assert out["matched"]
    assert out["policy"] == POSTEXP_POLICY


@pytest.mark.parametrize("command", [
    "crontab -l", "whoami /all", "id", "reg query HKCU\\Run", "ip route",
    "net share", "klist", "ls -la ~/.ssh", "schtasks /query /fo LIST",
])
def test_classify_allows_evidence_commands(command):
    out = PostExploitMixin().classify_postexp_command(command)
    assert out["class"] == "evidence"
    assert out["verdict"] == "allow"
    assert out["matched"] is None


@pytest.mark.parametrize("command", ["", "   ", None, 5, "x" * 241])
def test_classify_malformed_refused(command):
    with pytest.raises(ValueError):
        PostExploitMixin().classify_postexp_command(command)


def test_gate_refuses_mutation_steps_synthetic():
    """THE GATE PIN: a synthetic plan with mutation-class steps gets every
    mutation command refused; clean steps are unaffected."""
    synth = {"steps": [
        {"step": "install-backdoor",
         "commands": ["net user backdoor Str0ng! /add",
                      "reg add HKCU\\Software\\Run /v b /d cmd",
                      "crontab -l"]},
        {"step": "service-hijack",
         "commands": ["systemctl enable evil.service"]},
    ]}
    out = PostExploitMixin().postexp_gate(synth)
    assert out["verdict"] == "refuse"
    assert out["checked"] == 4
    assert out["refused_count"] == 3
    assert [r["class"] for r in out["refused"]] == [
        "account-mutation", "registry-write", "persistence-install"]
    for row in out["refused"]:
        assert row["step"] in {"install-backdoor", "service-hijack"}
        assert "evidence-only policy" in row["reason"]
        assert "re-plan" in row["reason"]
    assert out["policy"] == POSTEXP_POLICY


def test_gate_refuses_mutation_phases_synthetic():
    """The mixin's own plan shape (phases + sample_commands) is accepted;
    a mutation phase inside it is refused."""
    synth = {"phases": [
        {"phase": "1-boundary", "sample_commands": ["# boundary notes"]},
        {"phase": "2-persist",
         "sample_commands": ["schtasks /create /tn beacon",
                             "schtasks /query /fo LIST"]},
    ]}
    out = PostExploitMixin().postexp_gate(synth)
    assert out["verdict"] == "refuse"
    assert out["checked"] == 3
    assert out["refused_count"] == 1
    assert out["refused"][0]["step"] == "2-persist"
    assert out["refused"][0]["class"] == "persistence-install"


@pytest.mark.parametrize("arc", PIN_ARCS)
def test_gate_allows_own_plans(arc):
    plan = PostExploitMixin().plan_postexp(BENIGN, arc)
    out = PostExploitMixin().postexp_gate(plan)
    assert out["verdict"] == "allow"
    assert out["refused"] == []
    assert out["checked"] > 0
    assert out["policy"] == POSTEXP_POLICY


@pytest.mark.parametrize("plan", [
    None, "steps", ["id"], {},
    {"steps": []},
    {"phases": []},
    {"steps": ["bare-string"]},
    {"steps": [{"phase": "x"}]},
    {"steps": [{"step": "x", "commands": []}]},
    {"steps": [{"commands": ["id"]}]},
    {"steps": [{"step": "x", "commands": [None]}]},
    {"steps": [{"step": "x", "commands": [""]}]},
])
def test_gate_malformed_plans_refused(plan):
    with pytest.raises(ValueError):
        PostExploitMixin().postexp_gate(plan)


def test_step_catalogs_gate_clean_end_to_end():
    """Every catalog step of every arc passes the gate (catalog is
    evidence-only by construction)."""
    mixin = PostExploitMixin()
    for arc in PIN_ARCS:
        out = mixin.postexp_step_catalog(arc)
        gate = mixin.postexp_gate({"steps": out["steps"]})
        assert gate["verdict"] == "allow", (arc, gate["refused"])
        assert gate["checked"] == sum(len(s["commands"])
                                      for s in out["steps"])


def test_module_never_executes():
    module = importlib.import_module("agentic_ai.agents.cyber.postexp")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned