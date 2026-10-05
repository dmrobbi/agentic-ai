"""KA-009 - lab planner-parity battery. The OFFLINE half (the
no-phantom-cmd universe check + the compose declarations) runs
everywhere; the two LIVE lab tests run only when KA_LAB_BATTERY=1 (the
docker targets up) and skip cleanly otherwise. No network beyond the
lab's own containers; no unvetted binaries planned."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import (
    AuthorizationLevel,
    KALI_TOOLS_DB,
    KaliAgent,
)
from agentic_ai.agents.cyber.kali_v2 import ENHANCED_KALI_TOOLS_DB
from agentic_ai.agents.cyber.web_pentest import WebPentestMixin
from agentic_ai.agents.cyber.xss_exploit import XssMixin

REPO = Path(__file__).resolve().parents[2]
COMPOSE_PATH = REPO / "docker" / "lab-targets" / "docker-compose.yml"
LAB_BATTERY_ON = os.environ.get("KA_LAB_BATTERY") == "1"

lab_only = pytest.mark.skipif(
    not LAB_BATTERY_ON, reason="lab battery is owner-gated: set KA_LAB_BATTERY=1")

# the documented binaries the planners may emit: the v1 DB's command
# rows (real binaries) + the measured infra/planner set (KA-024's pins)
# the planner recon families also emit: whois/dig/wafw00f (measured)
DOCUMENTED_INFRA = {"python3", "curl", "openssl", "nginx",
                    "interactsh-client", "nginx-proxy:",
                    "whois", "dig", "wafw00f"}

JUICE_TARGET = "http://lab-juice.lab.example:8181"
OOB_HOST = "oob.lab.example"


def _planner_commands(sweep_results):
    """Collect (op, command) pairs from every planner surface."""
    wp = WebPentestMixin()
    try:
        out = wp.plan_web_pentest(JUICE_TARGET)
    except ValueError:
        out = {}
    for phase in out.get("phases", []):
        for cmd in phase.get("sample_commands", []):
            if not cmd.startswith("# "):
                sweep_results.append(("plan_web_pentest", cmd))
    xs = XssMixin()
    try:
        xplan = xs.plan_xss_exploit(JUICE_TARGET)
    except ValueError:
        xplan = {}
    for phase in xplan.get("phases", []):
        for cmd in phase.get("sample_commands", []):
            if not cmd.startswith("# "):
                sweep_results.append(("plan_xss_exploit", cmd))
    try:
        cb = xs.xss_callback_commands(OOB_HOST)
    except ValueError:
        cb = {}
    for step in cb.get("steps", []):
        for cmd in step.get("commands", []):
            if not cmd.startswith("# "):
                sweep_results.append(("xss_callback", cmd))


def test_no_phantom_commands_in_all_planner_outputs():
    """THE BATTERY CORE: every planned command's argv[0] = a known
    binary (the v1 DB's command rows + the documented infra set). No
    phantom binaries planned."""
    results: list = []
    _planner_commands(results)
    assert results, "the planners emitted nothing - dead battery"
    known = ({t.command for t in KALI_TOOLS_DB.values()}
             | {t.command for t in ENHANCED_KALI_TOOLS_DB.values()}
             | DOCUMENTED_INFRA)
    phantom_failures = []
    for op, cmd in results:
        argv0 = shlex.split(cmd)[0]
        if argv0 not in known:
            phantom_failures.append((op, argv0, cmd[:60]))
    assert not phantom_failures, phantom_failures[:5]


def test_compose_targets_are_declared():
    import yaml
    compose = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
    services = set(compose["services"])
    assert {"juice-shop", "dvwa", "dvwa-mysql", "wordpress",
            "wordpress-db"} <= services
    assert compose["services"]["juice-shop"]["ports"] == ["8181:3000"]
    assert compose["services"]["dvwa"]["ports"] == ["8182:80"]
    assert compose["services"]["wordpress"]["ports"] == ["8183:80"]


@lab_only
def test_planners_plan_against_lab_ports():
    wp = WebPentestMixin()
    out = wp.plan_web_pentest(JUICE_TARGET)
    assert "8181" in json.dumps(out)  # the lab port made it into the plan


@lab_only
def test_docker_services_reachable_when_battery_on():
    proc = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_PATH), "ps", "--format", "json"],
        capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        pytest.skip("docker compose ps failed: " + proc.stderr[:120])
    rows = [json.loads(line) for line in
            proc.stdout.splitlines() if line.strip()]
    running = {row.get("Service") for row in rows
               if "running" in (row.get("State", "") or "")}
    assert {"juice-shop", "dvwa", "wordpress"} <= running
