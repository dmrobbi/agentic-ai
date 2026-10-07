"""KA-076 - fleet test harness (OPT-76) contract pins. The harness
(docker/fleet-harness/) is committed DATA: compose + an owner-run driver
script. The suite NEVER executes it - no compose up/down, no script
invocation; state change belongs to the owner behind the gate
KA_FLEET_HARNESS=1 (the driver enforces the same gate). Every test in
this file skips cleanly by default; with the gate raised it pins the
harness contract offline (compose inventory, image tags, profile
posture, script markers) plus planner shapes against the farm aliases
(planner logic only, no network). Collect count grows by 29; the
BASELINE_SUITE_TOTAL pin lives in tests/test_ka_conventions.py
(integration-owned)."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import KALI_TOOLS_DB
from agentic_ai.agents.cyber.kali_v2 import ENHANCED_KALI_TOOLS_DB
from agentic_ai.agents.cyber.web_pentest import WebPentestMixin, wp_scrub_target
from agentic_ai.agents.cyber.xss_exploit import XssMixin

REPO = Path(__file__).resolve().parents[2]
HARNESS_DIR = REPO / "docker" / "fleet-harness"
COMPOSE_PATH = HARNESS_DIR / "docker-compose.fleet-lab.yml"
DRIVER_PATH = HARNESS_DIR / "harness.sh"
README_PATH = HARNESS_DIR / "README.md"
LAB_TARGETS_COMPOSE = REPO / "docker" / "lab-targets" / "docker-compose.yml"

HARNESS_ON = os.environ.get("KA_FLEET_HARNESS") == "1"

fleet_harness = pytest.mark.skipif(
    not HARNESS_ON, reason="fleet harness is owner-gated: set KA_FLEET_HARNESS=1")

# --- pinned contract constants (the drift alarms) ---------------------------

PROFILES = {"fleet-farm", "fleet-soc"}

FARM_SERVICES = {"farm-httpd", "farm-solr", "farm-wp-old",
                 "farm-wp-old-db", "farm-redis", "farm-oob"}
SOC_SERVICES = {"soc-wazuh-manager"}

IMAGES = {
    "farm-httpd": "httpd:2.4.49",
    "farm-solr": "solr:8.2.0",
    "farm-wp-old": "wordpress:5.8.1-apache",
    "farm-wp-old-db": "mariadb:10.6",
    "farm-redis": "redis:5.0.14",
    "farm-oob": "python:3.11-alpine",
    "soc-wazuh-manager": "wazuh/wazuh-manager:4.7.0",
}

FARM_PORTS = {
    "farm-httpd": "8191:80",
    "farm-solr": "8192:8983",
    "farm-wp-old": "8193:80",
    "farm-redis": "8194:6379",
}
FARM_NO_PORT_SERVICES = {"farm-oob", "farm-wp-old-db"}

FARM_ALIASES = {
    "farm-httpd": ["farm-httpd.fleet.example"],
    "farm-solr": ["farm-solr.fleet.example"],
    "farm-wp-old": ["farm-wp-old.fleet.example"],
    "farm-wp-old-db": ["farm-wp-old-db.fleet.example"],
    "farm-redis": ["farm-redis.fleet.example"],
    "farm-oob": ["oob.fleet.example"],
    "soc-wazuh-manager": ["wazuh-manager.fleet.example"],
}

FARM_HTTPD_URL = "http://farm-httpd.fleet.example:8191"
FARM_WP_OLD_URL = "http://farm-wp-old.fleet.example:8193"

DRIVER_SUBCOMMANDS = {"help", "status", "up", "down", "reset", "run", "evidence"}

# the documented-infra binary floor the farm plans may emit (mirrors the
# house no-phantom discipline; DB rows are united in at call time)
KNOWN_INFRA_BINARIES = {"python3", "curl", "openssl", "nginx", "whois",
                        "dig", "wafw00f", "arjun", "interactsh-client"}


def _compose():
    import yaml
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def _services():
    return _compose()["services"]


def _driver_text():
    return DRIVER_PATH.read_text(encoding="utf-8")


def _parse_ps_json(stdout):
    """docker compose ps --format json: JSONL on older compose, a JSON
    array on newer - parse both, return a list of row dicts."""
    txt = (stdout or "").strip()
    if not txt:
        return []
    try:
        obj = json.loads(txt)
        if isinstance(obj, dict):
            return [obj]
        if isinstance(obj, list):
            return [row for row in obj if isinstance(row, dict)]
    except ValueError:
        pass
    return [json.loads(ln) for ln in txt.splitlines() if ln.strip()]


def _compose_ps(profiles):
    """Read-only compose ps (never state-changing). Returns rows or None
    when docker/compose is unavailable from the caller."""
    cmd = ["docker", "compose", "-f", str(COMPOSE_PATH)]
    for prof in profiles:
        cmd += ["--profile", prof]
    cmd += ["ps", "--format", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        return None
    return _parse_ps_json(proc.stdout)


# --- compose contract (offline pins; no docker execution) -------------------


@fleet_harness
def test_compose_file_parses_offline():
    """The compose is valid YAML data with the harness project name."""
    compose = _compose()
    assert compose.get("name") == "fleet-harness"
    assert set(compose["services"]) == FARM_SERVICES | SOC_SERVICES


@fleet_harness
def test_bare_up_starts_nothing():
    """Deny-by-default posture: every service belongs to an opt-in
    profile; a bare `docker compose -f <this> up` starts nothing."""
    unprofiled = [s for s, body in _services().items()
                  if not body.get("profiles")]
    assert not unprofiled, unprofiled


@fleet_harness
def test_profile_allowlist_pinned():
    observed = {prof for body in _services().values()
                for prof in body["profiles"]}
    assert observed == PROFILES


@fleet_harness
def test_farm_inventory_pinned():
    observed = {s for s, body in _services().items()
                if "fleet-farm" in body["profiles"]}
    assert observed == FARM_SERVICES


@fleet_harness
def test_soc_inventory_pinned():
    observed = {s for s, body in _services().items()
                if "fleet-soc" in body["profiles"]}
    assert observed == SOC_SERVICES


@fleet_harness
def test_farm_host_ports_pinned():
    """8191-8194 pinned exactly (drift alarm); the catcher and the WP db
    publish no host ports."""
    services = _services()
    for name, port in FARM_PORTS.items():
        assert services[name].get("ports") == [port], name
    assert set(FARM_PORTS) | FARM_NO_PORT_SERVICES == FARM_SERVICES
    for name in FARM_NO_PORT_SERVICES:
        assert not (services[name].get("ports") or []), name


@fleet_harness
def test_farm_ports_disjoint_from_lab_targets():
    """Ports 8181-8183 belong to KA-009; the harness never collides."""
    import yaml
    lab = yaml.safe_load(LAB_TARGETS_COMPOSE.read_text(encoding="utf-8"))
    lab_ports = {p.split(":")[0] for body in lab["services"].values()
                 for p in (body.get("ports") or [])}
    assert lab_ports == {"8181", "8182", "8183"}
    harness_ports = {p.split(":")[0] for p in FARM_PORTS.values()}
    assert harness_ports & lab_ports == set()


@fleet_harness
def test_soc_sidecars_publish_no_host_ports():
    for name in SOC_SERVICES:
        assert not (_services()[name].get("ports") or []), name


@fleet_harness
def test_every_service_joins_shared_lab_net():
    """The whole farm + SOC slice shares the lab network plane; nothing
    runs off the documented plane."""
    for name, body in _services().items():
        assert "lab-net" in body["networks"], name


@fleet_harness
def test_farm_aliases_pinned():
    observed = {name: body["networks"]["lab-net"]["aliases"]
                for name, body in _services().items()}
    assert observed == FARM_ALIASES


@fleet_harness
def test_image_tags_pinned():
    """Every image:tag is exact - the drift alarm (verified live on
    Docker Hub 2026-10-06; bump compose + this pin in the same task)."""
    services = _services()
    for name, image in IMAGES.items():
        assert services[name]["image"] == image, name


@fleet_harness
def test_farm_wp_old_db_waits_healthy():
    """The house health-gated dep shape (mariadb healthcheck.sh), reused
    for the legacy WP pair."""
    services = _services()
    wp = services["farm-wp-old"]
    assert wp["depends_on"]["farm-wp-old-db"]["condition"] == "service_healthy"
    assert services["farm-wp-old-db"]["healthcheck"]["test"] == [
        "CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]


@fleet_harness
def test_wazuh_indexer_documented_not_deployed():
    """The indexer tie-in stays pinned as documented-absent (comment
    block; a real service must not appear here until KA-078 lands it)."""
    raw = COMPOSE_PATH.read_text(encoding="utf-8")
    assert "wazuh-indexer" not in _services()
    assert "soc-wazuh-indexer" in raw
    assert "KA-078" in raw


# --- driver-script contract (bash -n + marker pins; never executed) ---------


@fleet_harness
def test_driver_script_parses_bash_n():
    """bash -n parses the driver without executing ANY of it."""
    proc = subprocess.run(["bash", "-n", str(DRIVER_PATH)],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr


@fleet_harness
def test_driver_requires_owner_gate():
    text = _driver_text()
    assert "KA_FLEET_HARNESS" in text
    assert "KA_LAB_BATTERY=1" in text  # the lab run shapes both gates


@fleet_harness
def test_driver_subcommand_surface_pinned():
    text = _driver_text()
    for cmd in DRIVER_SUBCOMMANDS:
        assert f"cmd_{cmd}()" in text, cmd


@fleet_harness
def test_files_carry_lab_boundary_documentation():
    for path in (COMPOSE_PATH, DRIVER_PATH, README_PATH):
        assert "LAB BOUNDARY" in path.read_text(encoding="utf-8"), path.name


@fleet_harness
def test_driver_has_no_curl_pipe_or_eval():
    """The driver never pipes remote content into a shell and never
    eval: script-level marker discipline (mirrors the planner ban)."""
    text = _driver_text()
    assert "eval " not in text
    assert "curl" not in text
    assert "| bash" not in text
    assert "| sh " not in text


# --- planner shapes against the farm (logic only; no network) ---------------


@fleet_harness
@pytest.mark.parametrize("bad", [
    "farm-httpd.fleet.example; curl http://x.fleet.example",
    "farm-wp-old$(touch /tmp/ka-lab)",
    "../farm-httpd",
    "farm httpd.fleet.example",
    "farm-redis|nc -e",
])
def test_scrub_rejects_hostile_farm_targets(bad):
    """The shared scrub helper rejects every hostile farm-shaped input."""
    with pytest.raises(ValueError):
        wp_scrub_target(bad)


@fleet_harness
def test_plan_web_pentest_farm_httpd_parity():
    out = WebPentestMixin().plan_web_pentest(FARM_HTTPD_URL)
    dump = json.dumps(out)
    assert "farm-httpd.fleet.example" in dump
    assert "8191" in dump


@fleet_harness
def test_plan_web_pentest_farm_wp_old_parity():
    out = WebPentestMixin().plan_web_pentest(FARM_WP_OLD_URL)
    dump = json.dumps(out)
    assert "farm-wp-old.fleet.example" in dump
    assert "8193" in dump


@fleet_harness
def test_plan_xss_exploit_farm_httpd_parity():
    out = XssMixin().plan_xss_exploit(FARM_HTTPD_URL)
    dump = json.dumps(out)
    assert "farm-httpd.fleet.example" in dump
    assert "8191" in dump


@fleet_harness
def test_farm_plans_have_no_phantom_commands():
    """No-phantom floor for the farm-target plans: every argv[0] is a
    known binary (DB rows + the documented infra set). Planner logic
    only - nothing here runs."""
    results = []
    for plan in (WebPentestMixin().plan_web_pentest(FARM_HTTPD_URL),
                 WebPentestMixin().plan_web_pentest(FARM_WP_OLD_URL),
                 XssMixin().plan_xss_exploit(FARM_HTTPD_URL),
                 XssMixin().plan_xss_exploit(FARM_WP_OLD_URL)):
        for phase in plan.get("phases", []):
            for cmd in phase.get("sample_commands", []):
                if not cmd.startswith("# "):
                    results.append(cmd)
    assert results, "the planners emitted nothing for the farm targets"
    known = ({t.command for t in KALI_TOOLS_DB.values()}
             | {t.command for t in ENHANCED_KALI_TOOLS_DB.values()}
             | KNOWN_INFRA_BINARIES)
    phantoms = [cmd for cmd in results
                if shlex.split(cmd)[0] not in known]
    assert not phantoms, phantoms[:5]


# --- up-state checks (read-only compose ps; skip when not up) ---------------


@fleet_harness
def test_harness_farm_up_when_gate_raised():
    """With the gate raised the farm is expected up (the harness's own
    `run lab` guarantees it); farm-down surfaces as a SKIP pointing at
    the fix, never as a suite failure anywhere."""
    rows = _compose_ps(["fleet-farm"])
    if rows is None:
        pytest.skip("docker compose ps unavailable on this caller")
    running = {row.get("Service") for row in rows
               if "running" in (row.get("State", "") or "")}
    if not running:
        pytest.skip("farm not up: run docker/fleet-harness/harness.sh up farm"
                    " (owner-gated)")
    assert FARM_SERVICES <= running


@fleet_harness
def test_soc_manager_up_when_soc_profile_raised():
    rows = _compose_ps(["fleet-soc"])
    if rows is None:
        pytest.skip("docker compose ps unavailable on this caller")
    running = {row.get("Service") for row in rows
               if "running" in (row.get("State", "") or "")}
    if not running:
        pytest.skip("soc profile not started (owner choice): harness.sh up soc")
    assert SOC_SERVICES <= running
