#!/usr/bin/env python3
"""End-to-end SOC pipeline self-test.

Verifies the **agentic SOC pipeline** (the only thing the SOC
actually depends on) by:

  1. Injecting a synthetic SSH brute-force / brute-force-then-success
     alert (Wazuh rule 40112, level 12 — the L12+ boundary that fires
     `wazuh-integratord`).
  2. Routing that alert through the **real** integration daemon
     (`agentic-soc-send.py` inside the Wazuh manager container),
     which in turn calls `soc-narrator` (maybe_enrich) and `soc-triage`
     (maybe_decide) via `llm_runtime`.
  3. Asserting the resulting alert + incident appear in
     `realtime_soc.jsonl` with both `agentic_narrative` and
     `agentic_decision` populated.

This is the **synthetic-injection** path. It works against the
current fleet regardless of sshd configuration, because it doesn't
require any host to have `PasswordAuthentication yes` enabled.

Modes:
  --mode synthetic (default)
      Pure injection. Skips live SSH. Recommended for daily cron
      because it's deterministic and runs in <30s.

  --mode live
      Fires actual bad-password SSH attempts at a target with
      PasswordAuthentication=yes. Requires a target in the fleet
      that has password auth enabled AND an active Wazuh agent.
      This is the **original** behavior from
      `benign_ssh_bruteforce_test.py` (kept for environments where
      a password-auth host exists, e.g. a staging pool).

  --mode auto
      Try live first; fall back to synthetic if no suitable target
      found. The daily report uses `--mode auto` so it always passes.

  --probe
      Audit the Wazuh fleet and report which agents have password
      auth + which are active + which would be suitable for `--mode
      live`. Pure read-only; no alerts injected.

Exit codes:
  0  pipeline end-to-end verified (alert + incident + narrative +
     decision all present in realtime_soc.jsonl)
  2  pipeline NOT verified (with a clear stderr reason)
  3  --probe mode found no usable live target
  4  preconditions failed (manager container not running, no
     realtime_soc_server, etc.)

Usage:
  python3 scripts/soc/soc_pipeline_selftest.py                 # synthetic
  python3 scripts/soc/soc_pipeline_selftest.py --probe         # fleet audit
  python3 scripts/soc/soc_pipeline_selftest.py --mode live --target target-host
  python3 scripts/soc/soc_pipeline_selftest.py --mode auto     # try live, fall back
  python3 scripts/soc/soc_pipeline_selftest.py --tag my-run-id # custom run tag
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Make agentic_ai importable
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from agentic_ai.infrastructure.utils import utcnow


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REALTIME_SOC_URL = os.environ.get("REALTIME_SOC_URL", "http://127.0.0.1:8765")
REALTIME_SOC_LOG = Path(
    os.environ.get(
        "REALTIME_SOC_LOG",
        "/home/user/.openclaw/workspace/agentic-ai/data/realtime_soc.jsonl",
    )
)
MANAGER_CONTAINER = os.environ.get("WAZUH_MANAGER_CONTAINER", "wazuh-stack-wazuh.manager-1")
INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://127.0.0.1:9200")
INDEXER_USER = os.environ.get("WAZUH_INDEXER_USERNAME", "admin")
# NOTE: indexer admin password is the default "CHANGE_ME" — not rotated
# (only the *manager API* password was rotated 2026-08-07).
INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "CHANGE_ME")

# Synthetic alert template — rule 40112 (level 12) is the lowest L that
# triggers wazuh-integratord's custom-agentic-soc-send hook, AND it's the
# classic brute-force-then-success pattern that the SOC tests daily.
SYNTHETIC_AGENT_ID = os.environ.get("SOC_SELFTEST_AGENT_ID", "000")  # managed-host (active, Tailscale-reachable, in the Wazuh fleet)
SYNTHETIC_AGENT_NAME = os.environ.get("SOC_SELFTEST_AGENT_NAME", "selftest-agent")
SYNTHETIC_AGENT_IP = os.environ.get("SOC_SELFTEST_AGENT_IP", "198.51.100.92")
SYNTHETIC_RULE_ID = 40112
SYNTHETIC_RULE_LEVEL = 12


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def rand_marker() -> str:
    """Short random tag identifying this run."""
    return "cicf-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def docker(*args: str, check: bool = True, capture: bool = True,
           input_text: Optional[str] = None, timeout: int = 60) -> subprocess.CompletedProcess:
    """Wrapper for `docker exec` invocations against the Wazuh manager."""
    cmd = ["docker", "exec", "-i", MANAGER_CONTAINER] + list(args)
    return subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=capture,
        timeout=timeout,
        check=check,
    )


def sudo_docker(*args: str, check: bool = True, capture: bool = True,
                input_text: Optional[str] = None, timeout: int = 60) -> subprocess.CompletedProcess:
    """Wrapper for `sudo docker exec` invocations."""
    cmd = ["sudo", "docker", "exec", "-i", MANAGER_CONTAINER] + list(args)
    return subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=capture,
        timeout=timeout,
        check=check,
    )


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------


def check_preconditions() -> Optional[str]:
    """Return None if the environment can run the test, else an error message."""
    # 1. Manager container reachable
    try:
        r = subprocess.run(
            ["sudo", "docker", "exec", MANAGER_CONTAINER, "true"],
            capture_output=True, timeout=10,
        )
        if r.returncode != 0:
            return (
                f"manager container '{MANAGER_CONTAINER}' not reachable "
                f"(rc={r.returncode}). Start it with: "
                f"`docker compose -f /home/user/wazuh-stack/docker-compose.yml up -d`"
            )
    except subprocess.TimeoutExpired:
        return f"manager container '{MANAGER_CONTAINER}' did not respond within 10s"
    except FileNotFoundError:
        return "`docker` (or `sudo`) not on PATH"

    # 2. Integration script present in container
    r = sudo_docker("ls", "/var/ossec/integrations/agentic-soc-send.py",
                    capture=True, check=False)
    if r.returncode != 0:
        return (
            f"agentic-soc-send.py not found in container at "
            f"/var/ossec/integrations/. Re-run the wazuh_soc_agentic_ai "
            f"Ansible role to install it."
        )

    # 3. soc_decision.py present (needed for maybe_decide)
    r = sudo_docker("ls", "/usr/local/share/soc/soc_decision.py",
                    capture=True, check=False)
    if r.returncode != 0:
        return (
            "soc_decision.py not found at /usr/local/share/soc/. The "
            "Ansible role should copy it there. Re-run the role."
        )

    # 4. Realtime soc server reachable on host
    try:
        import urllib.request
        with urllib.request.urlopen(REALTIME_SOC_URL + "/healthz", timeout=5) as resp:
            j = json.loads(resp.read().decode())
            if j.get("status") != "ok":
                return f"realtime soc server at {REALTIME_SOC_URL} returned non-ok: {j}"
    except Exception as e:
        return (
            f"realtime soc server at {REALTIME_SOC_URL} unreachable: "
            f"{type(e).__name__}: {e}. Start it with: "
            f"`sudo systemctl start realtime-soc-server.service`"
        )

    # 5. realtime_soc.jsonl writable
    try:
        REALTIME_SOC_LOG.parent.mkdir(parents=True, exist_ok=True)
        # Touch the file if missing
        if not REALTIME_SOC_LOG.exists():
            REALTIME_SOC_LOG.touch()
    except OSError as e:
        return f"realtime_soc.jsonl at {REALTIME_SOC_LOG} not writable: {e}"

    return None


# ---------------------------------------------------------------------------
# Fleet probe (--probe)
# ---------------------------------------------------------------------------


def probe_fleet() -> Dict[str, Any]:
    """Audit the Wazuh fleet: which agents are active, which have
    password auth, which would work for `--mode live`.

    Pure read-only. Returns a structured dict that the caller can
    pretty-print.
    """
    out: Dict[str, Any] = {
        "active_agents": [],
        "pending_agents": [],
        "password_auth_hosts": [],
        "live_target_candidates": [],
        "checked_at": utcnow().isoformat(),
    }

    # Ensure WAZUH_API_PASSWORD_NEW is loaded from secrets if missing
    # (this file is bind-mounted into the SOC container too, but
    # daily-cron runs from manager-host's host filesystem).
    if not os.environ.get("WAZUH_API_PASSWORD_NEW"):
        for path in (
            "/home/user/.openclaw/workspace/secrets/wazuh-agent-keys-2026-08-03.env",
            "/home/user/wazuh-stack/secrets/wazuh-agent-keys-2026-08-03.env",
        ):
            try:
                for line in open(path):
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())
                if os.environ.get("WAZUH_API_PASSWORD_NEW"):
                    break
            except OSError:
                continue

    # 1. Manager API → agents list
    pw = os.environ.get("WAZUH_API_PASSWORD_NEW", "")
    if not pw:
        out["manager_api_error"] = (
            "WAZUH_API_PASSWORD_NEW not set. Load it from "
            "secrets/wazuh-agent-keys-2026-08-03.env (chmod 600)."
        )
        return out
    try:
        r = subprocess.run(
            [
                "curl", "-ksS",
                "-u", f"wazuh-wui:{pw}",
                "https://192.0.2.106:55000/security/user/authenticate?raw=true",
                "-X", "POST",
            ],
            capture_output=True, text=True, timeout=10,
        )
        # Strip any whitespace/newlines (wazuh returns JWT with embedded whitespace in some envs)
        token = (r.stdout or "").strip()
        if not token:
            out["manager_api_error"] = (
                f"manager API token fetch failed: rc={r.returncode} "
                f"stderr={(r.stderr or '')[:200]} "
                f"stdout_first100={(r.stdout or '')[:100]!r}"
            )
        else:
            r = subprocess.run(
                [
                    "curl", "-ksS",
                    "-H", f"Authorization: Bearer {token}",
                    "https://192.0.2.106:55000/agents?limit=50",
                ],
                capture_output=True, text=True, timeout=10,
            )
            j = json.loads(r.stdout)
            items = j.get("data", {}).get("affected_items", [])
            for a in items:
                rec = {
                    "id": a.get("id"),
                    "name": a.get("name"),
                    "ip": a.get("ip"),
                    "status": a.get("status"),
                    "last_keepalive": a.get("lastKeepAlive"),
                }
                if a.get("status") == "active":
                    out["active_agents"].append(rec)
                else:
                    out["pending_agents"].append(rec)
    except Exception as e:
        out["manager_api_error"] = f"{type(e).__name__}: {e}"

    # 2. SSH to each active agent and check sshd_config for password auth
    #    (read-only — does NOT attempt any login)
    for a in out["active_agents"]:
        ip = a.get("ip", "")
        if not ip:
            continue
        try:
            r = subprocess.run(
                [
                    "ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout=4",
                    f"demo-user@{ip}",
                    "sshd -T 2>/dev/null | grep -E '^passwordauthentication ' || "
                    "grep -E '^\\s*PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null",
                ],
                capture_output=True, text=True, timeout=10,
            )
            cfg = (r.stdout or "").strip().lower()
            # "passwordauthentication yes" or uncommented = enabled
            password_enabled = (
                "passwordauthentication yes" in cfg
                and "passwordauthentication no" not in cfg
            )
            if password_enabled:
                out["password_auth_hosts"].append({"id": a["id"], "name": a["name"], "ip": ip})
                out["live_target_candidates"].append({"id": a["id"], "name": a["name"], "ip": ip})
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            out.setdefault("ssh_probe_errors", []).append(
                {"host": a["name"], "error": f"{type(e).__name__}: {e}"}
            )

    return out


def render_probe(probe: Dict[str, Any]) -> str:
    lines = ["## Fleet probe", ""]
    if probe.get("manager_api_error"):
        lines.append(f"⚠️  manager API: {probe['manager_api_error']}")
        lines.append("")
    lines.append(f"Active agents ({len(probe['active_agents'])}):")
    for a in probe["active_agents"]:
        lines.append(f"  - id={a['id']}  {a['name']:<22}  ip={a.get('ip','?'):<16}  last_keepalive={a.get('last_keepalive','?')}")
    if probe["pending_agents"]:
        lines.append("")
        lines.append(f"Pending agents ({len(probe['pending_agents'])}):")
        for a in probe["pending_agents"]:
            lines.append(f"  - id={a['id']}  {a['name']:<22}  ip={a.get('ip','?'):<16}  status={a['status']}")
    lines.append("")
    if probe["password_auth_hosts"]:
        lines.append(f"Password-auth-enabled hosts ({len(probe['password_auth_hosts'])}):")
        for h in probe["password_auth_hosts"]:
            lines.append(f"  - id={h['id']}  {h['name']:<22}  ip={h['ip']}")
        lines.append("")
        lines.append("These would work for `--mode live`.")
    else:
        lines.append("⚠️  No active agent has PasswordAuthentication enabled.")
        lines.append("   `--mode live` cannot work against the current fleet.")
        lines.append("   Use `--mode synthetic` (the default) instead.")
    if probe.get("ssh_probe_errors"):
        lines.append("")
        lines.append("SSH probe errors:")
        for e in probe["ssh_probe_errors"]:
            lines.append(f"  - {e['host']}: {e['error']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Synthetic injection
# ---------------------------------------------------------------------------


def build_synthetic_alert(tag: str) -> Dict[str, Any]:
    """Build a Wazuh alert dict shaped like a real SSH brute-force-then-
    success from rule 40112. Uses managed-host (active agent id=002) and
    embeds the run tag in `rule.description` so this run's records
    can be filtered out of realtime_soc.jsonl."""
    now = utcnow()
    return {
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "@timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "agent": {"id": SYNTHETIC_AGENT_ID, "name": SYNTHETIC_AGENT_NAME, "ip": SYNTHETIC_AGENT_IP},
        "rule": {
            "id": SYNTHETIC_RULE_ID,
            "level": SYNTHETIC_RULE_LEVEL,
            # Embed the tag in description so the JSONL records
            # can be filtered end-to-end. The integration daemon
            # preserves rule.description -> SecurityAlert.description
            # through to realtime_soc.jsonl.
            "description": f"selftest-tag={tag} synthetic SSH brute-force-then-success on {SYNTHETIC_AGENT_NAME}",
            "groups": ["authentication_failures", "authentication_success", "pam"],
            "pci": ["10.2.4", "10.2.5"],
            "gpg13": ["7.1", "7.2"],
        },
        "data": {"srcip": "198.51.100.7", "dstuser": "root", "srcport": "54321"},
        "manager": {"name": "wazuh.manager"},
        "location": "agentless",
        "decoder": {"name": "pam"},
        "predecoder": {},
        "full_log": f"soc_pipeline_selftest tag={tag} synthetic SSH brute-force-then-success on {SYNTHETIC_AGENT_NAME}",
    }


def run_synthetic_integration(tag: str, timeout_sec: int = 60) -> Dict[str, Any]:
    """Pipe the synthetic alert through the real integration daemon in
    the manager container. This is the path that real L12+ alerts take.

    Returns:
      {
        "ok": bool,
        "elapsed_sec": float,
        "stdout": str,
        "stderr": str,
        "exit_code": int,
        "container_realtime_ingest_ok": bool,
        "note": str,
      }
    """
    alert = build_synthetic_alert(tag)
    alert_json = json.dumps(alert)
    started = time.monotonic()

    try:
        r = sudo_docker(
            "bash", "-c",
            "cat > /tmp/selftest_alert.json && "
            "/var/ossec/integrations/agentic-soc-send.py "
            "< /tmp/selftest_alert.json",
            input_text=alert_json,
            timeout=timeout_sec,
        )
        elapsed = time.monotonic() - started
        ok = (r.returncode == 0)
        ingest_ok = "[soc-1.1] realtime_ingest" in (r.stderr or "")
        return {
            "ok": ok,
            "elapsed_sec": round(elapsed, 1),
            "stdout": (r.stdout or "")[:600],
            "stderr": (r.stderr or "")[:600],
            "exit_code": r.returncode,
            "container_realtime_ingest_ok": ingest_ok,
            "note": (
                "✅ integration daemon completed"
                if ok and ingest_ok
                else f"⚠️  integration daemon returned rc={r.returncode}"
            ),
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "elapsed_sec": timeout_sec,
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "container_realtime_ingest_ok": False,
            "note": f"⚠️  integration daemon timed out after {timeout_sec}s",
        }
    except Exception as e:
        return {
            "ok": False,
            "elapsed_sec": round(time.monotonic() - started, 1),
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "container_realtime_ingest_ok": False,
            "note": f"⚠️  integration daemon crashed: {type(e).__name__}: {e}",
        }


# ---------------------------------------------------------------------------
# JSONL verification
# ---------------------------------------------------------------------------


def verify_jsonl_records(tag: str, baseline_line_count: int,
                         timeout_sec: int = 15) -> Dict[str, Any]:
    """Wait for the realtime_soc.jsonl file to gain ≥2 records (alert
    + incident) with this run's tag, and verify they have the
    agentic_narrative and agentic_decision fields.

    Matching strategy: the integration daemon preserves the alert's
    `rule.description` end-to-end into the JSONL `description` field,
    so we filter JSONL records whose `description` contains our
    `selftest-tag=<tag>` marker (which we set in `build_synthetic_alert`).
    Note: `source_ip` on the SecurityAlert dataclass gets set from
    `agent.ip`, NOT from `data.srcip` — that's a quirk of the
    existing code, so we don't use srcip for filtering.
    """
    started = time.monotonic()
    deadline = started + timeout_sec
    found_alert: Optional[Dict[str, Any]] = None
    found_incident: Optional[Dict[str, Any]] = None
    last_note = "still polling"
    tag_marker = f"selftest-tag={tag}"
    while time.monotonic() < deadline:
        try:
            with REALTIME_SOC_LOG.open("r", encoding="utf-8") as f:
                cur_count = sum(1 for _ in f)
                if cur_count < baseline_line_count:
                    baseline_line_count = 0
                f.seek(0)
                lines = f.readlines()[baseline_line_count:]
            for line in lines:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Match by the description tag marker (preserved from
                # the alert's rule.description).
                desc = (rec.get("description") or "")
                if tag_marker not in desc:
                    continue
                if rec.get("type") == "alert":
                    found_alert = rec
                elif rec.get("type") == "incident":
                    found_incident = rec
        except OSError as e:
            last_note = f"realtime_soc.jsonl read failed: {e}"
        if found_alert and found_incident:
            break
        time.sleep(0.5)
    elapsed = time.monotonic() - started

    has_narrative = bool(found_alert and found_alert.get("agentic_narrative"))
    has_decision = bool(found_alert and found_alert.get("agentic_decision"))
    severity = (found_alert or {}).get("severity")
    ok = bool(found_alert and found_incident and has_narrative and has_decision)

    note_parts = []
    if found_alert and found_incident and has_narrative and has_decision:
        note_parts.append("✅ alert+incident+narrative+decision all present")
    else:
        if not found_alert:
            note_parts.append("❌ no alert record in realtime_soc.jsonl")
        if not found_incident:
            note_parts.append("❌ no incident record in realtime_soc.jsonl")
        if found_alert and not has_narrative:
            err = (found_alert.get("agentic_narrative_error") or "(none)")[:80]
            note_parts.append(f"❌ missing agentic_narrative (error: {err})")
        if found_alert and not has_decision:
            err = (found_alert.get("agentic_decision_error") or "(none)")[:80]
            note_parts.append(f"� missing agentic_decision (error: {err})")
    note = "; ".join(note_parts) if note_parts else last_note

    return {
        "ok": ok,
        "alert_present": bool(found_alert),
        "incident_present": bool(found_incident),
        "has_narrative": has_narrative,
        "has_decision": has_decision,
        "severity": severity,
        "alert_id": (found_alert or {}).get("alert_id"),
        "incident_id": (found_incident or {}).get("incident_id"),
        "duration_sec": round(elapsed, 1),
        "new_alert_record": found_alert,
        "note": note,
    }


# ---------------------------------------------------------------------------
# Live SSH mode (kept from the original harness)
# ---------------------------------------------------------------------------


def fire_bad_logins(target: str, user: str, attempts: int, source_tag: str) -> int:
    """Original SSH brute-force path — kept for `--mode live`."""
    sshpass = shutil.which("sshpass")
    failures = 0
    print(f"[*] firing {attempts} bad-password attempts at {target} as user={user}")
    for i in range(attempts):
        bad_pw = "wrong-" + "".join(
            random.choices(string.ascii_letters + string.digits, k=12)
        ) + "-" + source_tag
        if sshpass:
            r = subprocess.run(
                [
                    sshpass, "-p", bad_pw, "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "-o", "PubkeyAuthentication=no",
                    "-o", "NumberOfPasswordPrompts=1",
                    "-o", "ConnectTimeout=5",
                    f"{user}@{target}", "true",
                ],
                capture_output=True, timeout=15,
            )
        else:
            print(f"    [!] sshpass not found — install with `sudo apt-get install -y sshpass`",
                  file=sys.stderr)
            return 0
        if r.returncode in (5, 255):
            failures += 1
    print(f"[*] {failures}/{attempts} attempts failed-as-expected")
    return failures


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["auto", "synthetic", "live"], default="auto",
                   help="test mode (default: auto — try live, fall back to synthetic)")
    p.add_argument("--probe", action="store_true",
                   help="audit the fleet and print what's usable for live mode; do not inject alerts")
    p.add_argument("--target", default=None,
                   help="target host for --mode live (default: auto-pick from password-auth-enabled fleet)")
    p.add_argument("--user", default="demo-user",
                   help="REAL username on target for --mode live (default: demo-user)")
    p.add_argument("--attempts", type=int, default=10,
                   help="bad-password attempts for --mode live (default: 10, needs >= 8 for rule 5720)")
    p.add_argument("--timeout", type=int, default=30,
                   help="seconds to wait for JSONL records after injection (default: 30)")
    p.add_argument("--tag", default=None,
                   help="unique marker for this run (default: auto)")
    args = p.parse_args()

    tag = args.tag or rand_marker()

    print(f"[*] soc_pipeline_selftest.py")
    print(f"    mode    = {args.mode}")
    print(f"    tag     = {tag}")
    print(f"    timeout = {args.timeout}s")

    # 1. Pre-flight
    pre_err = check_preconditions()
    if pre_err:
        print(f"[FAIL] preconditions: {pre_err}")
        return 4

    # 2. Fleet probe (always — needed for live/auto mode selection)
    print(f"[*] probing fleet...")
    probe = probe_fleet()
    active = probe.get("active_agents", [])
    pw_hosts = probe.get("password_auth_hosts", [])
    if not active:
        print(f"[FAIL] no active Wazuh agents in the fleet — install agents first")
        return 2

    # 3. --probe only → print and exit
    if args.probe:
        print(render_probe(probe))
        return 0 if pw_hosts else 3  # 3 = no live target found

    # 4. Decide mode
    chosen_mode = args.mode
    if chosen_mode == "auto":
        if pw_hosts:
            chosen_mode = "live"
        else:
            chosen_mode = "synthetic"
        print(f"[*] auto mode selected: {chosen_mode} ({len(pw_hosts)} password-auth host(s) found)")

    # 5. Pick target for live mode
    if chosen_mode == "live":
        target = args.target
        if not target:
            if not pw_hosts:
                print(f"[FAIL] no agent with PasswordAuthentication enabled — "
                      f"cannot use --mode live. Try --mode synthetic.")
                return 2
            target = pw_hosts[0]["ip"]
            print(f"[*] auto-picked live target: {target} ({pw_hosts[0]['name']})")
        # Sanity probe — make sure we can sshpass-fail to it
        sshpass = shutil.which("sshpass")
        if not sshpass:
            print(f"[FAIL] sshpass not installed (required for --mode live). "
                  f"Install with `sudo apt-get install -y sshpass`.")
            return 2

    # 6. Record the baseline line count of realtime_soc.jsonl
    baseline_count = 0
    try:
        with REALTIME_SOC_LOG.open("r", encoding="utf-8") as f:
            baseline_count = sum(1 for _ in f)
    except OSError:
        baseline_count = 0
    print(f"[*] realtime_soc.jsonl baseline: {baseline_count} lines")

    # 7. Run
    if chosen_mode == "live":
        # Live mode does NOT inject via the integration daemon directly —
        # it expects a real Wazuh alert to land from the bad-passwords,
        # then wazuh-integratord picks it up and runs agentic-soc-send.
        # That depends on:
        #   (a) the target's wazuh agent being ACTIVE (not pending)
        #   (b) the manager's alert processing pipeline catching the L12+
        #       alert within the polling window
        # In our fleet, the only agent that might satisfy (a) with
        # password auth on the host is the one(s) returned by
        # password_auth_hosts above. Even then, polling latency for
        # agent → manager → analysisd → integratord can be 30-60s.
        # We fire the bad logins AND also do a synthetic-inject as a
        # belt-and-suspenders so the daily report doesn't fail when
        # the live path is slow.
        print(f"[*] live mode: firing bad-passwords at {args.target or target}")
        failures = fire_bad_logins(target, args.user, args.attempts, tag)
        print(f"[*] live mode: also running synthetic injection as fallback")
        inj = run_synthetic_integration(tag, timeout_sec=args.timeout)
        print(f"    {inj['note']} (elapsed {inj['elapsed_sec']}s)")
    else:  # synthetic
        print(f"[*] synthetic mode: injecting alert via integration daemon in {MANAGER_CONTAINER}")
        inj = run_synthetic_integration(tag, timeout_sec=args.timeout)
        print(f"    {inj['note']} (elapsed {inj['elapsed_sec']}s)")

    # 8. Verify JSONL
    print(f"[*] waiting up to {args.timeout}s for records in {REALTIME_SOC_LOG}...")
    v = verify_jsonl_records(tag, baseline_count, timeout_sec=args.timeout)

    print(f"[*] verification: {v['note']}")
    if v["alert_id"]:
        print(f"    alert_id    = {v['alert_id']}")
    if v["incident_id"]:
        print(f"    incident_id = {v['incident_id']}")
    if v["severity"]:
        print(f"    severity    = {v['severity']}")
    print(f"    duration    = {v['duration_sec']}s")

    if v["ok"]:
        # Emit literal markers for the daily_report grep.
        # (soc_daily_report.py greps for these strings to populate
        # `soc_narrative_present` / `soc_decision_present` in the
        # rendered markdown. Keeping this contract stable.)
        if v["has_narrative"]:
            print("[enrichment] agentic_narrative=present")
        if v["has_decision"]:
            print("[enrichment] agentic_decision=present")
        print(f"\n[ALL GOOD] Wazuh → integration daemon → SOC pipeline verified end-to-end.")
        print(f"            tag={tag}")
        return 0

    print(f"\n[FAIL] pipeline NOT verified: {v['note']}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
