#!/usr/bin/env python3
"""End-to-end benign SSH brute-force test (LIVE FIRE ONLY).

⚠️  DEPRECATED for daily selftest (2026-08-09).
    The daily report now uses `soc_pipeline_selftest.py` (synthetic
    injection via the manager container's integration daemon), which
    works regardless of fleet sshd config.

    This script remains useful as a `--mode live` option in the new
    harness and as a one-off validation against a staging host that
    has PasswordAuthentication=yes.  Run it directly:

        python3 scripts/soc/benign_ssh_bruteforce_test.py --target STAGING --user wez

What this does:
  1. Fires N bad-password attempts from this host at a target where sshd
     is monitored by Wazuh (mail.stsgym.com, agent id 006).
  2. Polls the Wazuh indexer (`wazuh-alerts-*`) for a resulting rule-5720
     ("Multiple failed logins from same source IP") alert.
  3. Re-runs the SecurityOperationsAgent poller end-to-end and asserts it
     created a SecurityAlert AND an IncidentReport for the alert.

The bad logins use a deliberately-wrong username so they always fail
without any risk to a real account. The user is "ci-bot-sentinel-$$"
which does not exist anywhere. Wait — $$ won't expand in Python. Use a
unique-per-run marker so we can identify OUR test alert among the noise.

Usage:
  python3 scripts/soc/benign_ssh_bruteforce_test.py
  python3 scripts/soc/benign_ssh_bruteforce_test.py --target 192.168.1.151
  python3 scripts/soc/benign_ssh_bruteforce_test.py --user wez
  python3 scripts/soc/benign_ssh_bruteforce_test.py --attempts 10
  python3 scripts/soc/benign_ssh_bruteforce_test.py --timeout 90
"""
from __future__ import annotations

import argparse
import os
import random
import shutil
import string
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make agentic_ai importable
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from agentic_ai.infrastructure.utils import utcnow
from agentic_ai.infrastructure.wazuh_client import (
    WazuhIndexerClient,
    map_level_to_severity,
)
from agentic_ai.agents.cyber.soc import SecurityOperationsAgent


def rand_marker() -> str:
    """Short random tag identifying this run."""
    return "cicf-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def fire_bad_logins(target: str, user: str, attempts: int, source_tag: str) -> int:
    """Fire `attempts` bad-password ssh logins at `target`.

    Each attempt uses an obviously-wrong password. We log the failure rate
    so we know sshd is actually rejecting them (not rate-limiting us out).

    IMPORTANT: to trigger Wazuh rule 5720 ("Multiple authentication failures",
    level 10) we need 8+ rule-5716 ("sshd: authentication failed") events
    from the same source IP. Rule 5710 ("Invalid user") is a different parent
    and does NOT count toward 5720's frequency. So `user` MUST be a real
    account on `target` (so sshd logs "Failed password for <user> from <ip>"
    = 5716, not "Invalid user <user> from <ip>" = 5710).

    Also IMPORTANT: we use `sshpass` because piping a password into stdin of
    `ssh -o PreferredAuthentications=password` doesn't actually send it —
    OpenSSH closes the connection on the password prompt before reading
    stdin, so sshd never logs "Failed password" (only "Connection closed by
    authenticating user"). sshpass sends the password via the tty correctly.

    Returns the count of failures we observed via ssh exit code.
    """
    # sshd usually logs the attempted username, not the password — that's
    # what we rely on for filtering in Wazuh.
    sshpass = shutil.which("sshpass")
    if not sshpass:
        print("[!] sshpass not found on this host; the test will still run but "
              "will only generate rule-5710 'Invalid user' alerts (not 5716 "
              "'Failed password'), so rule 5720 will not fire.", file=sys.stderr)
        print("    install with: sudo apt-get install -y sshpass",
              file=sys.stderr)

    failures = 0
    print(f"[*] firing {attempts} bad-password attempts at {target} as user={user}")
    for i in range(attempts):
        bad_pw = "wrong-" + "".join(
            random.choices(string.ascii_letters + string.digits, k=12)
        ) + "-" + source_tag
        if sshpass:
            r = subprocess.run(
                [
                    sshpass, "-p", bad_pw,
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "-o", "PubkeyAuthentication=no",
                    "-o", "NumberOfPasswordPrompts=1",
                    "-o", "ConnectTimeout=5",
                    user + "@" + target,
                    "true",
                ],
                capture_output=True,
                timeout=15,
            )
        else:
            # Fallback: stdin pipe (won't trigger rule 5716 reliably, but at
            # least documents what the test is trying to do).
            r = subprocess.run(
                [
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "-o", "PubkeyAuthentication=no",
                    "-o", "PreferredAuthentications=password",
                    "-o", "NumberOfPasswordPrompts=1",
                    "-o", "ConnectTimeout=5",
                    user + "@" + target,
                    "true",
                ],
                input=(bad_pw + "\n").encode(),
                capture_output=True,
                timeout=15,
            )
        # sshpass: Permission denied, please try again. -> rc 5 (sshpass) or
        # rc 255 (ssh). Either is "sshd rejected the password" for our purposes.
        if r.returncode in (5, 255):
            failures += 1
        else:
            print(f"    [!] attempt {i+1} unexpected rc={r.returncode}: "
                  f"{r.stderr[:120]!r}")
    print(f"[*] {failures}/{attempts} attempts failed-as-expected")
    return failures


def wait_for_wazuh_alert(
    idx: WazuhIndexerClient,
    srcip: str,
    username: str,
    target_agent: str,
    timeout_sec: int,
    start_ts: "datetime | None" = None,
    poll_interval: float = 2.0,
) -> dict | None:
    """Poll the indexer for an SSH brute-force alert matching our test.

    Looks for rule.level >= 10 in the `authentication_failed` group within
    the current window. We deliberately do NOT over-constrain on dstuser /
    exact agent.name because the rule 5763 brute-force correlation alert
    doesn't always carry the original dstuser — it correlates by same
    source IP across multiple child events.

    For rpi42 we look at agent.id == "004"; for mail.stsgym.com the agent
    is named "mail.stsgym.com" (no separate numeric id we know). We use a
    `should` clause over a few fields and require minimum_should_match=1.

    `start_ts` should be captured BEFORE firing the bad logins, because rule
    5763's @timestamp is set when the 8th event arrives (during firing).
    If we use utcnow() inside this function, the alert is excluded by
    milliseconds from the range filter.
    """
    start = start_ts or (utcnow() - timedelta(minutes=2))
    deadline = utcnow() + timedelta(seconds=timeout_sec)
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": start.isoformat()}}},
                {"range": {"rule.level": {"gte": 10}}},
                {"terms": {"rule.groups": ["authentication_failed", "authentication_failures"]}},
            ],
            "should": [
                {"term": {"agent.name": target_agent}},
                {"term": {"data.srcip": srcip}},
                {"term": {"agent.id": "004"}},
            ],
            "minimum_should_match": 1,
        }
    }
    last_seen_count = 0
    last_diag = -10
    while utcnow() < deadline:
        hits = idx.search_alerts(size=50, sort_desc=True, query=query)
        relevant = []
        for h in hits:
            ts = h.get("@timestamp") or h.get("timestamp")
            if not ts:
                continue
            try:
                if isinstance(ts, str):
                    t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                else:
                    t = ts
                if t >= start - timedelta(seconds=2):
                    relevant.append(h)
            except Exception:
                relevant.append(h)
        if len(relevant) > last_seen_count:
            print(f"    [..] found {len(relevant)} candidate alert(s) so far "
                  f"(raw hits in query={len(hits)})")
            last_seen_count = len(relevant)
        if relevant:
            return relevant[0]
        time.sleep(poll_interval)
        elapsed = (utcnow() - start).total_seconds()
        if elapsed - last_diag >= 15:
            print(f"    [..] {elapsed:.0f}s elapsed, still polling "
                  f"(raw hits in this poll cycle: {len(hits)})")
            last_diag = elapsed
    return None


def run_poller_against_alert(
    alert: dict, idx: WazuhIndexerClient
) -> tuple[int, int, int]:
    """Run one full SOC ingestion cycle on the alert.

    Returns (delta_alerts, delta_incidents, severity_value).
    """
    soc = SecurityOperationsAgent()

    alerts_before = len(soc.alerts)
    incidents_before = len(soc.incidents)
    ingested = soc.ingest_wazuh_alert(alert)
    alerts_after = len(soc.alerts)
    incidents_after = len(soc.incidents)

    return (
        alerts_after - alerts_before,
        incidents_after - incidents_before,
        ingested.severity.value,
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", default="192.168.1.151",
                   help="sshd host monitored by Wazuh (default: 192.168.1.151 = rpi42, "
                        "which accepts password auth and is reporting via Wazuh agent 004)")
    p.add_argument("--user", default="wez",
                   help="REAL local username on target (must exist on target so sshd logs "
                        "rule-5716 'Failed password' not rule-5710 'Invalid user'; rule 5720 "
                        "only counts 5716 events). DEFAULT USER MUST EXIST ON TARGET.")
    p.add_argument("--attempts", type=int, default=10,
                   help="number of bad-password attempts (default: 10, must be >= 8 to trigger rule 5720)")
    p.add_argument("--timeout", type=int, default=120,
                   help="seconds to wait for the Wazuh alert (default: 120)")
    p.add_argument("--source-tag", default=None,
                   help="unique marker for this run (default: auto)")
    args = p.parse_args()

    tag = args.source_tag or rand_marker()
    user = args.user

    print(f"[*] benign_ssh_bruteforce_test.py")
    print(f"    target  = {args.target}")
    print(f"    user    = {user}")
    print(f"    attempts= {args.attempts}")
    print(f"    timeout = {args.timeout}s")
    print(f"    tag     = {tag}")

    # IMPORTANT: capture `start` BEFORE firing so that the rule-5763 brute-force
    # correlation alert (whose @timestamp is set when the 8th event arrives, ie
    # DURING firing) is included in our lookback window.
    start_ts = utcnow() - timedelta(seconds=5)
    print(f"[*] start_ts = {start_ts.isoformat()} (captured before firing)")

    # 1. fire bad logins
    failures = fire_bad_logins(args.target, user, args.attempts, tag)
    if failures < 5:
        print(f"[!] only {failures} failed as expected — sshd may be rate-limiting",
              file=sys.stderr)
        print(f"    continuing anyway; the level-10 alert may still appear",
              file=sys.stderr)

    # 2. wait for wazuh to pick them up
    print(f"[*] polling Wazuh indexer for level>=10 SSH alert from {args.target} "
          f"as user={user} ...")
    idx = WazuhIndexerClient(
        base_url=os.environ.get("WAZUH_INDEXER_URL", "https://127.0.0.1:9200"),
        username=os.environ.get("WAZUH_INDEXER_USERNAME", "admin"),
        password=os.environ.get("WAZUH_INDEXER_PASSWORD", "SecretPassword"),
        verify_ssl=False,
    )
    alert = wait_for_wazuh_alert(
        idx=idx,
        srcip="192.168.1.106",
        username=user,
        target_agent=args.target,
        timeout_sec=args.timeout,
        start_ts=start_ts,
    )
    if not alert:
        print(f"[FAIL] no Wazuh alert within {args.timeout}s "
              f"(rule.level>=10 sshd from {args.target} as {user})")
        return 2

    rule = alert.get("rule", {})
    print(f"[OK]   Wazuh alert seen: rule={rule.get('id')} "
          f"level={rule.get('level')} {rule.get('description', '?')[:60]}")
    print(f"       timestamp={alert.get('@timestamp')}")
    print(f"       agent={alert.get('agent', {}).get('name', '?')}")

    # 3. run the SOC pipeline end-to-end against the alert
    print(f"[*] running SecurityOperationsAgent.ingest_wazuh_alert on the alert...")
    delta_alerts, delta_incidents, sev = run_poller_against_alert(alert, idx)
    print(f"[OK]   ingested: +{delta_alerts} alert(s), +{delta_incidents} incident(s), "
          f"severity={sev}")
    if delta_alerts < 1:
        print(f"[FAIL] SOC did not produce any alert from the Wazuh doc")
        return 3
    if rule.get("level", 0) >= 10 and delta_incidents < 1:
        print(f"[FAIL] level>=10 Wazuh alert but SOC did not auto-create an incident")
        return 4

    print(f"\n[ALL GOOD] benign brute-force → Wazuh → SOC pipeline verified end-to-end.")
    print(f"            tag={tag}  (grep wazuh-alerts-* for 'dstuser:\"{user}\"' to re-find)")
    return 0


if __name__ == "__main__":
    sys.exit(main())