---
name: "kali-agent"
description: "Use when installing, verifying, or operating KaliAgent v4 (kali_agent_v4 in the agentic-ai repo) — CLI entry, health checks, dashboards, evidence packaging, and the authorization gate for live-fire phases."
---

# KaliAgent v4

`kali_agent_v4/` is the live Kali agent generation (v4, "Real Attack Works
Edition"; the CLI entry is the `kali_agent_v4/kaliagent` script). It is a
standalone click/rich CLI — separate from the in-repo `agenticai agent kali`
role agent (see the agentic-roles skill for that one).

Older generations live in the same repo and are NOT the current agent:
`kali_agent_v3/` (v3.0.0, superseded) and `kaliagent-v4/` (misleadingly
named; only evidence artifacts - a phase-14 LSTM module and CVE evidence
dirs). Dashboards: `kali_dashboard/` for the kali UI.

## Steps

1. Environment: `python3 -m venv .venv && pip install -r <repo>/requirements.txt`
   (the CLI needs click + rich; the pentest phases add tool-specific deps and
   a Kali Linux host). Run everything from the repo root so
   `sys.path` resolution holds; the script self-inserts its parent dir.
2. Dry-run layer (no agent phases, safe anywhere):
   - `python kali_agent_v4/kaliagent version` - banner (v4.0.0 codename).
   - `python kali_agent_v4/kaliagent --help` - command list: version, status,
     dashboard, doctor, update.
   - `python kali_agent_v4/kaliagent doctor` - health report (Python version,
     dependencies, dashboard port 5007, C2 ports, database, Redis, Ollama).
     Verified live 2026-09-29: all checks passed on a host with the SOC
     sidecar services; on a bare host expect the failing rows to show.
   Done when doctor runs and you understand what it probes.
3. Live-fire gate: the agent's real attack phases execute against TARGETS and
   generate evidence. Only run them against systems you are explicitly
   authorized to test, with the target set deliberately (the `evidence/`
   directory records runs; never edit evidence artifacts after the fact).
   The doctor/status commands never attack anything.
4. Dashboard + services: `kali_dashboard/` + `kali_agent_v4/docker-compose.yml`
   (dashboard on :5007, C2 ports 8888/1337/8889, Redis, Ollama);
   `python kali_agent_v4/kaliagent dashboard` launches the web UI.
5. Verify after any change: `doctor` green on the intended host, then a
   phase run only if the operator has authorized a target. Evidence lands in
   `kali_agent_v4/evidence/`.

## House rules

- Version badges in kali_agent_v4/README.md point at the historical
  pre-migration v4 GitHub releases; attribution history, kept as-is.
- Do not delete the older generations without an explicit owner decision -
  they preserve the audit lineage (v3 was the prior production release).
- Real-attack evidence is never edited post-run; if something in an evidence
  file is wrong, record the correction in a new file.

## Lab battery + runbook references

The fleet repo ships an owner-run lab battery so this agent's plans can be
proven against deliberately vulnerable targets, and a detection runbook that
turns a real lab attack into a real detection plus a verification plan:

- Fleet harness (KA-076): docker/fleet-harness/README.md — two opt-in compose
  profiles (vulnerable-app farm on host ports 8191-8194 plus a SOC sidecar
  slice), driven by docker/fleet-harness/harness.sh
  (`help|status|up|down|reset|run|evidence`); compose data sits in
  docker-compose.fleet-lab.yml (a bare `up` starts NOTHING). Start the
  battery with `docker/fleet-harness/harness.sh run lab` - gate check, farm
  up (idempotent), `pytest tests/lab`, then bundled evidence. The original
  lab-target trio (ports 8181-8183) lives in docker/lab-targets/.
- Lab battery tests: tests/lab/ (tests/lab/test_planner_parity.py,
  tests/lab/test_fleet_harness.py) - collected by the suite driver; every
  live surface inside skips cleanly without the owner gate raised.
- Detection runbook (KA-078): docs/KA-LAB-DETECTION.md - enroll the battery
  target into the SOC's Wazuh, run the marker brute force, confirm the
  expected rule fired, then map the alert row onto a per-finding
  verification plan with the `verify_soc_findings` op
  (agentic_ai/agents/cyber/soc_bridge.py). Entry points:
  scripts/lab/pve-lab-battery.sh (--check/--reset, battery target tier) and
  scripts/lab/enroll-wazuh.sh (--check/--verify/--enroll); sibling
  playbooks docs/KA-LAB-TARGET.md (target + reset machinery) and
  docs/KA-EXPLOIT-TESTS.md (the environment-gate discipline table).
- Consent discipline: battery and runbook state-changers are gated by
  environment gates the OWNER raises deliberately: KA_LAB_BATTERY (lab
  battery tests), KA_FLEET_HARNESS (fleet harness consent), KA_LAB_CONSENT
  and KA_BATTERY_CONSENT (the runbooks' mutating steps), BRUTEFORCE_E2E
  (the SOC e2e pipeline). Reference gates by NAME only in plans, reports,
  and chat; the agent's own surface stays planning-only and
  lab_or_authorized_targets_only, so dry-run ops keep working with no
  consent at all.
- Evidence: battery runs land under the repo's evidence/ directory
  (`evidence/<UTC stamp>/battery.log` + `manifest.sha256`, runtime output,
  untracked by design); the CLI's own phase evidence stays in
  kali_agent_v4/evidence/ - never edit evidence after the fact, and never
  store evidence on the lab target (a `--reset` wipes it). After surface
  changes the SOC fleet healthcheck re-proves kali op presence via its
  op-presence row (docs/ka_healthcheck_row.md).