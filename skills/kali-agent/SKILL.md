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