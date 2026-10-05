"""SOC findings bridge (KA-066): SOC alert findings -> per-finding
verification plans. PURE PLANNER: never executes anything; the live SOC
pull is a later P5 wiring decision, not this module.

OUTPUT SCHEMA (the contract; pinned by test_soc_bridge.py):
{
  "planned": [                       # one entry per planable finding
    {
      "finding_id": str,             # from the finding's "id"
      "severity": str,               # normalized lowercase
      "host": str,                   # the scrubbed host string
      "cve": {                       # present IFF the finding carried a
        "id": str,                   # WELL-FORMED cve_id
        "known": bool,               # resolved against the matcher
        "exploit_name": str|None,
        "metasploit_module": str|None,
        "reliability": str|None,
        "port": int|None
      } | null,
      "verification_steps": [str],   # planner command strings; executed
      "notes": [str]                 # by nobody here - planners only
    }
  ],
  "unplannable": [                   # schema-violating findings NEVER crash
    {"finding_id": str, "reasons": [str]},   # the flow: they land here
    # "<missing-id>" marks findings that had no usable id at all
  ],
  "summary": {
    "total": int, "planned": int, "unplannable": int, "with_known_cve": int
  }
}

FINDING CONTRACT (input): dict with
  id        required, ^[A-Za-z0-9_.-]{1,64}$
  severity  required, critical|high|medium|low (case-insensitive)
  host      required, must survive scrub_host (no metachars/whitespace)
  cve_id    optional, CVE-\d{4}-\d+ exactly; anything else is unplannable
  summary   optional free text (quoted in planner notes only)

Matcher injection: the CVE path consults an injected matcher with the
duck-typed protocol match_cve(cve_id) -> object-with-exploit-fields | None,
defaulting to CVEMatchingEngine (cross-engine reference is a bridge's
purpose; exec/network facilities remain banned - source-scanned; the
engine default imports LAZILY - a module-level import would cycle
with the v2 chassis).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

CVE_RE = r"CVE-\d{4}-\d+"
ID_RE = r"[A-Za-z0-9_.\-]{1,64}"
SEVERITIES = ("critical", "high", "medium", "low")


def scrub_host(host: str) -> str:
    """The shared input gate for host targets (wp_scrub_target pattern)."""
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host must be a non-empty string")
    scrubbed = host.strip()
    if re.search(r"[;|&`$()\n\r<>\"'\s]", scrubbed) or ".." in scrubbed:
        raise ValueError("rejected host with disallowed characters: %r" % host)
    return scrubbed


class SocFindingsVerifier:
    """Plan per-finding verification for SOC alert findings (planners only)."""

    def __init__(self, matcher=None):
        if matcher is not None:
            self.matcher = matcher
        else:
            # lazy default: a module-level import would make a
            # bridge<->chassis cycle (the v2 chassis imports this bridge)
            from agentic_ai.agents.cyber.kali_v2 import CVEMatchingEngine
            self.matcher = CVEMatchingEngine()

    def _cve_reference(self, cve_id: str) -> Dict[str, Any]:
        match = self.matcher.match_cve(cve_id)
        known = match is not None
        return {
            "id": cve_id,
            "known": known,
            "exploit_name": match.exploit_name if known else None,
            "metasploit_module": match.metasploit_module if known else None,
            "reliability": match.reliability if known else None,
            "port": match.port if known else None,
        }

    def _steps_and_notes(
        self, finding_id: str, host: str, severity: str,
        summary: str, cve_ref: Optional[Dict[str, Any]],
    ) -> tuple:
        steps: List[str] = []
        notes: List[str] = []
        if cve_ref is None:
            steps.append("nmap -sV -sC -oX /tmp/%s-nmap.xml %s" % (finding_id, host))
            if summary:
                notes.append("manual triage: '%s' (severity %s)" % (summary, severity))
            else:
                notes.append("manual triage required (severity %s)" % severity)
            return steps, notes

        cve_id = cve_ref["id"]
        if cve_ref["known"]:
            probe = (
                "nmap -sV -sC -p %d -oX /tmp/%s-nmap.xml %s"
                % (cve_ref["port"], finding_id, host)
                if cve_ref["port"]
                else "nmap -sV -sC -oX /tmp/%s-nmap.xml %s"
                % (finding_id, host)
            )
            steps.append(probe)
            steps.append("searchsploit %s" % cve_ref["exploit_name"])
            if cve_ref["metasploit_module"]:
                steps.append("msfconsole -q -x 'search %s'" % cve_id)
            notes.append(
                "matcher: %s known (exploit %s, reliability %s, port %s) - "
                "confirm the service banner before any engagement"
                % (cve_id, cve_ref["exploit_name"],
                   cve_ref["reliability"], cve_ref["port"])
            )
        else:
            steps.append("nmap -sV -sC -oX /tmp/%s-nmap.xml %s" % (finding_id, host))
            notes.append(
                "%s is real but absent from the internal exploit DB - "
                "triage against the host patch level" % cve_id
            )
        return steps, notes

    def verify_findings(
        self, findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Turn SOC findings into per-finding verification plans."""
        planned: List[Dict[str, Any]] = []
        unplannable: List[Dict[str, Any]] = []
        with_known_cve = 0
        rows = list(findings or [])
        for row in rows:
            raw_id = row.get("id") if isinstance(row, dict) else None
            finding_id = raw_id.strip() if isinstance(raw_id, str) and raw_id.strip() else "<missing-id>"

            reasons: List[str] = []
            if raw_id is None or not (isinstance(raw_id, str) and raw_id.strip()):
                reasons.append("finding id missing")
            elif not re.fullmatch(ID_RE, raw_id.strip()):
                reasons.append("finding id malformed: %r" % raw_id)

            severity = row.get("severity") if isinstance(row, dict) else None
            if not isinstance(severity, str) or severity.strip().lower() not in SEVERITIES:
                reasons.append("severity must be one of critical|high|medium|low, got: %r"
                               % (severity,))

            host = row.get("host") if isinstance(row, dict) else None
            scrubbed = None
            if isinstance(host, str) and host.strip():
                try:
                    scrubbed = scrub_host(host)
                except ValueError as exc:
                    reasons.append(str(exc))
            else:
                reasons.append("host missing")

            raw_cve = row.get("cve_id") if isinstance(row, dict) else None
            cve_ref: Optional[Dict[str, Any]] = None
            if raw_cve:
                if isinstance(raw_cve, str) and re.fullmatch(CVE_RE, raw_cve):
                    cve_ref = self._cve_reference(raw_cve)
                    if cve_ref["known"]:
                        with_known_cve += 1
                else:
                    reasons.append("cve_id malformed: %r" % (raw_cve,))

            if reasons:
                unplannable.append({"finding_id": finding_id, "reasons": reasons})
                continue

            summary = row.get("summary") if isinstance(row, dict) else None
            severity_norm = severity.strip().lower()
            steps, notes = self._steps_and_notes(
                finding_id, scrubbed, severity_norm,
                summary if isinstance(summary, str) else "", cve_ref,
            )
            planned.append({
                "finding_id": finding_id,
                "severity": severity_norm,
                "host": scrubbed,
                "cve": cve_ref,
                "verification_steps": steps,
                "notes": notes,
            })

        return {
            "planned": planned,
            "unplannable": unplannable,
            "summary": {
                "total": len(rows),
                "planned": len(planned),
                "unplannable": len(unplannable),
                "with_known_cve": with_known_cve,
            },
        }
