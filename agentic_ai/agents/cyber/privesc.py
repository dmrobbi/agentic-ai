"""PrivescMixin (KA-031): privilege-escalation methodology planning
and capability-index lookups (no execution).

Adds privesc-aware planning ops to the kali agents: a 6-phase escalation
plan per platform (unix/windows with aliases), and a capability lookup
into the committed index (data/privesc_index.json; structure inspired by
GTFOBins/LOLBAS - command SYNTAX only, no payloads; every planned command
still passes the host agent's normal execution gates + a human review).

Ops:
- plan_privesc(target, platform) - platform is case-insensitive with
  common aliases (linux/macos -> unix; the unknown raises ValueError
  listing the known forms); the target passes the shared scrub + the
  host agent's target gate when one exists.
- privesc_index() - the committed index (dict).
- privesc_capability_lookup(binary, platform=None) - the index rows for
  the binary (case-insensitive, cross-platform capable: one call can
  return unix AND windows rows); a miss = found:False; a malformed
  binary name = ValueError.
"""

from __future__ import annotations

import json
import pathlib
import re

from agentic_ai.agents.cyber.web_pentest import wp_scrub_target

CATALOG_PATH = pathlib.Path(__file__).with_name("data").joinpath("privesc_index.json")

KNOWN_PLATFORMS = {"unix": ("unix", "linux", "macos"),
                   "windows": ("windows",)}
PHASE_POLICY = {"command_syntax_only": True}

PRIVESC_ENUM_STEPS = {
    "unix": (
        ("sudo-context", ("sudo -l",)),
        ("suid-sgid", ("find / -perm -4000 -type f 2>/dev/null",)),
        ("capabilities", ("getcap -r / 2>/dev/null",)),
        ("scheduled", ("crontab -l; ls -la /etc/cron* 2>/dev/null",)),
    ),
    "windows": (
        ("privileges", ("whoami /priv", "whoami /groups")),
        ("saved-creds", ("cmdkey /list",)),
        ("scheduled", ("schtasks /query /fo LIST",)),
    ),
}


def _platform_for(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("platform must be a non-empty string")
    form = value.strip().lower()
    for canonical, aliases in KNOWN_PLATFORMS.items():
        if form in aliases:
            return canonical
    raise ValueError("unknown platform %r - known: unix, linux, macos, windows"
                     % (value,))


class PrivescMixin:
    """Privilege-escalation planning + capability-index ops (no execution)."""

    def privesc_index(self) -> dict:
        """Load the committed capability index."""
        return json.loads(CATALOG_PATH.read_text())

    def _privesc_guard(self, target):
        t = wp_scrub_target(target)
        gate = getattr(self, "validate_target", None)
        if callable(gate):
            ok, msg = gate(t)
            if not ok:
                raise ValueError("target rejected by host agent gate: %s" % msg)
        return t

    def plan_privesc(self, target, platform):
        """The 6-phase escalation plan for a target on a platform."""
        t = self._privesc_guard(target)
        canonical = _platform_for(platform)
        phases = [
            ("1-scope", "Establish the escalation boundary",
             ["Document who you are now and what the engagement allows.",
              "Record the target baseline (patch level, hardening state)."],
             ["# scope: %s on %s; evidence = before/after only" % (t, canonical)]),
            ("2-enumerate", "Enumerate the platform's escalation surface",
             ["Run the platform enum set; capture every row as evidence."],
             list(PRIVESC_ENUM_STEPS[canonical][0][1]) +
             [c for _, cmds in PRIVESC_ENUM_STEPS[canonical][1:] for c in cmds]),
            ("3-capability-fit", "Match enum findings against the index",
             ["For every flagged binary, call "
              "privesc_capability_lookup(binary, platform=%r)." % canonical,
              "Record capabilities, syntax, and the detection pairing."],
             ["# op: privesc_capability_lookup('<binary>', platform=%r)" % canonical]),
            ("4-strategy", "Order candidates by impact and noise",
             ["Least-impact first; reversible before persistent.",
              "Never escalate beyond the engagement's written ceiling."],
             ["# per candidate: review the syntax row and the detection row"]),
            ("5-evidence", "Capture the proof, nothing more",
             ["Before/after shells, command outputs, timestamps.",
              "Everything leaves the machine scrubbed."],
             ["# evidence: outputs + the escalation record"]),
            ("6-hardening", "Hand the fix to the defense",
             ["Pair every finding with the index's detection row.",
              "Propose the config fix; retest the closed path."],
             ["# op: countermeasures pairing per finding"]),
        ]
        return {"target": t, "platform": canonical,
                "phases": [{"phase": pid, "goal": goal, "activities": acts,
                            "sample_commands": cmds, "policy": dict(PHASE_POLICY)}
                           for pid, goal, acts, cmds in phases]}

    def privesc_capability_lookup(self, binary, platform=None):
        """Index rows for a binary name (case-insensitive; optional
        platform filter; cross-platform binaries return all rows)."""
        if not isinstance(binary, str):
            raise ValueError("binary must be a string")
        q = binary.strip().lower()
        if not q or len(q) > 64 or not re.fullmatch(r"[a-z0-9_.\-]+", q):
            raise ValueError("binary must be 1..64 chars of [a-z0-9_.-]: %r"
                             % (binary,))
        platform = _platform_for(platform) if platform else None
        index = self.privesc_index()
        rows = []
        for plat in sorted(index["platforms"]):
            if platform and plat != platform:
                continue
            for row in index["platforms"][plat]:
                if row["binary"] == q:
                    rows.append(dict(row, platform=plat))
        return {"binary": q, "rows": rows, "found": bool(rows)}
