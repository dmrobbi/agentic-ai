"""ForensicsMixin (KA-038): analyst workflows for memory/disk/metadata
artifacts + evidence-handling policy (no execution).

Policy: read_only_on_originals: True — every artifact is worked on a
COPY; the originals stay untouched and get hash-chained via the
evidence modules (agentic_ai.agents.cyber.evidence_chain / evidence_bundle —
pointer-level coupling only; no import here).

Kinds: memory (aliases ram, memdump), disk (image), metadata (exif).
Unknown kinds raise ValueError naming the known kinds.

Ops:
- forensics_policy() - the policy rows + the module doc
- forensics_step_catalog(kind=None) - the per-kind analyst commands
  (raw templates with placeholders); None = the kind list
- plan_forensics(artifact_label, kind) - the 5-phase arc per kind
"""

from __future__ import annotations

from agentic_ai.agents.cyber.web_pentest import wp_scrub_target

FORENSIC_POLICY = {"read_only_on_originals": True, "work_on_copies": True}

KINDS = {"memory": ("memory", "ram", "memdump"),
         "disk": ("disk", "image"),
         "metadata": ("metadata", "exif")}

FORENSIC_STEPS = {
    "memory": (
        ("identify", ("volatility -f {artifact} psinfo",)),
        ("processes", ("volatility -f {artifact} pslist",
                       "volatility -f {artifact} pstree")),
        ("network", ("volatility -f {artifact} netscan",)),
        ("extract", ("volatility -f {artifact} procdump -D ./out",)),
    ),
    "disk": (
        ("partition-table", ("mmls {artifact}",)),
        ("file-listing", ("fls -r -p {artifact} > files.body",)),
        ("timeline", ("fls -m / -r {artifact} > timeline.body",)),
        ("extract", ("icat {artifact} <inode> > out.bin",)),
    ),
    "metadata": (
        ("exif", ("exiftool {artifact}",)),
        ("batch", ("exiftool -csv <dir> | head -50",)),
    ),
}

FORENSICS_PLAN = (
    ("1-preserve", "The originals stay untouched and get chained",
     ["The artifacts = a copy; the originals hash-locked away.",
      "Record the file hashes before anything else."],
     ["# op: evidence_chain over the originals (read-only)"]),
    ("2-acquire", "Verify the working copy",
     ["sha256 the copy; confirm it matches the original's chain head."],
     ["sha256sum {artifact}"]),
    ("3-analyze", "Run the kind's step catalog",
     ["The analyst's catalog per kind; every step's output = evidence."],
     ["# op: forensics_step_catalog('<kind>')"]),
    ("4-timeline", "Stitch the timeline per artifact",
     ["Order the evidence; mark the gaps honestly."],
     ["# timeline: per-artifact rows with the sources"]),
    ("5-report", "The SOC-paired findings",
     ["Per finding: the evidence + the detection pairing."],
     ["# report: SOC-paired; scrub before it leaves the machine"]),
)


def _kind_for(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("kind must be a non-empty string")
    form = value.strip().lower()
    for canonical, aliases in KINDS.items():
        if form in aliases:
            return canonical
    raise ValueError("unknown artifact kind %r - known: memory, disk, "
                     "metadata" % (value,))


class ForensicsMixin:
    """Forensics analyst planning ops (no execution; read-only policy)."""

    def forensics_index(self) -> dict:
        return {"kinds": sorted(KINDS), "policy": dict(FORENSIC_POLICY)}

    def _forensics_guard(self, artifact_label):
        t = wp_scrub_target(artifact_label)
        return t

    def forensics_policy(self) -> dict:
        return dict(FORENSIC_POLICY)

    def forensics_step_catalog(self, kind=None):
        if kind is None:
            return {"kinds": sorted(KINDS), "policy": dict(FORENSIC_POLICY)}
        form = kind.strip().lower()
        canonical = None
        for name, aliases in KINDS.items():
            if form in aliases:
                canonical = name
        if not canonical:
            raise ValueError("unknown artifact kind %r - known: memory, "
                             "disk, metadata" % (kind,))
        return {"kind": canonical, "policy": dict(FORENSIC_POLICY),
                "steps": [{"step": s, "commands": list(cmds)}
                          for s, cmds in FORENSIC_STEPS[canonical]]}

    def plan_forensics(self, artifact_label, kind):
        t = self._forensics_guard(artifact_label)
        canonical = _kind_for(kind)
        phases = []
        for pid, goal, acts, cmds in FORENSICS_PLAN:
            phases.append({"phase": pid, "goal": goal,
                           "activities": list(acts),
                           "sample_commands": [
                               c.replace("{artifact}", t)
                               for c in cmds],
                           "policy": dict(FORENSIC_POLICY)})
        return {"artifact": t, "kind": canonical,
                "policy": dict(FORENSIC_POLICY), "phases": phases}
