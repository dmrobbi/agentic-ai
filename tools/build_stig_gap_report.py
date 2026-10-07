#!/usr/bin/env python3
"""Build data/stig_gap_report.json - KA-072 STIG-coverage gap report.

STIG-coverage gap planning across the two sides OPT-72 names:

* MAINTAINED BASELINES - the stig-baselines program's baseline inventory
  (public repo https://github.com/dmrobbi/stig-baselines; DISA STIG
  checklists generated from the official DISA XCCDF sources, plus custom
  STIG-style baselines carrying controls.yaml kits). Curated rows carry
  the per-platform CKL-file counts and the DISTINCT Vuln_Num counts
  measured in that repo on BASELINE_COUNTS_AS_OF (2026-10-06; merged
  baselines such as the RHEL+Firefox checklists count each Vuln_Num once
  per platform, matching the repo's own baseline table).
* FLEET SCAN STATE - parsed .ckl checklists (the program's checklist
  shape: VULN rows with STIG_DATA attribute pairs and STATUS values
  NotAFinding / Open / Not_Applicable / Not_Reviewed) keyed to their
  maintained baseline by the checklist STIG_INFO title.

GAP DEFINITION (rule-level, deterministic): a rule is COVERED when its
SRG control family carries at least one curated assessment template in
this catalog, UNMET otherwise; a maintained baseline with no fleet scan
state reports as an unscanned coverage gap. Coverage is capability, not
compliance - the status counts carry the fleet's finding truth
separately, and the Open / Not_Reviewed rows form the bounded,
severity-ordered priority queue. Control families are the DISA SRG
domains observed across the maintained baselines (SRG-OS / SRG-APP /
SRG-NET; legacy prose group titles fall to the `unknown` family). The
OS and APP families carry curated template rows; NET carries none on
2026-10-06, which is exactly the capability gap this report surfaces.

OUTPUT SCHEMA (shape pinned by tests/test_stig_gap.py):
  top-level: baselines, families, gap_definition, gaps, meta, totals
  family row:    arc, label, templates
  template row:  name, purpose, stage, url
  baseline row:  ckls, kit, labels, rules_maintained, track
  by_platform row: covered_rules, coverage_pct, in_scan_state,
      priority_queue, rules_by_family, rules_total, statuses,
      unmet_by_family, unmet_rules  (queue row: family, severity,
      status, vuln_num)
  unscanned row:  ckls, kit, platform, reason, rules_maintained
  unmatched row:  reason, stig_title, vulns
  malformed row:  error, file
  unmet_by_family row: platforms, rules_unmet

Sources/licensing: maintained-baseline inventory from the public
stig-baselines repository (DISA STIG content is public domain per the
DoD Cyber Exchange); per-family assessment template rows are
RE-AUTHORED in-house from each platform's own official documentation
(nothing verbatim). Rule and queue rows carry identifiers, severities,
statuses and counts only - no verbatim DISA rule prose, no payloads,
no exploit content.

Build-time URL discipline (mirrors tools/build_cms_catalog.py): every
URL in the emitted catalog was verified live (HTTP 200) on 2026-10-06
with the bounded polite sequential sweep (the --live mode below;
429/Retry-After honored once, then the candidate is dropped).
Candidates dropped during curation and not in the catalog:
  - www.freedesktop.org/software/systemd/man/  (HTTP 418 to
    non-browser clients) - its OS inventory row was replaced by
    manpages.debian.org/.
  - docs.vmware.com/ verified live but not shipped: the NET family
    carries no template rows yet (designed gap, not a dead link).
  - docs.ansible.com/ansible/latest/  (rate-limited 429 through the
    once-honored Retry-After re-check on 2026-10-06; a bare re-probe
    in curation had seen 200, so the url is live but too
    rate-aggressive for this sweep's budget) - the remediation-plan
    row was dropped; the OS arc's remediation-plan stage carries no
    template row today.
Dead-link notes live in this docstring, never in the emitted data.

The default run is OFFLINE and deterministic: no --scan means no fleet
state has been wired yet, so every maintained baseline reports as an
unscanned coverage gap; the catalog part re-serializes the curated rows
below canonically (the data evolves by editing the literals, never by
hand-editing the JSON). --scan ingests .ckl files or directories of
them; --live is opt-in URL verification only, never in CI or tests.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "stig_gap_report.json"

STATUSES = ("NotAFinding", "Open", "Not_Applicable", "Not_Reviewed")
SEVERITIES = ("high", "medium", "low")
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
# how actionable a repeated Vuln_Num's status is across fleet files:
# a rule Open on any host outranks one that is merely unreviewed.
STATUS_RANK = {"Open": 0, "Not_Reviewed": 1, "NotAFinding": 2,
               "Not_Applicable": 3}
OPEN_STATUSES = ("Open", "Not_Reviewed")
MAX_PRIORITY_ROWS = 25
UNSCANNED_REASON = "no_fleet_scan_state"
UNMATCHED_REASON = "no_matching_maintained_baseline"

GAP_DEFINITION = (
    "a rule is covered when its SRG control family carries at least one "
    "curated assessment template; families without templates report their "
    "rules as unmet capability gaps; a maintained baseline without fleet "
    "scan state reports as an unscanned coverage gap. Coverage is "
    "capability, not compliance - status counts carry the fleet finding "
    "truth separately")

BASELINE_COUNTS_AS_OF = "2026-10-06"
URLS_VERIFIED = "2026-10-06"

SOURCE = (
    "maintained-baseline inventory from the public stig-baselines "
    "repository (github.com/dmrobbi/stig-baselines; DISA STIG content is "
    "public domain per the DoD Cyber Exchange); per-family assessment "
    "template rows re-authored in-house from each platform's own "
    "official vendor documentation; checklist shapes modeled on the "
    "program's generated CKL files")

POLICY = (
    "identifiers, severities, statuses, and counts only - no verbatim "
    "DISA rule text, no payloads, no exploit tooling; every catalog url "
    "verified live at build time; the offline default run is "
    "deterministic")

REGISTRY_NOTE = (
    "the OS and APP families carry curated assessment template rows; the "
    "NET family carries none on the baseline-counts date, so its rules "
    "report as unmet capability gaps across scanned baselines")

SOURCES = [
    {"label": "stig-baselines maintained baselines",
     "url": "https://github.com/dmrobbi/stig-baselines"},
    {"label": "DISA STIG program (public domain licensing anchor)",
     "url": "https://public.cyber.mil/stigs/"},
]

# Curated per-family assessment templates: RE-AUTHORED methodology
# pointers (names + official doc links + purposes; no payloads). Every
# URL below returned HTTP 200 to the bounded polite sweep on
# 2026-10-06; NET is deliberately without rows (see REGISTRY_NOTE).
OS_ARC = ("inventory", "config-review", "finding-pairing",
          "remediation-plan")
APP_ARC = ("service-inventory", "config-review", "version-trail",
           "findings")
NET_ARC = ("device-inventory", "config-review", "segmentation-review",
           "findings")

FAMILY_ROWS = {
    "OS": {
        "label": "Operating-system rules",
        "arc": list(OS_ARC),
        "templates": [
            {"stage": "inventory",
             "name": "Ubuntu server documentation",
             "url": "https://ubuntu.com/server/docs",
             "purpose": "system service and configuration documentation "
                        "for read-only inventory of Linux hosts in "
                        "scope"},
            {"stage": "config-review",
             "name": "Debian manpages repository",
             "url": "https://manpages.debian.org/",
             "purpose": "authoritative manpage ground truth for reading "
                        "configuration directives before judging an "
                        "OS rule check"},
            {"stage": "config-review",
             "name": "OpenSSH manual",
             "url": "https://www.openssh.com/manual.html",
             "purpose": "sshd_config directive review for OS rules "
                        "keyed to remote access settings"},
            {"stage": "config-review",
             "name": "sudo reference manual",
             "url": "https://www.sudo.ws/docs/man/sudoers.man/",
             "purpose": "sudoers directive review for OS rules on "
                        "privilege escalation and command "
                        "restriction"},
        ],
    },
    "APP": {
        "label": "Application rules",
        "arc": list(APP_ARC),
        "templates": [
            {"stage": "service-inventory",
             "name": "Exchange documentation",
             "url": "https://learn.microsoft.com/en-us/exchange/",
             "purpose": "mail-organizational surface map for planning "
                        "service-level enumeration of the mail "
                        "baselines"},
            {"stage": "config-review",
             "name": "Mozilla policy templates",
             "url": "https://mozilla.github.io/policy-templates/",
             "purpose": "browser enterprise-policy keys for reviewing "
                        "each Firefox baseline rule against its "
                        "official policy setting"},
            {"stage": "config-review",
             "name": "nginx documentation",
             "url": "https://nginx.org/en/docs/",
             "purpose": "server directive review for application rules "
                        "keyed to web service configuration"},
        ],
    },
    "NET": {
        "label": "Network-device rules",
        "arc": list(NET_ARC),
        "templates": [],
    },
}

# Curated maintained-baseline inventory (stig-baselines repo, measured
# 2026-10-06): ckls = committed .ckl files per baseline directory;
# rules_maintained = DISTINCT Vuln_Num across those files (merged
# baselines count each rule once); kit = the baseline ships a
# controls.yaml kit (custom STIG-style baseline); track: archived
# EOL-track baselines carry "eol", everything shipped today "active".
BASELINE_ROWS = {
    "citrix": {"labels": ["Citrix"], "ckls": 13, "rules_maintained": 49,
               "kit": False, "track": "active"},
    "docker": {"labels": ["Docker"], "ckls": 0, "rules_maintained": 0,
               "kit": True, "track": "active"},
    "exchange": {"labels": ["Microsoft Exchange"], "ckls": 7,
                 "rules_maintained": 432, "kit": False,
                 "track": "active"},
    "firefox": {"labels": ["Mozilla Firefox"], "ckls": 1,
                "rules_maintained": 33, "kit": False, "track": "active"},
    "horizon": {"labels": ["VMware Horizon 7.13"], "ckls": 3,
                "rules_maintained": 57, "kit": False, "track": "active"},
    "kubernetes": {"labels": ["Kubernetes"], "ckls": 1,
                   "rules_maintained": 92, "kit": True, "track": "active"},
    "macos": {"labels": ["Apple macOS"], "ckls": 2,
              "rules_maintained": 320, "kit": False, "track": "active"},
    "nsx": {"labels": ["VMware NSX"], "ckls": 13, "rules_maintained": 131,
            "kit": False, "track": "active"},
    "outlook": {"labels": ["Microsoft Outlook"], "ckls": 2,
                "rules_maintained": 146, "kit": False, "track": "active"},
    "proxmox": {"labels": ["Proxmox VE"], "ckls": 0,
                "rules_maintained": 0, "kit": True, "track": "active"},
    "rhel7": {"labels": ["Red Hat Enterprise Linux 7"], "ckls": 3,
              "rules_maintained": 277, "kit": False, "track": "eol"},
    "rhel8": {"labels": ["Red Hat Enterprise Linux 8"], "ckls": 3,
              "rules_maintained": 404, "kit": False, "track": "active"},
    "rhel9": {"labels": ["Red Hat Enterprise Linux 9"], "ckls": 3,
              "rules_maintained": 478, "kit": False, "track": "active"},
    "ubuntu20.04": {"labels": ["Canonical Ubuntu 20.04 LTS"], "ckls": 1,
                    "rules_maintained": 173, "kit": False,
                    "track": "active"},
    "ubuntu22.04": {"labels": ["Canonical Ubuntu 22.04 LTS"], "ckls": 1,
                    "rules_maintained": 188, "kit": False,
                    "track": "active"},
    "ubuntu24.04": {"labels": ["Canonical Ubuntu 24.04 LTS"], "ckls": 1,
                    "rules_maintained": 194, "kit": False,
                    "track": "active"},
    "vra7": {"labels": ["VMware vRealize Automation",
                        "VMW vRealize Automation"],
             "ckls": 8, "rules_maintained": 611, "kit": False,
             "track": "active"},
    "vrops6": {"labels": ["VMware vRealize Operations",
                          "VMW vRealize Operations"],
               "ckls": 5, "rules_maintained": 517, "kit": False,
               "track": "active"},
    "vsphere65": {"labels": ["VMware vSphere 6.5"], "ckls": 3,
                  "rules_maintained": 180, "kit": False,
                  "track": "active"},
    "vsphere67": {"labels": ["VMware vSphere 6.7"], "ckls": 12,
                  "rules_maintained": 502, "kit": False,
                  "track": "active"},
    "vsphere70": {"labels": ["VMware vSphere 7.0"], "ckls": 12,
                  "rules_maintained": 491, "kit": False,
                  "track": "active"},
    "vsphere80": {"labels": ["VMware vSphere 8.0"], "ckls": 12,
                  "rules_maintained": 487, "kit": False,
                  "track": "active"},
    "windows": {"labels": ["Microsoft Windows"], "ckls": 4,
                "rules_maintained": 1084, "kit": False,
                "track": "active"},
    "workspace_one": {"labels": ["VMware Workspace ONE UEM"], "ckls": 1,
                      "rules_maintained": 20, "kit": False,
                      "track": "active"},
}


def build_catalog() -> dict:
    """Canonical catalog structure from the curated rows: sorted family
    and baseline keys, rows kept verbatim, meta totals computed by
    count (drift alarm)."""
    families = {name: dict(FAMILY_ROWS[name])
                for name in sorted(FAMILY_ROWS)}
    baselines = {name: dict(BASELINE_ROWS[name], labels=list(BASELINE_ROWS[name]["labels"]))
                 for name in sorted(BASELINE_ROWS)}
    totals = {
        "baselines": len(baselines),
        "ckls": sum(row["ckls"] for row in baselines.values()),
        "families": len(families),
        "rules_maintained": sum(row["rules_maintained"]
                                for row in baselines.values()),
        "template_rows": sum(len(e["templates"])
                             for e in families.values()),
    }
    return {
        "families": families,
        "baselines": baselines,
        "meta": {
            "source": SOURCE,
            "policy": POLICY,
            "registry_note": REGISTRY_NOTE,
            "totals": totals,
            "urls_verified": URLS_VERIFIED,
        },
    }


_SRG_RE = re.compile(r"\bSRG-([A-Z]+)-\d+")


def srg_family(group_title: str) -> str:
    """Derive the STIG control family (the DISA SRG domain) from a rule
    group title: 'SRG-OS-000480-GPOS-00227' -> 'OS'; anything without a
    recognizeable SRG id (legacy prose group titles, empty values)
    reports as the 'unknown' family - an unmet capability, never a
    crash."""
    match = _SRG_RE.search(group_title or "")
    return match.group(1) if match else "unknown"


def parse_ckl(text: str) -> dict:
    """Parse a checklist (the stig-baselines program CKL shape) into
    rule rows for scan-state gap math.

    Returns {stig_title, stig_id, release_info, source, rules}; rule
    rows carry vuln_num / rule_id / rule_ver / severity / group_title /
    cci / status - identifiers and state only, never check or fix
    prose.

    Raises ValueError with an actionable message when the shape misses:
    unparseable xml, a non-CHECKLIST root, a missing STIG_INFO header,
    no VULN rows, a missing STATUS element, a status outside the four
    program statuses, a severity outside high/medium/low, or a VULN
    row without Vuln_Num / Rule_ID / Rule_Ver. Group titles may be
    empty (they fall to the 'unknown' family by design).
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("CKL text empty (expected CHECKLIST xml)")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("CKL not parseable xml: %s" % exc)
    if root.tag != "CHECKLIST":
        raise ValueError("CKL root element is %r (expected CHECKLIST)"
                         % (root.tag,))
    stig_node = root.find("STIGS/iSTIG/STIG_INFO")
    if stig_node is None:
        raise ValueError("CKL missing STIGS/iSTIG/STIG_INFO header")
    info: dict = {}
    for si in stig_node.findall("SI_DATA"):
        name = si.findtext("SID_NAME")
        if name is not None:
            info.setdefault(name.strip(), (si.findtext("SID_DATA") or "").strip())
    vulns = root.findall("STIGS/iSTIG/VULN")
    if not vulns:
        raise ValueError("CKL carries no VULN rows")
    rules: list = []
    for index, vuln in enumerate(vulns, start=1):
        attrs: dict = {}
        for sd in vuln.findall("STIG_DATA"):
            name = sd.findtext("VULN_ATTRIBUTE")
            if name is not None:
                attrs.setdefault(
                    name.strip(),
                    (sd.findtext("ATTRIBUTE_DATA") or "").strip())
        status = vuln.findtext("STATUS")
        if status is None:
            raise ValueError("VULN row %d missing STATUS element" % index)
        status = status.strip()
        if status not in STATUSES:
            raise ValueError(
                "VULN row %d status %r not one of %s"
                % (index, status, ", ".join(STATUSES)))
        severity = attrs.get("Severity")
        if severity not in SEVERITIES:
            raise ValueError(
                "VULN row %d severity %r not one of %s"
                % (index, severity, ", ".join(SEVERITIES)))
        missing = [key for key in ("Vuln_Num", "Rule_ID", "Rule_Ver")
                   if not attrs.get(key)]
        if missing:
            raise ValueError(
                "VULN row %d missing required attributes: %s"
                % (index, ", ".join(missing)))
        rules.append({
            "vuln_num": attrs["Vuln_Num"],
            "rule_id": attrs["Rule_ID"],
            "rule_ver": attrs["Rule_Ver"],
            "severity": severity,
            "group_title": attrs.get("Group_Title", ""),
            "cci": attrs.get("CCI_REF", ""),
            "status": status,
        })
    return {
        "stig_title": info.get("title", ""),
        "stig_id": info.get("stigid", ""),
        "release_info": info.get("releaseinfo", ""),
        "source": info.get("source", ""),
        "rules": rules,
    }


_XCCDF_NS_RE = re.compile(
    r"\{http://checklists\.nist\.gov/xccdf/[0-9.]+\}Benchmark$")
_SRG_EXTRACT_RE = re.compile(r"SRG-[A-Z]+-\d+-[A-Z]+-\d+")


def parse_xccdf(text: str) -> dict:
    """Parse an official DISA XCCDF source (the Benchmark/Group/Rule
    shape the maintained baselines are generated from) into rule rows.

    Returns {benchmark_title, rules} where rule rows carry group_id /
    rule_id / rule_ver / severity / srg / cci (the SRG id sits in the
    Group title, the CCI in the Rule's ident). Raises ValueError on
    shape misses; carries no rule prose.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("XCCDF text empty (expected a Benchmark)")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("XCCDF not parseable xml: %s" % exc)
    if not _XCCDF_NS_RE.match(root.tag):
        raise ValueError(
            "XCCDF root element is %r (expected a xccdf Benchmark)"
            % (root.tag,))
    ns = re.match(r"\{(.+)\}Benchmark$", root.tag).group(1)
    tag = "{%s}" % ns
    title = root.findtext(tag + "title") or ""
    groups = root.findall(".//" + tag + "Group")
    if not groups:
        raise ValueError("XCCDF benchmark carries no Group elements")
    rules: list = []
    for index, group in enumerate(groups, start=1):
        group_id = group.get("id") or ""
        if not group_id:
            raise ValueError("XCCDF Group %d missing its id" % index)
        srg = _SRG_EXTRACT_RE.search(
            (group.findtext(tag + "title") or "") + " "
            + (group.findtext(tag + "Rule/" + tag + "description") or ""))
        if srg is None:
            raise ValueError(
                "XCCDF Group %d (%s) carries no SRG reference"
                % (index, group_id))
        for rule in group.findall(tag + "Rule"):
            rule_id = rule.get("id") or ""
            severity = rule.get("severity") or ""
            if not rule_id:
                raise ValueError(
                    "XCCDF Rule under group %s missing its id"
                    % (group_id,))
            if severity not in SEVERITIES:
                raise ValueError(
                    "XCCDF Rule %s severity %r not one of %s"
                    % (rule_id, severity, ", ".join(SEVERITIES)))
            # the group's first Rule supplies the srg family context;
            # keep the regex match found for THIS group
            rules.append({
                "group_id": group_id,
                "rule_id": rule_id,
                "rule_ver": (rule.findtext(tag + "version") or "").strip(),
                "severity": severity,
                "srg": srg.group(0),
                "cci": " ".join(stripped for stripped in (
                    (ident.text or "").strip()
                    for ident in rule.findall(tag + "ident")) if stripped),
            })
    return {"benchmark_title": title, "rules": rules}


def resolve_platform(catalog: dict, stig_title: str) -> str | None:
    """Key a checklist STIG_INFO title to its maintained baseline by
    longest platform-prefix match (labels list; ties keep the first
    sorted platform). Returns None when no baseline matches - the
    checklist names a system the maintained set does not carry."""
    best = None
    best_len = -1
    for platform in sorted(catalog["baselines"]):
        for label in catalog["baselines"][platform]["labels"]:
            if stig_title.startswith(label) and len(label) > best_len:
                best = platform
                best_len = len(label)
    return best


def _collapse_rules(existing: list, incoming: list) -> list:
    """Collapse repeated Vuln_Num rows to the most-actionable status
    (STATUS_RANK; deterministic tie-break keeps the first) across a
    platform's fleet checklists; order stays stable for the rest."""
    ordered: dict = {}
    for rule in list(existing) + list(incoming):
        key = (rule["vuln_num"], rule["rule_id"])
        rank = STATUS_RANK[rule["status"]]
        prev = ordered.get(key)
        if prev is None or rank < prev[0]:
            ordered[key] = (rank, dict(rule))
    return [row for (rank, row) in ordered.values()]


def gap_report(catalog: dict, scan_state: dict | None = None) -> dict:
    """The KA-072 report: the catalog joined with fleet scan state.

    scan_state maps platform name -> rule dicts as returned by
    parse_ckl (the CLI path keys them via resolve_platform; duplicate
    Vuln_Num rows collapse to the most-actionable status). Emits the
    pinned shape; every derived value is deterministic (sorted keys,
    fixed status order, severity-then-status-then-id queue ordering,
    bounded queue)."""
    if scan_state is None:
        scan_state = {}
    unknown_scan = [p for p in scan_state
                    if p not in catalog["baselines"]]
    if unknown_scan:
        raise ValueError(
            "scan_state platforms not in the maintained catalog: %s"
            % (", ".join(sorted(unknown_scan))))

    by_platform: dict = {}
    unmet_by_family: dict = {}
    lacking: list = []
    rules_scanned = 0
    covered_total = 0
    unmet_total = 0
    for platform in sorted(scan_state):
        rules = _collapse_rules([], scan_state[platform])
        rules_total = len(rules)
        statuses = {status: 0 for status in STATUSES}
        rules_by_family: dict = {}
        unmet_platform: dict = {}
        queue: list = []
        for rule in rules:
            statuses[rule["status"]] += 1
            family = srg_family(rule["group_title"])
            rules_by_family[family] = rules_by_family.get(family, 0) + 1
            if rule["status"] in OPEN_STATUSES:
                queue.append({
                    "family": family,
                    "severity": rule["severity"],
                    "status": rule["status"],
                    "vuln_num": rule["vuln_num"],
                })
            if family in catalog["families"] and \
                    catalog["families"][family]["templates"]:
                continue
            unmet_platform[family] = unmet_platform.get(family, 0) + 1
            fam_rows = unmet_by_family.setdefault(family, {})
            fam_rows[platform] = fam_rows.get(platform, 0) + 1
        queue.sort(key=lambda row: (SEVERITY_RANK[row["severity"]],
                                    STATUS_RANK[row["status"]],
                                    row["vuln_num"]))
        covered = rules_total - sum(unmet_platform.values())
        coverage_pct = (round(100.0 * covered / rules_total, 1)
                        if rules_total else 0.0)
        by_platform[platform] = {
            "covered_rules": covered,
            "coverage_pct": coverage_pct,
            "in_scan_state": True,
            "priority_queue": queue[:MAX_PRIORITY_ROWS],
            "rules_by_family": {k: rules_by_family[k]
                                for k in sorted(rules_by_family)},
            "rules_total": rules_total,
            "statuses": statuses,
            "unmet_by_family": {k: unmet_platform[k]
                                for k in sorted(unmet_platform)},
            "unmet_rules": sum(unmet_platform.values()),
        }
        rules_scanned += rules_total
        covered_total += covered
        unmet_total += sum(unmet_platform.values())
        if unmet_platform:
            lacking.append(platform)

    unscanned = [
        {"platform": platform,
         "ckls": row["ckls"],
         "kit": row["kit"],
         "rules_maintained": row["rules_maintained"],
         "reason": UNSCANNED_REASON,
         "track": row["track"],
         "labels": row["labels"]}
        for platform, row in sorted(catalog["baselines"].items())
        if platform not in scan_state]
    lacking.extend(row["platform"] for row in unscanned)
    unmet_family_rows = {
        family: {"platforms": sorted(platforms),
                 "rules_unmet": sum(platforms.values())}
        for family, platforms in sorted(unmet_by_family.items())}

    totals = {
        "baselines": len(catalog["baselines"]),
        "baselines_in_scan_state": len(scan_state),
        "covered_rules": covered_total,
        "rules_scanned": rules_scanned,
        "unmet_rules": unmet_total,
        "unscanned_baselines": len(unscanned),
    }
    return {
        "gap_definition": GAP_DEFINITION,
        "families": catalog["families"],
        "baselines": catalog["baselines"],
        "meta": {
            "source": SOURCE,
            "policy": POLICY,
            "registry_note": REGISTRY_NOTE,
            "sources": list(SOURCES),
            "urls_verified": URLS_VERIFIED,
        },
        "gaps": {
            "by_platform": by_platform,
            "lacking_coverage": sorted(lacking),
            "malformed_checklists": [],
            "notes": [
                "baseline row counts are the repo inventory snapshot as "
                "of %s (merged baselines count distinct Vuln_Num per "
                "platform)" % BASELINE_COUNTS_AS_OF,
                "the NET family carries no curated assessment templates "
                "yet - its rules report as unmet capability gaps",
                "the priority queue is the Open/Not_Reviewed fleet "
                "side of covered plus unmet rules, severity-ordered, "
                "capped at %d rows" % MAX_PRIORITY_ROWS,
            ],
            "unmet_by_family": unmet_family_rows,
            "unmatched_checklists": [],
            "unscanned_baselines": unscanned,
        },
        "totals": totals,
    }


def load_scan_state(catalog: dict, paths):
    """CLI-side scan-state ingestion: .ckl files (or directories, all
    their .ckl files recursively) parsed and keyed by resolved platform
    title. Returns (scan_state, unmatched, malformed) - unmatched and
    malformed carry deterministic rows (file basename / given arg, no
    absolute paths) so the report stays machine-independent."""
    scan_state: dict = {}
    unmatched: list = []
    malformed: list = []
    for raw_path in paths:
        path = pathlib.Path(raw_path)
        if path.is_dir():
            files = sorted(p for p in path.rglob("*.ckl"))
        elif path.exists():
            files = [path]
        else:
            malformed.append({"file": raw_path,
                              "error": "scan path not found"})
            continue
        for ckl in files:
            try:
                parsed = parse_ckl(
                    ckl.read_text(encoding="utf-8", errors="replace"))
            except ValueError as exc:
                malformed.append({"file": ckl.name,
                                  "error": str(exc)})
                continue
            platform = resolve_platform(catalog, parsed["stig_title"])
            if platform is None:
                unmatched.append({
                    "stig_title": parsed["stig_title"],
                    "vulns": len(parsed["rules"]),
                    "reason": UNMATCHED_REASON})
                continue
            scan_state[platform] = _collapse_rules(
                scan_state.setdefault(platform, []), parsed["rules"])
    unmatched.sort(key=lambda row: (row["stig_title"], row["vulns"]))
    malformed.sort(key=lambda row: (row["file"], row["error"]))
    return scan_state, unmatched, malformed


def check_url_once(url: str, timeout: int = 20):
    """One polite bounded live check of a single catalog URL.

    Returns the final HTTP status code (after redirects), or an error
    string. Honors 429/Retry-After once (bounded wait), then gives up -
    candidates that fail here are dropped from the curated rows, never
    shipped dead."""
    import time
    import urllib.error
    import urllib.request

    ua = "Mozilla/5.0 (compatible; bedimsecurity-linkcheck/1.0)"
    request = urllib.request.Request(url, headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.getcode()
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            retry = exc.headers.get("Retry-After", "").strip()
            wait = min(int(retry) if retry.isdigit() else 15, 30)
            time.sleep(wait)
            try:
                with urllib.request.urlopen(
                        request, timeout=timeout) as retry_response:
                    return retry_response.getcode()
            except Exception as exc2:
                return type(exc2).__name__ + ": " + str(exc2)[:120]
        return "HTTP %d" % exc.code
    except Exception as exc:
        return type(exc).__name__ + ": " + str(exc)[:120]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scan", action="append", default=[],
                        metavar="PATH",
                        help="fleet scan state: a .ckl file or a "
                             "directory of them (resolved by "
                             "checklist title)")
    parser.add_argument("--out", default=str(OUT),
                        help="report path (default data/"
                             "stig_gap_report.json)")
    parser.add_argument("--live", action="store_true",
                        help="opt-in: verify every catalog url is live "
                             "(HTTP 200); never in CI - drop/replace "
                             "any dead candidate and rebuild offline")
    args = parser.parse_args()

    catalog = build_catalog()

    if args.live:
        urls = [source["url"] for source in SOURCES]
        urls += [row["url"] for entry in catalog["families"].values()
                 for row in entry["templates"]]
        dead = []
        for url in sorted(set(urls)):
            result = check_url_once(url)
            if result != 200:
                dead.append((url, result))
        for (url, result) in dead:
            print("DEAD: %s -> %s" % (url, result))
        print("STIG-GAP-LIVE checked=%d dead=%d"
              % (len(set(urls)), len(dead)))
        return 1 if dead else 0

    scan_state, unmatched, malformed = load_scan_state(
        catalog, args.scan)
    report = gap_report(catalog, scan_state)
    report["gaps"]["unmatched_checklists"] = unmatched
    report["gaps"]["malformed_checklists"] = malformed
    report["totals"]["unmatched_checklists"] = len(unmatched)
    report["totals"]["malformed_checklists"] = len(malformed)

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    totals = report["totals"]
    print("STIG-GAP-OK baselines=%d families=%d scan_state=%d "
          "rules=%d covered=%d unmet=%d out=%s"
          % (totals["baselines"], len(catalog["families"]),
             totals["baselines_in_scan_state"], totals["rules_scanned"],
             totals["covered_rules"], totals["unmet_rules"], out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
