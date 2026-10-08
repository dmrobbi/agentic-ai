#!/usr/bin/env python3
"""Build agentic_ai/agents/cyber/data/cve_dossiers.json - the defensive
halves of the two confirmed-real CVE workspaces carried inside the
removed kaliagent-v4 leftover directory (KA merge A2, 2026-10-08, the
owner's merge order after the dead-generation removal).

SOURCES (git history commit c965747, kaliagent-v4/vulns/...): the
analysis, affected-surface, mitigation, and detection artifacts of
CVE-2026-41089 (Windows Netlogon CLDAP stack overflow, CVSS 9.8 -
verified real via Rapid7, CERT-EU advisory 2026-007, Securonix) and
CVE-2026-46243 (CIFSwitch, Linux CIFS client LPE, CVSS 7.8 - verified
real via oss-security, Red Hat RHSB-2026-005, the Ubuntu CVE tracker).

Content is RE-AUTHORED: dossier rows distill the defensive methodology
(what is affected, how to detect, how to mitigate) - never PoC or
exploit content, which stays in git history only, per the catalog-data
policy; PoC repository links carry as links per the house
names+links+purposes rule.

Usage:
  python tools/build_cve_dossiers.py            (build)
  python tools/build_cve_dossiers.py --verify   (rebuild + byte-compare
      against the committed file; prints KALI-DOSSIERS-VERIFY-OK and
      exits 0 on match, non-zero otherwise)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT = (REPO_ROOT / "agentic_ai" / "agents" / "cyber" / "data"
       / "cve_dossiers.json")

FIELDS = {
    "affected", "cwe", "cvss", "detection", "links", "mitigation",
    "one_liner", "patch", "product", "provenance", "published", "summary",
}
SURFACES = {"suricata", "yara", "shell"}
EXPECTED_IDS = {"CVE-2026-41089", "CVE-2026-46243"}

DV_41089 = {
    "cvss": 9.8,
    "published": "2026-05-12",
    "product": "Windows Netlogon (domain-controller role only)",
    "cwe": "CWE-121 stack-based buffer overflow; CWE-120 buffer copy "
           "without checking size",
    "one_liner": "One unauthenticated CLDAP packet crashes LSASS on a "
                 "vulnerable domain controller (pre-auth RCE/DoS).",
    "summary": (
        "Byte-vs-WCHAR size confusion in netlogon.dll's "
        "NetpLogonPutUnicodeString: the copy loop applies a WCHAR-count "
        "max_chars budget to sources while writing into a ~528-byte "
        "stack buffer inside BuildSamLogonResponse with no destination "
        "bound check. One crafted UDP 389 DC-locator SearchRequest "
        "carrying an oversized User attribute overflows the buffer; "
        "LSASS crashes and the DC reboots ~60 seconds later. Remote "
        "code execution is theoretically possible but not demonstrated "
        "by the public PoC. Field status: actively exploited "
        "(Securonix, June 2026); CERT-EU advisory 2026-007 (October "
        "2026); not in the KEV catalog."),
    "affected": [
        "Windows Server 2025 / 2022 (incl. 23H2) / 2019 / 2016: "
        "pre-May-2026-patch builds, DC role only",
        "Windows Server 2012 / 2012 R2: ESU-only patches",
        "Windows Server 2008 R2 and unpatched 2012 tiers: end of life "
        "(0patch micropatch route)",
        "Workstations and member servers are NOT exploitable: the "
        "CLDAP DC-locator handler is DC-only",
    ],
    "patch": "KB5089549 (May 2026 Patch Tuesday; feature flag "
             "Feature_404993339)",
    "detection": [
        {
            "surface": "suricata",
            "what": "four alert rules (SIDs 2026041089-2026041092): "
                    "oversized User attribute in CLDAP DC-locator pings "
                    "(>=100 B and >=130 B grades), the NtVer=\\x02 "
                    "non-EX exploit path, and threshold-gated DC pings "
                    "from non-domain sources",
            "artifact": "kaliagent-v4/vulns/CVE-2026-41089/"
                        "detect_suricata.rules @ c965747",
        },
        {
            "surface": "yara",
            "what": "matches the VULNERABLE netlogon.dll: the unbounded "
                    "NetpLogonPutUnicodeString copy-loop byte pattern "
                    "plus its consecutive unbounded calls in "
                    "BuildSamLogonResponse (patched builds call "
                    "RtlStringCbCopyExW instead)",
            "artifact": "kaliagent-v4/vulns/CVE-2026-41089/"
                        "detect_yara.yar @ c965747",
        },
    ],
    "mitigation": [
        "Apply KB5089549 (May 2026 Patch Tuesday) to every domain "
        "controller",
        "Block inbound UDP 389 (CLDAP) from untrusted sources at the "
        "perimeter; on DCs allow CLDAP only from management and "
        "domain-joined subnets",
        "For end-of-life Windows (2008 R2 / 2012 tiers): the 0patch "
        "micropatch bounds the copy loop (single-instruction fix)",
    ],
    "links": {
        "nvd": "https://nvd.nist.gov/vuln/detail/CVE-2026-41089",
        "rapid7": "https://www.rapid7.com/db/vulnerabilities/"
                  "cve-2026-41089/",
        "cert_eu": "https://cert.europa.eu/publications/"
                   "security-advisories/2026-007",
        "kaluche_research": "https://kaluche.github.io/research/msrc/"
                            "2026-05/cve-2026-41089/",
        "securonix_active_exploit": "https://connect.securonix.com/"
                                    "threat-research-intelligence-62/"
                                    "cve-2026-41089-windows-netlogon-"
                                    "cldap-stack-overflow-now-actively-"
                                    "exploited-351",
        "opencve": "https://app.opencve.io/cve/CVE-2026-41089",
        "0patch": "https://0patch.com/blog/micropatches-released-for-"
                  "windows-netlogon-remote-code-execution-vulnerability"
                  "-cv",
    },
    "provenance": "defensive halves re-authored from the removed "
                  "kaliagent-v4/vulns/CVE-2026-41089 workspace (git "
                  "history c965747); PoC/exploit files stay in history "
                  "untranspiled (catalog policy)",
}

DV_46243 = {
    "cvss": 7.8,
    "published": "2026-05-28",
    "product": "Linux kernel CIFS client + cifs-utils upcall (local "
               "privilege escalation)",
    "cwe": "kernel keyrings cifs.spnego key description missing origin "
           "validation (.vet_description)",
    "one_liner": "A 19-year-old CIFS keyring logic bug: forged key "
                 "descriptions run the root cifs.upcall and load an "
                 "attacker NSS module before the privilege drop.",
    "summary": (
        "The kernel's cifs.spnego key type shipped without "
        ".vet_description, so any unprivileged user can request_key a "
        "forged key description; /sbin/request-key then runs cifs."
        "upcall as root; the helper parses attacker-supplied pid/uid/"
        "upcall_target fields, switches into the attacker's mount "
        "namespace, and getpwuid(0) triggers an NSS lookup that loads "
        "an attacker-controlled NSS module BEFORE the privilege drop - "
        "ending in local root. The bug dates to ~2007 (19 years). "
        "Coordinated disclosure May 27-28, 2026 (oss-security, "
        "manizada); Red Hat RHSB-2026-005; the mainline fix is kernel "
        "commit 3da1fdf4efbc (smb: client: reject userspace cifs."
        "spnego descriptions)."),
    "affected": [
        "Any Linux system with cifs-utils and unprivileged user "
        "namespaces on a pre-fix kernel (mainline 6.12+; distro "
        "backports required below)",
        "Stock-exploitable: Linux Mint 21.3/22.3, CentOS Stream 9, "
        "Rocky Linux 9 Workstation, AlmaLinux 9.7, SLES 15 SP7 / SAP "
        "15 SP7 / SLES SAP 16, Kali 2021.4-2026.1 headless",
        "Exploitable if cifs-utils is installed: Ubuntu 18.04/20.04/"
        "22.04 (24.04 blocked by default AppArmor userns), Debian "
        "11/12/13, Pop!_OS 22.04/24.04, openSUSE Leap 15.6, Rocky "
        "Linux 8 GenericCloud, Oracle Linux 8/9 KVM, Amazon Linux "
        "2023 KVM (SELinux permissive)",
    ],
    "patch": "kernel commit 3da1fdf4efbc (smb: client: reject "
             "userspace cifs.spnego descriptions); distro kernels need "
             "the backport",
    "detection": [
        {
            "surface": "shell",
            "what": "user-runnable host exposure check (no root "
                    "required): kernel < 6.12 rough grade, cifs-utils "
                    "presence, the /etc/request-key.d cifs.spnego rule "
                    "state, unprivileged-userns policy; exit 0 = not "
                    "vulnerable, 1 = likely vulnerable, 2 = manual "
                    "verification needed",
            "artifact": "kaliagent-v4/vulns/CVE-2026-46243/detect.sh "
                        "@ c965747",
        },
    ],
    "mitigation": [
        "Install the fixed kernel (the 3da1fdf4efbc backport) via the "
        "distro update path",
        "Negate the cifs.spnego request-key rule (the keyctl negate "
        "route) until patched",
        "Block the cifs kernel module (modprobe blacklist) where CIFS "
        "mounts are unnecessary",
        "Disable unprivileged user namespaces (the distro sysctl; "
        "mitigate.sh --disable-userns)",
        "mitigate.sh automates the config mitigations with backup/"
        "status/remove modes",
    ],
    "links": {
        "oss_security": "https://www.openwall.com/lists/oss-security/"
                        "2026/05/28/2",
        "red_hat_rhsb": "https://access.redhat.com/security/"
                        "vulnerabilities/RHSB-2026-005",
        "ubuntu": "https://ubuntu.com/security/CVE-2026-46243",
        "kernel_commit": "https://github.com/torvalds/linux/commit/"
                         "3da1fdf4efbc490041eb4f836bf596201203f8f2",
        "poc_repo": "https://github.com/manizada/CIFSwitch",
        "writeup": "https://heyitsas.im/posts/cifswitch/",
    },
    "provenance": "defensive halves re-authored from the removed "
                  "kaliagent-v4/vulns/CVE-2026-46243 workspace (git "
                  "history c965747); PoC/exploit files stay in history "
                  "untranspiled (catalog policy)",
}

DOSSIERS = {
    "CVE-2026-41089": DV_41089,
    "CVE-2026-46243": DV_46243,
}


def validate(db: dict) -> None:
    if not isinstance(db, dict) or set(db) != EXPECTED_IDS:
        raise SystemExit(
            "expected exactly the dossiers %s" % sorted(EXPECTED_IDS))
    for key, row in db.items():
        if not isinstance(row, dict) or set(row) != FIELDS:
            raise SystemExit(
                "dossier %s does not carry exactly %s"
                % (key, sorted(FIELDS)))
        if (isinstance(row["cvss"], bool)
                or not isinstance(row["cvss"], (int, float))
                or not 0 <= row["cvss"] <= 10):
            raise SystemExit("dossier %s cvss not in [0, 10]" % key)
        for field in ("published", "product", "cwe", "one_liner",
                      "summary", "patch", "provenance"):
            if not isinstance(row[field], str) or not row[field].strip():
                raise SystemExit(
                    "dossier %s field %r is not a non-blank string"
                    % (key, field))
        for field in ("affected", "mitigation"):
            if (not isinstance(row[field], list) or not row[field]
                    or not all(isinstance(x, str) and x.strip()
                               for x in row[field])):
                raise SystemExit(
                    "dossier %s %s is not a non-empty string list"
                    % (key, field))
        dets = row["detection"]
        if not isinstance(dets, list) or not dets:
            raise SystemExit(
                "dossier %s detection is empty" % key)
        for det in dets:
            if not isinstance(det, dict) or set(det) != {
                    "surface", "what", "artifact"}:
                raise SystemExit(
                    "dossier %s detection row malformed" % key)
            if det["surface"] not in SURFACES:
                raise SystemExit(
                    "dossier %s detection surface %r unknown"
                    % (key, det["surface"]))
            if (not det["what"].strip() or not det["artifact"].strip()):
                raise SystemExit(
                    "dossier %s detection row has blank text" % key)
        links = row["links"]
        if not isinstance(links, dict) or not 1 <= len(links) <= 25:
            raise SystemExit(
                "dossier %s links must number 1-25" % key)
        for name, url in links.items():
            if (not isinstance(name, str) or not name.strip()
                    or not isinstance(url, str)
                    or not url.startswith("https://")):
                raise SystemExit(
                    "dossier %s link %r malformed" % (key, name))


def render(db: dict) -> str:
    return json.dumps(db, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    argv = sys.argv[1:]
    db = DOSSIERS
    validate(db)
    text = render(db)
    if argv == ["--verify"]:
        current = (OUT.read_text(encoding="utf-8")
                   if OUT.exists() else None)
        if current == text:
            print("KALI-DOSSIERS-VERIFY-OK")
            return 0
        print("KALI-DOSSIERS-VERIFY-DIFF", file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print("KALI-DOSSIERS-BUILT %d dossiers -> %s" % (len(db), OUT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
