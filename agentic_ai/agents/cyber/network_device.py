"""NetworkDeviceMixin (KA-040): router/switch/firewall enum planners +
vendor config-audit catalogs (no execution; lab-only policy).

Policy: lab_only True - device-audit work exists for the owner's lab
network rigs; nothing here targets a production device. plan_only True -
the ops emit step/checklist text; any future execution stays behind the
chassis gates + a human review. no_device_connections True - the
planners never build an addressed/credentialed device session; configs
arrive as synthetic or exported TEXT that audit_config reads offline
(no file, bus, or device I/O in this module).

Kinds: router (aliases rtr), switch (sw), firewall (fw, ngfw). Unknown
kinds raise ValueError naming the known ones.
Vendors: cisco-ios (cisco, ios), juniper-junos (juniper, junos),
paloalto-panos (paloalto, panos), fortinet-fortigate (fortinet,
fortigate, fortios). Unknown vendors raise ValueError naming the known
ones.

The enum command sets are read-only show-class templates in a
cisco-style baseline; translate them to the device vendor's CLI. The
config-audit rule rows are authored in-house from operator knowledge of
the vendors' hardened-CLI practice - never verbatim from any external
guide - and are starter rows: grow them by editing the rule constants.
The audit match is a lowercase regex run per config line (heuristic
substring anchors, not a parser; lab configs, lab verdicts).

Ops:
- plan_device_audit(device_label, kind) - the 6-phase lab audit arc
- device_index() - the kind/vendor list + the lab policy rows
- device_enum_catalog(kind=None) - the per-kind enum command sets
- config_audit_rules(vendor=None) - the vendor's curated rule rows
- audit_config(config_text, vendor) - the offline scan of a synthetic
  or exported config text against that vendor's rule rows
"""

from __future__ import annotations

import re

from agentic_ai.agents.cyber.web_pentest import wp_scrub_target

DEVICE_POLICY = {"lab_only": True, "plan_only": True,
                 "no_device_connections": True}

DEVICE_KINDS = {"router": ("router", "rtr"),
                "switch": ("switch", "sw"),
                "firewall": ("firewall", "fw", "ngfw")}

VENDORS = {"cisco-ios": ("cisco-ios", "cisco", "ios"),
           "juniper-junos": ("juniper-junos", "juniper", "junos"),
           "paloalto-panos": ("paloalto-panos", "paloalto", "panos"),
           "fortinet-fortigate": ("fortinet-fortigate", "fortinet",
                                  "fortigate", "fortios")}

ENUM_STEPS = {
    "router": (
        ("identity", ("show version",)),
        ("interfaces", ("show ip interface brief",)),
        ("routing", ("show ip route summary", "show ip protocols summary")),
        ("management", ("show running-config", "show logging")),
    ),
    "switch": (
        ("identity", ("show version",)),
        ("vlans", ("show vlan brief",)),
        ("spanning-tree", ("show spanning-tree summary",)),
        ("ports", ("show mac address-table", "show interfaces status",
                   "show port-security")),
    ),
    "firewall": (
        ("identity", ("show version",)),
        ("interfaces", ("show interface ip brief", "show nameif")),
        ("policies", ("show running-config access-group",
                      "show running-config nat")),
        ("sessions", ("show conn count",)),
    ),
}

CISCO_IOS_RULES = (
    {"id": "cisco-ios-auth-01",
     "check": "an enable secret is configured",
     "family": "auth", "severity": "high", "mode": "require",
     "match": "enable secret",
     "finding": "no enable secret in the config - privileged mode is unguarded",
     "remediation": "set an enable secret (hashed; not a cleartext enable password)",
     "detection": "config-watch: edits to the privileged-secret lines"},
    {"id": "cisco-ios-auth-02",
     "check": "telnet is closed on the vty lines",
     "family": "auth", "severity": "high", "mode": "flag",
     "match": "transport input telnet",
     "finding": "vty lines accept telnet sessions - cleartext management",
     "remediation": "transport input ssh; drop the telnet acceptance",
     "detection": "mgmt-plane watch: telnet accepts into network devices"},
    {"id": "cisco-ios-mgmt-01",
     "check": "the legacy http management plane is closed",
     "family": "mgmt-plane", "severity": "high", "mode": "flag",
     "match": r"^\s*ip http server\b",
     "finding": "the legacy http server is on - unencrypted management plane",
     "remediation": "no ip http server; https-only where a web plane is required",
     "detection": "mgmt-plane watch: plaintext http to device control ports"},
    {"id": "cisco-ios-mgmt-02",
     "check": "snmp community strings are not the factory defaults",
     "family": "mgmt-plane", "severity": "high", "mode": "flag",
     "match": "snmp-server community public",
     "finding": "the factory read-only snmp community is configured",
     "remediation": "rotate to unique strings or snmpv3 auth+priv views",
     "detection": "network watch: snmp walk patterns sweeping devices"},
    {"id": "cisco-ios-mgmt-03",
     "check": "no factory read-write snmp community",
     "family": "mgmt-plane", "severity": "high", "mode": "flag",
     "match": "snmp-server community private",
     "finding": "the factory read-write snmp community is configured",
     "remediation": "remove the rw community; snmpv3 only",
     "detection": "network watch: snmp set patterns against devices"},
    {"id": "cisco-ios-audit-01",
     "check": "a syslog collector is configured",
     "family": "logging", "severity": "medium", "mode": "require",
     "match": "logging host",
     "finding": "no syslog target in the config - device events stay local",
     "remediation": "logging host <lab collector>; set the baseline levels",
     "detection": "log-pipeline watch: device sources that stopped feeding"},
)

JUNIPER_JUNOS_RULES = (
    {"id": "juniper-junos-auth-01",
     "check": "root authentication is configured",
     "family": "auth", "severity": "high", "mode": "require",
     "match": "set system root-authentication",
     "finding": "no root-authentication stanza - the root account is unconfigured or open",
     "remediation": "set system root-authentication with a hashed secret",
     "detection": "auth watch: root logins without the baseline hash"},
    {"id": "juniper-junos-auth-02",
     "check": "the telnet service is off",
     "family": "auth", "severity": "high", "mode": "flag",
     "match": "set system services telnet",
     "finding": "the telnet service is enabled - cleartext management",
     "remediation": "delete system services telnet; ssh only",
     "detection": "mgmt-plane watch: telnet accepts into network devices"},
    {"id": "juniper-junos-mgmt-01",
     "check": "the http web plane is off",
     "family": "mgmt-plane", "severity": "medium", "mode": "flag",
     "match": r"set system services web-management http\b",
     "finding": "j-web over plaintext http is enabled",
     "remediation": "web-management https only; system services http off",
     "detection": "mgmt-plane watch: plaintext http to the j-web port"},
    {"id": "juniper-junos-mgmt-02",
     "check": "snmp community strings are not the factory defaults",
     "family": "mgmt-plane", "severity": "high", "mode": "flag",
     "match": "set snmp community public",
     "finding": "the factory snmp community is configured",
     "remediation": "rotate communities or move to snmpv3",
     "detection": "network watch: snmp walk patterns sweeping devices"},
    {"id": "juniper-junos-audit-01",
     "check": "a time source is configured",
     "family": "logging", "severity": "medium", "mode": "require",
     "match": "set system ntp",
     "finding": "no ntp stanza - audit timestamps have no clock anchor",
     "remediation": "set system ntp server <lab time source>",
     "detection": "log-pipeline watch: device logs with drifting timestamps"},
)

PALOALTO_PANOS_RULES = (
    {"id": "paloalto-panos-auth-01",
     "check": "an admin password-complexity policy is configured",
     "family": "auth", "severity": "high", "mode": "require",
     "match": "password-complexity",
     "finding": "no password-complexity block - short admin passwords accepted",
     "remediation": "set the device's password-complexity block per baseline",
     "detection": "auth watch: admin logins that pass weak-credential checks"},
    {"id": "paloalto-panos-mgmt-01",
     "check": "the telnet management service is off",
     "family": "mgmt-plane", "severity": "high", "mode": "flag",
     "match": r"system service telnet\b",
     "finding": "telnet is enabled on the management plane",
     "remediation": "system service ssh-only; drop telnet",
     "detection": "mgmt-plane watch: telnet accepts into network devices"},
    {"id": "paloalto-panos-mgmt-02",
     "check": "the plaintext http management service is off",
     "family": "mgmt-plane", "severity": "medium", "mode": "flag",
     "match": r"system service http\b",
     "finding": "the plaintext http management service is enabled",
     "remediation": "https-only management; delete the http service row",
     "detection": "mgmt-plane watch: plaintext http to the management web port"},
    {"id": "paloalto-panos-policy-01",
     "check": "no any-any security rule",
     "family": "policy", "severity": "high", "mode": "flag",
     "match": r"\bany\b.*\bany\b",
     "finding": "a security rule permits any source/destination/service",
     "remediation": "replace with zone/app-scoped rules; default-deny",
     "detection": "policy watch: traffic passing the catch-all rule"},
)

FORTINET_FORTIGATE_RULES = (
    {"id": "fortinet-fortigate-mgmt-01",
     "check": "the admin trusted-host is not all hosts",
     "family": "mgmt-plane", "severity": "high", "mode": "flag",
     "match": r"trusthost1 0\.0\.0\.0 0\.0\.0\.0",
     "finding": "the admin trusted-host allows every address",
     "remediation": "pin the trusthost rows to the lab mgt net",
     "detection": "auth watch: admin logins from unplanned addresses"},
    {"id": "fortinet-fortigate-auth-01",
     "check": "an admin passwd-policy is configured",
     "family": "auth", "severity": "high", "mode": "require",
     "match": "passwd-policy",
     "finding": "no passwd-policy block - weak admin passwords accepted",
     "remediation": "set the passwd-policy rows per baseline",
     "detection": "auth watch: admin logins that pass weak-credential checks"},
    {"id": "fortinet-fortigate-mgmt-02",
     "check": "snmp community names are not the factory defaults",
     "family": "mgmt-plane", "severity": "high", "mode": "flag",
     "match": 'set name "public"',
     "finding": "the factory snmp community name is configured",
     "remediation": "rename or remove the community; snmpv3 preferred",
     "detection": "network watch: snmp walk patterns sweeping devices"},
    {"id": "fortinet-fortigate-audit-01",
     "check": "the syslog stanza is configured",
     "family": "logging", "severity": "medium", "mode": "require",
     "match": "config log syslogd",
     "finding": "no syslog stanza - device events stay local",
     "remediation": "configure the syslogd block to the lab collector",
     "detection": "log-pipeline watch: device sources that stopped feeding"},
)

RULE_CATALOG = {"cisco-ios": CISCO_IOS_RULES,
                "juniper-junos": JUNIPER_JUNOS_RULES,
                "paloalto-panos": PALOALTO_PANOS_RULES,
                "fortinet-fortigate": FORTINET_FORTIGATE_RULES}

DEVICE_AUDIT_PLAN = (
    ("1-authorize", "The lab boundary in writing",
     ["Confirm the written authorization: the lab network rig only.",
      "Record the inventory row (label, vendor, kind, firmware).",
      "No production network device is ever in this arc."],
     ["# authorization: lab-only; device = {device_label} ({kind})"]),

    ("2-enum", "Read-only surface walk",
     ["Run the kind's enum command set; capture the outputs as evidence.",
      "Nothing here mutates: show-class text only."],
     ["# op: device_enum_catalog('{kind}')"]),

    ("3-capture", "Config snapshot via the permitted read-only channel",
     ["Export the running-config through the lab channel the owner allows.",
      "Mask the secrets before the text leaves the rig; store the snapshot."],
     ["show running-config  # via the lab console session to {device_label}"]),

    ("4-audit", "Offline rule-row scan",
     ["Run audit_config over the snapshot with the site's vendor.",
      "Every finding = its rule row's severity + family."],
     ["# op: audit_config('<snapshot>', vendor=pick via device_index())"]),

    ("5-remediate", "Fix the rule rows, one change at a time",
     ["Apply each finding's remediation row; re-audit until clean.",
      "Keep the before/after snapshots; no bulk config pushes."],
     ["# per finding: remediation row + a fresh audit_config run"]),

    ("6-report", "Findings + the SOC pairing",
     ["Pair every finding with the rule row's detection note.",
      "Scrub the report before it leaves the machine."],
     ["# report: rule-row findings + detection notes; scrubbed"]),
)


def _kind_for(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("device kind must be a non-empty string")
    form = value.strip().lower()
    for canonical, aliases in DEVICE_KINDS.items():
        if form in aliases:
            return canonical
    raise ValueError("unknown device kind %r - known: router, switch, "
                     "firewall" % (value,))


def _vendor_for(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("vendor must be a non-empty string")
    form = value.strip().lower()
    for canonical, aliases in VENDORS.items():
        if form in aliases:
            return canonical
    raise ValueError("unknown vendor %r - known: cisco-ios, "
                     "fortinet-fortigate, juniper-junos, paloalto-panos"
                     % (value,))


def nd_scrub_config(config_text):
    """Validate + normalize an offline config text: a bounded string,
    newline-normalized, control characters refused (the audit reads the
    text; it never carries any command out of here)."""
    if not isinstance(config_text, str) or not config_text.strip():
        raise ValueError("config_text must be a non-empty string")
    if len(config_text) > 20000:
        raise ValueError("config_text too large (<= 20000 chars)")
    text = config_text.replace("\r\n", "\n").replace("\r", "\n")
    for ch in text:
        code = ord(ch)
        if code in (9, 10):
            continue
        if code < 32 or code == 127:
            raise ValueError("rejected config_text with control characters")
    if text.count("\n") + 1 > 2000:
        raise ValueError("config_text too large (<= 2000 lines)")
    return text


class NetworkDeviceMixin:
    """Network-device audit planning ops (no execution; lab-only)."""

    def device_index(self) -> dict:
        """The kind/vendor list + the lab policy rows."""
        return {"kinds": sorted(DEVICE_KINDS), "vendors": sorted(VENDORS),
                "policy": dict(DEVICE_POLICY)}

    @staticmethod
    def _nd_scrub_config(config_text):
        """Validate + normalize an offline config text (shared helper)."""
        return nd_scrub_config(config_text)

    def _nd_guard(self, device_label):
        """Scrub the device label; consult the host agent's target gate
        when it provides one (silent fallback)."""
        t = wp_scrub_target(device_label)
        gate = getattr(self, "validate_target", None)
        if callable(gate):
            ok, msg = gate(t)
            if not ok:
                raise ValueError("device rejected by host agent gate: %s"
                                 % msg)
        return t

    def plan_device_audit(self, device_label, kind):
        """The 6-phase lab audit arc for a network device."""
        t = self._nd_guard(device_label)
        canonical = _kind_for(kind)
        phases = []
        for pid, goal, acts, cmds in DEVICE_AUDIT_PLAN:
            phases.append({"phase": pid, "goal": goal,
                           "activities": list(acts),
                           "sample_commands": [
                               c.replace("{device_label}", t)
                                .replace("{kind}", canonical)
                               for c in cmds],
                           "policy": dict(DEVICE_POLICY)})
        return {"device": t, "kind": canonical,
                "policy": dict(DEVICE_POLICY), "phases": phases}

    def device_enum_catalog(self, kind=None):
        """The per-kind enum command set (None lists the kinds)."""
        if kind is None:
            return {"kinds": sorted(DEVICE_KINDS),
                    "policy": dict(DEVICE_POLICY)}
        canonical = _kind_for(kind)
        return {"kind": canonical, "policy": dict(DEVICE_POLICY),
                "note": ("cisco-style read-only baseline; translate to the "
                         "device vendor's CLI"),
                "steps": [{"step": step, "commands": list(cmds)}
                          for step, cmds in ENUM_STEPS[canonical]]}

    def config_audit_rules(self, vendor=None):
        """The vendor's curated config-audit rule rows (None lists the
        vendors)."""
        if vendor is None:
            return {"vendors": sorted(VENDORS),
                    "policy": dict(DEVICE_POLICY)}
        canonical = _vendor_for(vendor)
        return {"vendor": canonical, "policy": dict(DEVICE_POLICY),
                "rules": [dict(row) for row in RULE_CATALOG[canonical]]}

    def audit_config(self, config_text, vendor):
        """Offline scan of a config text against the vendor's rule rows."""
        text = self._nd_scrub_config(config_text)
        canonical = _vendor_for(vendor)
        lines = text.split("\n")
        findings = []
        for row in RULE_CATALOG[canonical]:
            hits = [(n, line.strip()) for n, line in enumerate(lines, 1)
                    if re.search(row["match"], line.lower())]
            if row["mode"] == "flag":
                if not hits:
                    continue
            elif hits:  # require mode: any match satisfies the check
                continue
            matches = [{"line": n, "text": strip[:80]}
                       for n, strip in hits[:3]]
            finding = {"rule_id": row["id"], "check": row["check"],
                       "family": row["family"], "severity": row["severity"],
                       "finding": row["finding"],
                       "remediation": row["remediation"],
                       "detection": row["detection"],
                       "matches": matches, "match_count": len(hits)}
            findings.append(finding)
        by_severity = {}
        for f in findings:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        return {"vendor": canonical, "policy": dict(DEVICE_POLICY),
                "findings": findings,
                "summary": {"rules": len(RULE_CATALOG[canonical]),
                            "findings": len(findings), "lines": len(lines),
                            "by_severity": by_severity,
                            "clean": not findings}}
