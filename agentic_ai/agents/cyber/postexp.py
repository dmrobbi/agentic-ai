"""PostExploitMixin (KA-044): post-exploitation strategy planning with
an evidence-only policy (no execution).

Adds post-exploitation planning ops to the kali agents. Every op
returns planning data under one shared policy:

- evidence_only: True - every planned step is a read-only discovery or
  reporting question; the captured output is the deliverable.
- mutation_forbidden: True - mutation-class steps (account or service
  changes, registry writes, persistence installation, credential
  dumping, remote execution, log tampering) are refused by the gate op
  with a reason; tests pin that refusal on synthetic plans.

Arcs (aliases in parentheses):
- host-enum (host, system, system-enum) - the foothold enumeration
  strategy on the compromised machine.
- credential-surface (credentials) - where stored credentials LIVE
  (managers, key files, ticket caches, history files): locations and
  labels only, never the contents.
- persistence-discovery (persistence, persistence-audit, audit) - AUDIT
  what persistence already exists (enabled units, cron/task rows,
  startup rows, autorun keys); this mixin never plans persistence
  installation.
- lateral-map (lateral, lateral-movement, mapping) - lateral-movement
  MAPPING as reporting (peers, routes, trusts, share surface); no
  remote-execution step class is planned.

Targets pass the shared scrub helper; when the mixin is composed onto
a host agent the plan also passes that agent's validate_target gate
(silent fallback when the attribute is absent, so standalone mixins
stay usable).

Ops:
- postexp_policy() - the policy rows + the enforced mutation classes
- postexp_arcs() - the arc list with audit/report modes
- postexp_step_catalog(arc=None) - per-arc read-only steps; None = arcs
- postexp_credential_classes() - credential-access class discovery rows
- plan_postexp(target, arc) - the 5-phase evidence-only plan
- classify_postexp_command(command) - one command's evidence/mutation
  class
- postexp_gate(plan) - refuse every mutation-class command in a plan
  dict, allow clean evidence-only plans

All command rows are in-house authoring (short read-only syntax, no
payload strings); nothing external is copied or bundled here.
"""

from __future__ import annotations

from agentic_ai.agents.cyber.web_pentest import wp_scrub_target

POSTEXP_POLICY = {"evidence_only": True, "mutation_forbidden": True}

ARC_ALIASES = {
    "host-enum": ("host", "host-enum", "system", "system-enum"),
    "credential-surface": ("credential-surface", "credentials"),
    "persistence-discovery": ("persistence", "persistence-discovery",
                              "persistence-audit", "audit"),
    "lateral-map": ("lateral", "lateral-map", "lateral-movement", "mapping"),
}

ARC_META = {
    "host-enum": {
        "mode": "audit",
        "purpose": "Foothold enumeration strategy on the compromised machine",
    },
    "credential-surface": {
        "mode": "audit",
        "purpose": "Locate stored-credential surfaces; contents stay sealed",
    },
    "persistence-discovery": {
        "mode": "audit",
        "purpose": "Audit the persistence that exists; install nothing",
    },
    "lateral-map": {
        "mode": "report",
        "purpose": "Map reachable peers, trusts, and shares as a report",
    },
}

POSTEXP_STEPS = {
    "host-enum": (
        ("identity", ("id", "whoami /all", "hostname")),
        ("privilege-context", ("sudo -n -l",)),
        ("services", ("systemctl list-units --type=service --state=running",
                      "sc query")),
        ("network", ("ss -tulpn", "netstat -ano")),
        ("scheduled", ("crontab -l", "schtasks /query /fo LIST")),
        ("artifacts", ("ls -la /tmp /var/tmp 2>/dev/null", "dir %TEMP%")),
    ),
    "credential-surface": (
        ("os-credential-managers", ("cmdkey /list", "vaultcmd /list")),
        ("ssh-key-surfaces", ("ls -la ~/.ssh",
                              "ls -la /home/*/.ssh 2>/dev/null")),
        ("ticket-caches", ("klist", "klist -l")),
        ("history-surfaces", ("ls -l ~/.bash_history 2>/dev/null",)),
    ),
    "persistence-discovery": (
        ("service-audit", ("systemctl list-unit-files --state=enabled",
                           "sc qc")),
        ("task-audit", ("crontab -l", "schtasks /query /fo LIST /v")),
        ("startup-audit", ("ls -la /etc/rc.local /etc/init.d 2>/dev/null",)),
        ("registry-autorun-audit",
         ("reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")),
    ),
    "lateral-map": (
        ("network-context", ("ip -brief addr", "ip route", "route print")),
        ("established-peers", ("ss -tn state established",
                               "netstat -ano | findstr ESTABLISHED")),
        ("trusts-and-suffixes", ("nltest /domain_trusts", "ipconfig /all")),
        ("share-surface", ("net share",)),
    ),
}

CREDENTIAL_CLASSES = {
    "os-credential-managers": {
        "surface": "windows",
        "evidence_role": "location and label rows only; contents stay sealed",
    },
    "ssh-key-surfaces": {
        "surface": "unix",
        "evidence_role": "path and permission rows only; keys never printed",
    },
    "ticket-caches": {
        "surface": "kerberos",
        "evidence_role": "session-ticket listing only; never an export",
    },
    "history-surfaces": {
        "surface": "unix",
        "evidence_role": "presence and size; contents go to the report "
                         "scrubbed or not at all",
    },
}

# The mutation-class table: rule classes in pin order; a substring hit on
# the SPACE-PADDED, casefolded command places it in the class, so tokens
# can carry a leading space and still match at the string boundary. The
# gate refuses the class - it never plans, mutates, or runs anything.
# Read-safe by design: the known mutation FORMS are pinned; loose verbs
# that would also match read commands (a bare nft/kill row, or "del "
# inside "model ") are deliberately absent or space-anchored.
MUTATION_RULES = (
    ("account-mutation", ("useradd", "adduser", "usermod", "net user",
                          "dsadd", "net group", "net localgroup", "/add")),
    ("persistence-install", ("schtasks /create", "schtasks /delete",
                             "sc create", "sc delete", "sc config",
                             "systemctl enable", "systemctl start",
                             "systemctl restart", "crontab -e", "crontab -r",
                             "update-rc.d", " chkconfig ")),
    ("registry-write", ("reg add", "reg delete", "reg load", "reg unload",
                        "reg import")),
    ("package-install", ("apt install", "apt-get install", "yum install",
                         "dnf install", "pip install", "gem install")),
    ("file-mutation", (" >", ">>", " tee ", " rm ", " rmdir ", " del ",
                       " shred ", " mv ", " cp ", " touch ", " install ",
                       " chmod ", " chown ", " truncate ", "dd if=",
                       "ssh-keygen")),
    ("credential-extraction", ("mimikatz", "secretsdump", "lsass", "procdump",
                               "ntdsutil", "hashdump", "cachedump",
                               "pypykatz", "pwdump", "reg save",
                               "vssadmin delete")),
    ("lateral-exec", ("psexec", "smbexec", " winrs ", "wmic /node",
                      "impacket-", "xfreerdp", " mstsc ", " ssh ")),
    ("network-tamper", ("iptables -a", "iptables -d", "iptables -f",
                        "iptables -i ", "iptables -p", "iptables -x",
                        "nft add", "nft delete", "nft flush",
                        "netsh advfirewall", "netsh int", "ip route add",
                        "route add", "arp -s")),
    ("service-kill", ("taskkill", "pkill", "killall", "net stop", "net start",
                      "stop-service", "start-service")),
    ("log-tamper", ("wevtutil cl", "wevtutil /cl", "history -c",
                    "auditpol /clear", "clear-log")),
)

GATE_REJECT_NOTE = ("evidence-only policy: %s work is refused (matched %r); "
                    "re-plan it as a read-only discovery query")


def _arc_for(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("arc must be a non-empty string")
    form = value.strip().lower()
    for canonical, aliases in ARC_ALIASES.items():
        if form in aliases:
            return canonical
    raise ValueError("unknown arc %r - known: credential-surface, host-enum, "
                     "lateral-map, persistence-discovery" % (value,))


def _classify_command(command):
    """One command's (class, matched-token); evidence class has None."""
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string")
    text = command.strip().lower()
    if len(text) > 240:
        raise ValueError("command too long: cap is 240 chars")
    # space-padded so space-anchored tokens match at the boundaries too
    padded = " %s " % (text,)
    for cls, tokens in MUTATION_RULES:
        for tok in tokens:
            if tok in padded:
                return cls, tok
    return "evidence", None


def _phases_for(arc, target, steps):
    """The 5-phase evidence-only arc; every phase carries the policy."""
    boundary = "# evidence boundary: host=%s arc=%s" % (target, arc)
    return [
        {"phase": "1-boundary",
         "goal": "Restate the written scope and record the starting state",
         "activities": [
             "The foothold does not widen the scope; work only what the "
             "engagement names.",
             "Everything below observes and records; it never changes state."],
         "sample_commands": [boundary],
         "policy": dict(POSTEXP_POLICY)},
        {"phase": "2-enumerate",
         "goal": "Run the arc's read-only steps; captured output is evidence",
         "activities": _ENUM_ACTIVITIES[arc],
         "sample_commands": [c for _, cmds in steps for c in cmds],
         "policy": dict(POSTEXP_POLICY)},
        {"phase": "3-evidence",
         "goal": "Turn the captured output into evidence rows",
         "activities": [
             "Hash every captured output into the engagement bundle.",
             "Timestamps and tool rows stay attached to their evidence."],
         "sample_commands": ["# op: evidence bundle (read-only rows only)"],
         "policy": dict(POSTEXP_POLICY)},
        {"phase": "4-detect",
         "goal": "Pair every finding with the defensive view",
         "activities": list(ARC_DETECTION[arc]),
         "sample_commands": ["# op: pair each finding with its detection note"],
         "policy": dict(POSTEXP_POLICY)},
        {"phase": "5-handoff",
         "goal": "Ship the report, not the mutation",
         "activities": [
             "The report carries findings, evidence, and pairing - scrubbed.",
             "postexp_gate(plan) must read allow before anything ships."],
         "sample_commands": ["# op: postexp_gate on this plan; verdict allow"],
         "policy": dict(POSTEXP_POLICY)},
    ]


_ENUM_ACTIVITIES = {
    "host-enum": [
        "Work the identity, privilege, service, network, scheduled, and "
        "artifact steps in order.",
        "Each step's raw output rows into the evidence bundle with its "
        "timestamp."],
    "credential-surface": [
        "Locate every stored-credential surface: managers, key files, ticket "
        "caches, history files.",
        "Locations and labels only; contents never enter the evidence "
        "bundle."],
    "persistence-discovery": [
        "Audit what already exists: enabled units, cron rows, task rows, "
        "startup rows, autorun keys.",
        "The audit is query-only; installing persistence is the opposite of "
        "evidence."],
    "lateral-map": [
        "Map the network context, established peers, trusts, and share "
        "surface.",
        "The map is a set of report rows; remote-exec tooling stays out of "
        "this arc."],
}

ARC_DETECTION = {
    "host-enum": [
        "Enumeration bursts show in Sysmon process rows - the SOC sees the "
        "plan run.",
        "whoami and sudo -l outputs name the real risk: privileged context "
        "on weakly patched state."],
    "credential-surface": [
        "Credential-store access events pair with every credential-surface "
        "query.",
        "Discovery never prints a secret; a dump attempt is a gate refusal "
        "and a SOC alert if anyone runs one."],
    "persistence-discovery": [
        "Enabled units, cron rows, and autorun keys are diffed against the "
        "change baseline.",
        "An audit reads; an install writes - the policy gate refuses the "
        "install class."],
    "lateral-map": [
        "Peer maps and share listings appear in network logs; send the map "
        "to the SOC scrubbed.",
        "Mapping is the deliverable; any remote-exec step class is a gate "
        "refusal."],
}


class PostExploitMixin:
    """Post-exploitation strategy planning with evidence-only policy gates
    (no execution)."""

    def _postexp_guard(self, target):
        """Scrub + consult the host agent's target gate when it provides one."""
        t = wp_scrub_target(target)
        gate = getattr(self, "validate_target", None)
        if callable(gate):
            ok, msg = gate(t)
            if not ok:
                raise ValueError("target rejected by host agent gate: %s" % msg)
        return t

    def postexp_policy(self) -> dict:
        """The evidence-only policy rows plus the enforced mutation classes."""
        return {"policy": dict(POSTEXP_POLICY),
                "forbidden_classes": [cls for cls, _ in MUTATION_RULES],
                "doc": [
                    "Every output row is evidence; the mixin plans "
                    "discovery, never mutation.",
                    "Persistence = audit what exists; lateral = map and "
                    "report; credential = locate surfaces."],
                }

    def postexp_arcs(self) -> dict:
        """The planning arcs with their audit/report modes (no execution)."""
        arcs = sorted(ARC_ALIASES)
        return {"arcs": arcs,
                "modes": {a: ARC_META[a]["mode"] for a in arcs},
                "policy": dict(POSTEXP_POLICY)}

    def postexp_step_catalog(self, arc=None) -> dict:
        """Per-arc read-only enumeration steps; None returns the arc list."""
        if arc is None:
            return {"arcs": sorted(ARC_ALIASES),
                    "policy": dict(POSTEXP_POLICY)}
        canonical = _arc_for(arc)
        return {"arc": canonical,
                "mode": ARC_META[canonical]["mode"],
                "policy": dict(POSTEXP_POLICY),
                "steps": [{"step": name, "commands": list(cmds)}
                          for name, cmds in POSTEXP_STEPS[canonical]]}

    def postexp_credential_classes(self) -> dict:
        """Credential-access class discovery rows (locations only, never
        contents)."""
        rows = {}
        for name, cmds in POSTEXP_STEPS["credential-surface"]:
            meta = CREDENTIAL_CLASSES[name]
            rows[name] = {"surface": meta["surface"],
                          "discovery_commands": list(cmds),
                          "evidence_role": meta["evidence_role"],
                          "policy": dict(POSTEXP_POLICY)}
        return {"classes": rows, "policy": dict(POSTEXP_POLICY)}

    def plan_postexp(self, target, arc):
        """The 5-phase evidence-only post-exploitation plan for a target."""
        t = self._postexp_guard(target)
        canonical = _arc_for(arc)
        return {"target": t,
                "arc": canonical,
                "meta": dict(ARC_META[canonical]),
                "policy": dict(POSTEXP_POLICY),
                "phases": _phases_for(canonical, t,
                                      POSTEXP_STEPS[canonical])}

    def classify_postexp_command(self, command):
        """Classify one command as evidence or as a forbidden mutation class."""
        cls, tok = _classify_command(command)
        return {"command": command, "class": cls, "matched": tok,
                "verdict": "allow" if cls == "evidence" else "refuse",
                "policy": dict(POSTEXP_POLICY)}

    def postexp_gate(self, plan):
        """Gate a plan dict: refuse every mutation-class command, allow
        evidence-only plans."""
        if not isinstance(plan, dict):
            raise ValueError("plan must be a dict with a steps or phases list")
        entries = plan.get("steps") if plan.get("steps") is not None \
            else plan.get("phases")
        if not isinstance(entries, list) or not entries:
            raise ValueError("plan needs a non-empty steps or phases list")
        checked = 0
        refused = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("every plan step must be a dict with a "
                                 "commands list")
            name = entry.get("step", entry.get("phase"))
            if not isinstance(name, str) or not name.strip():
                raise ValueError("every plan step needs a name (step or "
                                 "phase key)")
            raw = entry.get("commands", entry.get("sample_commands"))
            if not isinstance(raw, list) or not raw:
                raise ValueError("plan step %r needs a non-empty commands "
                                 "list" % (name,))
            for cmd in raw:
                cls, tok = _classify_command(cmd)
                checked += 1
                if cls != "evidence":
                    refused.append({"step": name, "command": cmd,
                                    "class": cls,
                                    "reason": GATE_REJECT_NOTE % (cls, tok)})
        return {"policy": dict(POSTEXP_POLICY),
                "verdict": "refuse" if refused else "allow",
                "checked": checked,
                "refused_count": len(refused),
                "refused": refused}