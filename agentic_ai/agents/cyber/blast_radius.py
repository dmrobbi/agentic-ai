"""Blast-radius classifier (KA-053): tags operator-proposed commands with
a blast-radius class plus the authorization tier that class requires.

Contract:
- `classify(command)` reads ONE untrusted external string - a proposed
  single shell command - and returns a frozen CommandClassification
  carrying the tag (`read` / `scan` / `exploit-class`) and the mapped
  authorization requirement. Nothing here executes; it is a planner.
- Classes, weakest to strongest (BLAST_CLASSES):
    read          single-record lookups and observation; the command
                  sends no target-affecting traffic beyond a lookup.
    scan          active probing/enumeration of a target surface
                  (network probes, service/content sweeps, capture).
    exploit-class anything that drives payloads, credential attacks,
                  remote execution, rogue servers, floods, spoofing,
                  or writes to the target.
- Authorization requirement mapping (chassis RBAC levels, KA-051
  semantics; the module imports NOTHING from the package):
    read          -> required level 1 (basic)   : every executable role
    scan          -> required level 2 (advanced): observer roles denied
    exploit-class -> required level 3 (critical) AND lab staging required
  REQUIRED_LEVELS/REQUIRED_LEVEL_NAMES carry the ints/names;
  STAGING_CLASSES lists classes that additionally require lab staging
  (`staging_required=True` on the classification).
- Fail-closed: a program that is not catalogued - shells, interpreters,
  privilege runners (sudo/su/doas), netcat, anything unknown -
  classifies as `exploit-class`. Over-tagging (a read/scan command
  whose arguments contain attack keywords) is acceptable; under-tagging
  is never acceptable, so keyword matches only ever RAISE the class.
- Escalation keywords always yield `exploit-class`; they are scanned in
  pinned order and the first match wins the reported rule string:
    1. global whole-token matches (tokens in left-to-right order;
       method words match case-insensitively),
    2. global case-insensitive substring matches (constant list order),
    3. per-tool whole-token matches (case-SENSITIVE: -F/-T are curl's
       upload flags, while curl -f is --fail and must not escalate),
    4. per-tool case-insensitive substring matches.
  With no escalation, the catalog lookup on the program token decides;
  a program missing from the catalog is the fail-closed case above.
- Rule (evidence) strings, deterministic and pinned:
    program:<program>   catalog match on the program token
    unknown:<program>   fail-closed uncatalogued program
    keyword:<kw>        global token/substring escalation
    tool:<program>:<flag|substring>
- Acceptance of the external string (ValueError, pinned messages):
  must be a str; no control characters (below 0x20 or 0x7f); printable
  ASCII only (0x20-0x7e); non-empty after strip; at most
  MAX_COMMAND_CHARS characters after strip; NO shell metacharacters
  (`; | & < > backtick dollar backslash`) - a chained, piped,
  substituted, redirected, or backgrounded compound is not ONE command
  and is unclassifiable here. Quoting is otherwise permitted: the
  program token gets surrounding quote pairs stripped (balanced pairs
  only), the directory part dropped, then lowercased for catalog
  matching; an unbalanced quote fails closed via the unknown rule.
- `audit_event(classification)` returns one deterministic,
  JSON-serializable dict per classified command for the chassis audit
  path (command text is already sanitized printable ASCII, capped).
  The CALLER decides which classifications to record.
- Planner purity: no execution facilities, no network access, no wall
  clock, no I/O - data in, data out (source-scan pinned in tests).
  Chassis wiring happens ONLY in the integration task, never here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

# --- Blast-radius classes and their authorization requirements -----------

CLASS_READ = "read"
CLASS_SCAN = "scan"
CLASS_EXPLOIT = "exploit-class"

BLAST_CLASSES: Tuple[str, ...] = (CLASS_READ, CLASS_SCAN, CLASS_EXPLOIT)

REQUIRED_LEVELS = {
    CLASS_READ: 1,
    CLASS_SCAN: 2,
    CLASS_EXPLOIT: 3,
}

REQUIRED_LEVEL_NAMES = {1: "basic", 2: "advanced", 3: "critical"}

STAGING_CLASSES = frozenset({CLASS_EXPLOIT})

# Classes that require lab staging are exactly STAGING_CLASSES; the
# boolean is computed per classification ("exploit-class" only).

EVENT_KIND = "command_blast_radius_classified"

# --- Input acceptance ----------------------------------------------------

MAX_COMMAND_CHARS = 256

FORBIDDEN_METACHARS: Tuple[str, ...] = (";", "|", "&", "<", ">", "`", "$", "\\")

# --- Program catalog (hand-curated, deterministic) ------------------------
#
# Read: single-record lookups and observation only - no interpreters,
# no mutators (no find/sed/awk/xargs/dd/tee), no shells, no privilege
# runners, nothing with a write or connect-back mode.
READ_PROGRAMS: Tuple[str, ...] = (
    "arp", "cat", "curl", "cut", "date", "df", "dig", "du", "env",
    "file", "free", "getent", "grep", "head", "history", "host",
    "hostname", "id", "ifconfig", "ldapsearch", "less", "ls", "lsof",
    "md5sum", "netstat", "nslookup", "printenv", "ps", "pwd",
    "searchsploit", "sha256sum", "sort", "ss", "stat", "strings",
    "tail", "tcpdump", "tshark", "uname", "uniq", "uptime", "wc",
    "wget", "which", "who", "whoami", "whois",
)

# Scan: active probing/enumeration - noisy, IDS-logged traffic, but no
# credential attacks, no payload delivery, no writes to the target.
SCAN_PROGRAMS: Tuple[str, ...] = (
    "amass", "arp-scan", "dirb", "dirsearch", "dnsenum", "dnsmap",
    "dnsrecon", "enum4linux", "enum4linux-ng", "feroxbuster", "ffuf",
    "gobuster", "httpx", "masscan", "nbtscan", "nikto", "nmap",
    "nuclei", "ping", "rpcinfo", "showmount", "smbclient", "smbmap",
    "snmpwalk", "sslscan", "sslyze", "subfinder", "testssl.sh",
    "traceroute", "unicornscan", "wafw00f", "whatweb", "wpscan", "zmap",
)

# Exploit-class: attack-driving programs (credential attacks, injection,
# remote exec, rogue servers, floods, spoofing) plus DoS-capable probes.
EXPLOIT_PROGRAMS: Tuple[str, ...] = (
    "aircrack-ng", "aireplay-ng", "arpspoof", "bettercap", "cme",
    "commix", "crackmapexec", "dnsspoof", "ettercap", "hping3", "hydra",
    "john", "macof", "medusa", "mimikatz", "msfconsole", "msfvenom",
    "ncrack", "netexec", "ntlmrelayx.py", "nxc", "psexec.py",
    "responder", "secretsdump.py", "setoolkit", "smbexec.py", "sqlmap",
    "yersinia",
)

PROGRAM_CLASSES = {}
for _class, _names in ((CLASS_READ, READ_PROGRAMS), (CLASS_SCAN, SCAN_PROGRAMS),
                       (CLASS_EXPLOIT, EXPLOIT_PROGRAMS)):
    for _name in _names:
        PROGRAM_CLASSES[_name] = _class

# --- Escalation keywords (only ever raise to exploit-class) --------------

ESCALATION_TOKENS: Tuple[str, ...] = (
    "post", "put", "patch", "delete", "mkfifo",
)

ESCALATION_SUBSTRINGS: Tuple[str, ...] = (
    "exploit", "payload", "--form", "--os-shell", "--file-write",
    "--post", "--upload-file",
)

# Per-tool scoped matches, so common flags of OTHER tools never collide
# (`-T` is nmap timing and wget timeout; `-d` is nmap debug; `--data`
# is also the prefix of nmap's --data-length - all scoped away).

TOOL_ESCALATION_TOKENS = {"curl": ("-d", "-F", "-T")}

TOOL_ESCALATION_SUBSTRINGS = {"curl": ("--data",)}


@dataclass(frozen=True)
class CommandClassification:
    """One command's blast-radius tag plus its authorization requirement.

    `rule` documents the single deterministic piece of evidence that
    decided the class (scan order in the module docstring). The command
    echo is the sanitized input: stripped, printable, capped.
    """

    command: str
    program: str
    blast_class: str
    rule: str
    required_level: int
    level_name: str
    staging_required: bool


def _sanitize(command: str) -> str:
    """Validate the raw external string; return it stripped for tagging."""
    if not isinstance(command, str):
        raise ValueError(
            "command must be a string, got %s" % (type(command).__name__,))
    for ch in command:
        if ord(ch) < 0x20 or ord(ch) == 0x7f:
            raise ValueError("command contains control characters")
        if ord(ch) > 0x7e:
            raise ValueError("command contains non-ASCII characters")
    stripped = command.strip()
    if not stripped:
        raise ValueError("command is empty")
    if len(stripped) > MAX_COMMAND_CHARS:
        raise ValueError("command exceeds %d printable characters"
                         % (MAX_COMMAND_CHARS,))
    for ch in FORBIDDEN_METACHARS:
        if ch in stripped:
            raise ValueError("command contains shell metacharacters")
    return stripped


def _program_token(command: str) -> str:
    """Program token: surrounding quote pairs stripped, dir part dropped,
    lowercased - the documented catalog-matching form."""
    token = command.split()[0]
    while len(token) >= 2 and token[0] == token[-1] and token[0] in "'\"":
        token = token[1:-1]
    program = token.rsplit("/", 1)[-1].lower()
    if not program:
        raise ValueError("command has no program token")
    return program


def classify(command: str) -> CommandClassification:
    """Tag one command string with a blast-radius class and the
    authorization tier (level, level name, lab staging) it requires.
    Pure: returns data only, never executes."""
    stripped = _sanitize(command)
    program = _program_token(stripped)
    lowered = stripped.lower()
    tokens = stripped.split()

    rule = None
    for tok in tokens:
        if tok.lower() in ESCALATION_TOKENS:
            rule = "keyword:%s" % (tok.lower(),)
            break
    if rule is None:
        for keyword in ESCALATION_SUBSTRINGS:
            if keyword in lowered:
                rule = "keyword:%s" % (keyword,)
                break
    if rule is None:
        for flag in TOOL_ESCALATION_TOKENS.get(program, ()):
            if flag in tokens:
                rule = "tool:%s:%s" % (program, flag)
                break
    if rule is None:
        for keyword in TOOL_ESCALATION_SUBSTRINGS.get(program, ()):
            if keyword in lowered:
                rule = "tool:%s:%s" % (program, keyword)
                break

    if rule is not None:
        blast_class = CLASS_EXPLOIT
    else:
        blast_class = PROGRAM_CLASSES.get(program, CLASS_EXPLOIT)
        if blast_class is CLASS_EXPLOIT and program not in PROGRAM_CLASSES:
            rule = "unknown:%s" % (program,)
        else:
            rule = "program:%s" % (program,)

    required_level = REQUIRED_LEVELS[blast_class]
    return CommandClassification(
        command=stripped,
        program=program,
        blast_class=blast_class,
        rule=rule,
        required_level=required_level,
        level_name=REQUIRED_LEVEL_NAMES[required_level],
        staging_required=blast_class in STAGING_CLASSES,
    )


def audit_event(result: CommandClassification) -> Dict[str, Any]:
    """One deterministic, JSON-serializable audit dict for a classified
    command; the caller decides which classifications to record."""
    return {
        "event": EVENT_KIND,
        "command": result.command,
        "program": result.program,
        "blast_class": result.blast_class,
        "rule": result.rule,
        "required_level": result.required_level,
        "level_name": result.level_name,
        "staging_required": result.staging_required,
    }