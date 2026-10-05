"""KA-064 tests - doctor tool-version matrix: docs/ka_tool_versions.json.

Pins, against the CURRENT tree:
- the JSON stays valid JSON with a _meta block (generated_at, sources);
- the tool-entry schema (required keys + types) and tool-name uniqueness;
- the MEASURED enumeration: every tool invoked in the landed mixin
  modules' planning command strings (segment-head probe over evaluated
  string literals) equals the pinned constant and the JSON's tool set;
- per-tool planner_modules attribution equals the live re-measurement;
- the out-of-matrix mentions (named but never invoked) and the drift
  canaries (known tools absent from the tree today);
- planner purity of this test itself (the matrix is a spec artifact -
  no tool is executed here; doctor execution is INT-5+). No network.
"""
from __future__ import annotations

import ast
import io
import json
import re
import tokenize
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CYBER = REPO / "agentic_ai" / "agents" / "cyber"
DOC = REPO / "docs" / "ka_tool_versions.json"

# The landed mixin modules (files defining `class *Mixin`): the scan set.
# Pinned by name; test_scan_modules_match_the_tree re-derives the rule.
SCAN_MODULES = frozenset({
    "ad_pentest.py", "api_pentest.py", "chain_ops.py", "cloud_pentest.py",
    "container_pentest.py", "forensics_ops.py", "full_engagement.py",
    "ics_iot.py", "malware_ops.py", "mobile_pentest.py", "network_device.py",
    "osint_pentest.py", "postexp.py", "privesc.py", "redteam_pentest.py",
    "socialeng_ops.py", "web_pentest.py", "webauth_ops.py",
    "wireless_pentest.py", "xss_exploit.py",
})

# MEASURED from the tree at build time (KA-064): tools INVOKED in mixin
# planning command strings, kali/operator side, alias-normalized. The
# probe below re-derives exactly this set; a mismatch = the drift alarm
# to resolve in the task that moved the tree.
MEASURED_TOOLS = frozenset({
    "ab", "aderyn", "aircrack-ng", "airmon-ng", "airodump-ng", "anvil",
    "apktool", "arjun", "binwalk", "cadaver", "commix", "crackmapexec",
    "curl", "dalfox", "davtest", "dig", "dirb", "echidna", "enum4linux",
    "exiftool", "ffuf", "file", "fls", "forge", "ganache", "gobuster",
    "graphql-cop", "hardhat", "hashcat", "hostapd", "hydra", "icat",
    "interactsh-client", "iw", "jadx", "jq", "ldapsearch", "maigret",
    "mbpoll", "mmls", "mythril", "nikto", "nmap", "nslookup", "nuclei",
    "objdump", "olevba", "openssl", "otool", "phpggc", "semgrep",
    "sha256sum", "sherlock", "slither", "smbclient", "ssdeep", "sslscan",
    "strings", "subfinder", "tcpdump", "testssl.sh", "volatility",
    "waybackurls", "wafw00f", "whatweb", "whois", "wpscan", "xsstrike",
    "yara",
})

# True-tool alias: the mythril catalog row's template invokes Mythril via
# its legacy 'myth' CLI; the matrix carries the canonical name.
ALIASES = {"myth": "mythril"}

# Mentioned in the mixin modules but NOT matrix entries - every reason
# is pinned and every token must stay present in the tree.
EXCLUDED_MENTIONS = {
    "cdk": "container checklist tool row; no invoked command string",
    "clairvoyance": "named in an api_pentest activity string; never invoked",
    "deepce": "container checklist tool row; no invoked command string",
    "dnsmasq": "named in a wireless_pentest activity note; never invoked",
    "frida": "named in a mobile_pentest dynamic-lane note; never invoked",
    "impacket": "postexp lateral-exec forbidden-class pattern (target-side arc)",
    "inql": "named in an api_pentest activity string; never invoked",
    "kube-bench": "container checklist tool row; no invoked command string",
    "kubehound": "container checklist tool row; no invoked command string",
    "manticore": "chain_ops analyzer id with template=None",
    "medusa": "chain_ops analyzer id with template=None",
    "move-analyzer": "chain_ops analyzer id with template=None",
    "cargo-contract-audit": "chain_ops analyzer id with template=None",
    "woke": "chain_ops analyzer id with template=None",
}

# Known-tool canaries, zero-hit in the tree today: if one starts to
# appear, this file's constants move in the SAME task (drift alarm).
DRIFT_CANARIES = frozenset({
    "amass", "dirsearch", "feroxbuster", "gau", "john", "kerbrute",
    "mitm6", "nc", "onesixtyone", "responder", "snmpwalk", "socat",
    "theharvester", "wfuzz",
})

SCRIPT_PROGS = ("python3", "python")
EMBEDDED = ("openssl",)  # embedded after a prose prefix in one guidance string

TOOL_LEXICON = frozenset(
    MEASURED_TOOLS | set(ALIASES) | set(EXCLUDED_MENTIONS) | DRIFT_CANARIES)

REQUIRED_TOOL_KEYS = {
    "name", "purpose", "minimum_version", "minimum_version_note",
    "where_checked", "planner_modules",
}
REQUIRED_META_KEYS = {"generated_at", "sources"}

# Execution facilities banned from the artifact and this test. Token
# literals are spliced so they never match their own assertions.
FORBIDDEN_EXEC = (
    "sub" "process",
    "os." "system",
    "soc" "ket",
    "url" "lib",
    "requ" "ests",
)
BARE_EVAL_RE = re.compile("(?<" + "![\\w.])" + "e" + "val\\(")


def probe():
    """Measure tool mentions in the scan modules' string literals.

    Matrix tokens hit via: command segment heads (after splitting on
    newlines / ';' / pipes / '&&', skipping '#'-comment segments), a
    `python3 <tool>.py` script-invocation second token, the documented
    EMBEDDED invocation (openssl), or the alias map (myth -> mythril).
    Excluded tokens hit via word-boundary presence anywhere in the
    module's literal values (they are never invoked). f-string literals
    are skipped (runtime-built, not catalog constants). Pure file reads -
    nothing is executed.
    """
    lex = sorted(TOOL_LEXICON, key=len, reverse=True)
    lex_re = re.compile(
        r"\b(" + "|".join(re.escape(t) for t in lex) + r")\b")
    embedded_res = {
        t: re.compile(r"\b" + re.escape(t)
                      + r"\b[^\n]{0,80}(?<![\w-])-(?=\w)")
        for t in EMBEDDED
    }
    hits = {t: set() for t in TOOL_LEXICON}
    scanned = set()
    for path in sorted(CYBER.glob("*.py")):
        src = path.read_text(encoding="utf-8")
        if not re.search(r"^class \w+Mixin", src, flags=re.M):
            continue
        mod = path.name
        scanned.add(mod)
        values = []
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type != tokenize.STRING:
                continue
            lead = re.match(r"^([rbuBRUfF]{1,2})[\"']", tok.string)
            if lead and "f" in lead.group(1).lower():
                continue
            try:
                value = str(ast.literal_eval(tok.string))
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                continue
            values.append(value)
            for seg in re.split(r"\r?\n|;|\|\||&&|\|", value):
                seg = seg.strip()
                if not seg or seg.startswith("#"):
                    continue
                head = seg.split(None, 1)[0].strip("(")
                if head in TOOL_LEXICON:
                    hits[ALIASES.get(head, head)].add(mod)
                if head in SCRIPT_PROGS:
                    parts = seg.split(None, 2)
                    if len(parts) > 1:
                        mt = re.match(
                            r"([A-Za-z0-9_.\-]+)\.py\b", parts[1])
                        if mt and mt.group(1) in TOOL_LEXICON:
                            hits[ALIASES.get(mt.group(1), mt.group(1))].add(mod)
        for t, rex in embedded_res.items():
            if any(rex.search(v) for v in values):
                hits[ALIASES.get(t, t)].add(mod)
        for t in EXCLUDED_MENTIONS:
            if any(re.search(r"\b" + re.escape(t) + r"\b", v) for v in values):
                hits[t].add(mod)
    measured = {}
    for token, mods in hits.items():
        canon = ALIASES.get(token, token)
        if canon in MEASURED_TOOLS:
            measured.setdefault(canon, set()).update(mods)
    return measured, hits, scanned


def load_doc():
    return json.loads(DOC.read_text(encoding="utf-8"))


def test_scan_modules_match_the_tree():
    scanned = {p.name for p in CYBER.glob("*.py")
               if re.search(r"^class \w+Mixin", p.read_text(encoding="utf-8"),
                            flags=re.M)}
    assert scanned == SCAN_MODULES  # scan-set drift alarm


def test_doc_is_valid_json_with_top_level_shape():
    doc = load_doc()
    assert set(doc) == {"_meta", "tools"}
    assert isinstance(doc["tools"], list) and doc["tools"]
    assert all(isinstance(t, dict) for t in doc["tools"])


def test_meta_pin():
    meta = load_doc()["_meta"]
    assert REQUIRED_META_KEYS <= set(meta)
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
                    meta["generated_at"])
    expected_sources = sorted(
        f"agentic_ai/agents/cyber/{m}" for m in SCAN_MODULES)
    assert meta["sources"] == expected_sources


def test_tool_entry_schema():
    doc = load_doc()
    names = [t["name"] for t in doc["tools"]]
    for tool in doc["tools"]:
        assert set(tool) == REQUIRED_TOOL_KEYS
        assert isinstance(tool["name"], str) and tool["name"].strip()
        assert isinstance(tool["purpose"], str) and tool["purpose"].strip()
        assert tool["minimum_version"] is None or isinstance(
            tool["minimum_version"], str)
        assert isinstance(tool["minimum_version_note"], str)
        assert tool["minimum_version_note"].strip()  # why-unknown/why-known note
        assert isinstance(tool["where_checked"], str)
        assert tool["where_checked"].strip()
        assert isinstance(tool["planner_modules"], list)
        assert tool["planner_modules"]
        assert set(tool["planner_modules"]) <= SCAN_MODULES
    assert names == sorted(names)  # deterministic doc ordering


def test_tool_name_uniqueness():
    names = [t["name"] for t in load_doc()["tools"]]
    assert len(names) == len(set(names))
    assert set(names) == MEASURED_TOOLS  # 3-way pin: JSON == constant == tree


def test_measured_enumeration_matches_tree():
    measured, hits, scanned = probe()
    assert scanned == SCAN_MODULES
    excluded_hit = {t: hits[t] for t in EXCLUDED_MENTIONS}
    canary_hits = [t for t in DRIFT_CANARIES if hits[t]]
    assert canary_hits == [], "canary mentioned: promote it in the same task"
    hit_tokens = set(measured) | {
        t for t in EXCLUDED_MENTIONS if excluded_hit[t]}
    assert hit_tokens == MEASURED_TOOLS | set(EXCLUDED_MENTIONS)
    assert set(measured) == MEASURED_TOOLS


def test_json_planner_modules_match_tree():
    doc = load_doc()
    measured, _, _ = probe()
    for tool in doc["tools"]:
        assert set(tool["planner_modules"]) == measured[tool["name"]]


def test_excluded_mentions_absent_from_matrix():
    doc = load_doc()
    names = {t["name"] for t in doc["tools"]}
    assert names & set(EXCLUDED_MENTIONS) == set()
    measured, hits, _ = probe()
    for token in EXCLUDED_MENTIONS:
        assert hits[token], f"excluded mention vanished from the tree: {token}"


def test_drift_canaries_absent_from_matrix():
    names = {t["name"] for t in load_doc()["tools"]}
    assert names & DRIFT_CANARIES == set()


def test_where_checked_references_the_tool():
    for tool in load_doc()["tools"]:
        name = tool["name"]
        pattern = r"\b" + re.escape(name) + r"\b"
        assert re.search(pattern, tool["where_checked"]), tool["name"]


def test_minimum_version_policy_shape():
    for tool in load_doc()["tools"]:
        mv = tool["minimum_version"]
        assert mv is None or (isinstance(mv, str) and mv.strip())
        assert tool["minimum_version_note"].strip()


def test_doc_free_of_execution_facilities():
    text = DOC.read_text(encoding="utf-8")
    for token in FORBIDDEN_EXEC:
        assert token not in text


def test_self_scan_planner_purity():
    source = Path(__file__).read_text(encoding="utf-8")
    for token in FORBIDDEN_EXEC:
        assert token not in source
    # ast.literal_eval is the only parser used; no bare eval
    assert not BARE_EVAL_RE.search(source)