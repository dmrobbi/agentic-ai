"""KA-087 - tool KB: the generated one-pager catalog's shape and counted
totals (52 registry tools - the kali agent's KALI_TOOLS_DB key set, the
one duplicate registry key collapsing - every tool carrying 2-4 safe
command patterns with placeholder fields and 1-2 verified official
references), the pattern-policy scans (no shell metachars outside the
<placeholder> brackets, no credential material, no payload or hostile
strings, no encoded blobs, no dead-link markers in the data - the drop
list lives in the builder docstring only), the consumer get/search/
stats shapes with copy semantics and the house search cap, the loud
row validation in the builder, and the offline builder running green -
byte-identical across two runs and equal to the committed file - with
the live URL sweep staying opt-in.

No network in these tests: the builder's default run is offline and
the committed data/tool_kb.json is read as a fixture."""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.kali import KALI_TOOLS_DB

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "build_tool_kb.py"
DATA = REPO / "data" / "tool_kb.json"
CONSUMER = REPO / "agentic_ai" / "agents" / "cyber" / "tool_kb.py"

_builder_spec = importlib.util.spec_from_file_location(
    "build_tool_kb", str(TOOL))
BUILD = importlib.util.module_from_spec(_builder_spec)
_builder_spec.loader.exec_module(BUILD)

_consumer_spec = importlib.util.spec_from_file_location(
    "tool_kb_consumer", str(CONSUMER))
KB = importlib.util.module_from_spec(_consumer_spec)
_consumer_spec.loader.exec_module(KB)

ENTRY_KEYS = {"tool", "package", "purpose", "command_patterns",
              "false_positive_notes", "references"}
META_KEYS = {"policy", "source", "totals", "url_count", "urls_verified"}
URLS_VERIFIED_DATE = "2026-10-07"

EXPECTED_TOOLS = (
    "aircrack_ng", "amass", "binwalk", "bloodhound", "burpsuite", "cewl",
    "crunch", "dirb", "dnsrecon", "empire", "exiftool", "ffuf",
    "foremost", "gobuster", "hash_identifier", "hashcat", "hydra",
    "john", "joomscan", "kismet", "lazagne", "maltego", "masscan",
    "mdk4", "medusa", "metasploit", "mimikatz", "nikto", "nmap",
    "nmap_exploit", "nmap_vuln", "openvas", "reaver", "recon_ng",
    "responder", "rsmangler", "searchsploit", "setoolkit", "shodan",
    "sleuthkit", "spiderfoot", "sqlmap", "sslscan", "subfinder",
    "testssl", "theHarvester", "volatility", "whatweb", "wifite",
    "wireshark", "wpscan", "zap_cli")

# First pattern token per tool. All values are the kali.py registry
# row's command binary EXCEPT empire - the override documents that
# kali.py's command predates Kali's package rename (see the builder).
EXPECTED_FIRST_BINARIES = {
    "aircrack_ng": "aircrack-ng", "amass": "amass", "binwalk": "binwalk",
    "bloodhound": "bloodhound-python", "burpsuite": "burpsuite",
    "cewl": "cewl", "crunch": "crunch", "dirb": "dirb",
    "dnsrecon": "dnsrecon", "empire": "powershell-empire",
    "exiftool": "exiftool", "ffuf": "ffuf", "foremost": "foremost",
    "gobuster": "gobuster", "hash_identifier": "hash-identifier",
    "hashcat": "hashcat", "hydra": "hydra", "john": "john",
    "joomscan": "joomscan", "kismet": "kismet", "lazagne": "lazagne",
    "maltego": "maltego", "masscan": "masscan", "mdk4": "mdk4",
    "medusa": "medusa", "metasploit": "msfconsole", "mimikatz": "mimikatz",
    "nikto": "nikto", "nmap": "nmap", "nmap_exploit": "nmap",
    "nmap_vuln": "nmap", "openvas": "gvm-cli", "reaver": "reaver",
    "recon_ng": "recon-ng", "responder": "responder",
    "rsmangler": "rsmangler", "searchsploit": "searchsploit",
    "setoolkit": "setoolkit", "shodan": "shodan", "sleuthkit": "fls",
    "spiderfoot": "spiderfoot-cli", "sqlmap": "sqlmap",
    "sslscan": "sslscan", "subfinder": "subfinder", "testssl": "testssl.sh",
    "theHarvester": "theHarvester", "volatility": "volatility",
    "whatweb": "whatweb", "wifite": "wifite", "wireshark": "tshark",
    "wpscan": "wpscan", "zap_cli": "zap-cli",
}

# Package-name spot pins for the rows where the Kali package diverges
# from the binary name or is otherwise easy to curate wrong.
EXPECTED_PACKAGES_SPOT = {
    "aircrack_ng": "aircrack-ng", "bloodhound": "bloodhound.py",
    "empire": "powershell-empire", "exiftool": "libimage-exiftool-perl",
    "hash_identifier": "hash-identifier", "lazagne":
        "github:AlessandroZ/LaZagne", "metasploit":
        "metasploit-framework", "openvas": "gvm-tools", "searchsploit":
        "exploitdb", "setoolkit": "set", "shodan": "python3-shodan",
    "sleuthkit": "sleuthkit", "testssl": "testssl.sh", "theHarvester":
        "theharvester", "volatility": "volatility", "wireshark": "tshark",
    "zap_cli": "pip:zapcli",
}

PLACEHOLDER = re.compile(r"<[a-z][a-z0-9-]*>")

FORBIDDEN_SUBSTRINGS = (
    "<script", "javascript:", "onerror", "onload", "union select",
    "drop table", "select *", "base64", "base32", "etc/passwd",
    "etc/shadow", "whoami", "bash -c", "sh -c", "nc -e", "rm -rf",
    "chmod", "meterpreter", "reverse_tcp", "shellcode", "msfvenom",
    "subprocess", "os.system", "python -c", "perl -e", "php -r",
    "file://", "password", "eval",
    # dead-link markers: the drop list lives in the docstring only
    "404", "dead", "dropped", "unavailable", "unreachable", "removed",
    "no longer", "not found",
)
FORBIDDEN_CHARS = set("();|`$&<>")

# concrete targeting must not appear in the data
TARGETING_TOKENS = ("127.0.0.1", "0.0.0.0", "10.0.", "192.168.",
                    "localhost", ":4444")

BLOB_PATTERNS = (re.compile(r"\b[0-9a-fA-F]{24,}\b"),
                 re.compile(r"[A-Za-z0-9+/=]{48,}"))

# Stable query-result pins (from the committed catalog): exact ordering
# = rank (tool key, package, purpose, patterns, notes) then catalog
# tool order.
SEARCH_PINS = (
    ("wordpress", ["wpscan"]),
    ("joomla", ["joomscan"]),
    ("wireless", ["aircrack_ng", "kismet", "mdk4", "reaver", "wifite"]),
    ("dns", ["dnsrecon", "amass", "gobuster", "subfinder"]),
    ("brute", ["gobuster"]),
    ("fingerprinting", ["nikto", "whatweb"]),
    ("handshake", ["aircrack_ng"]),
    ("memory", ["volatility"]),
    ("subdomain", ["subfinder", "theHarvester"]),
    ("digest", ["aircrack_ng", "cewl", "hash_identifier", "hashcat",
                "john", "wifite"]),
    ("proxy", ["burpsuite", "zap_cli"]),
    ("metadata", ["exiftool", "sleuthkit"]),
    ("tls", ["openvas"]),
)

TAMPER_CASES = (
    ("drop-tool", "curated/tool key mismatch"),
    ("extra-tool", "curated/tool key mismatch"),
    ("first-token", "first pattern token"),
    ("one-pattern", "want 2-4 patterns"),
    ("five-patterns", "want 2-4 patterns"),
    ("no-placeholder", "no pattern carries"),
    ("three-refs", "want 1-2 verified references"),
    ("no-refs", "want 1-2 verified references"),
    ("empty-package", "empty package"),
)


def _entries_by_tool():
    return {entry["tool"]: entry for entry in _committed()["entries"]}


def _committed():
    return json.loads(DATA.read_text(encoding="utf-8"))


def _string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _string_values(item)


def test_committed_data_exists_with_pinned_top_shape():
    data = _committed()
    assert set(data) == {"entries", "meta"}
    assert data["meta"]["urls_verified"] == URLS_VERIFIED_DATE
    assert set(data["meta"]) == META_KEYS


def test_entry_order_and_count_match_pins():
    data = _committed()
    entries = data["entries"]
    assert len(entries) == len(EXPECTED_TOOLS) == 52
    assert tuple(entry["tool"] for entry in entries) == EXPECTED_TOOLS
    assert [entry["tool"] for entry in entries] == sorted(
        entry["tool"] for entry in entries)


def test_catalog_covers_the_registry_exactly():
    data = _committed()
    catalog_tools = {entry["tool"] for entry in data["entries"]}
    assert catalog_tools == set(KALI_TOOLS_DB)
    assert set(EXPECTED_TOOLS) == catalog_tools


def test_entry_shape_fields_for_every_tool():
    entries = _entries_by_tool()
    assert sorted(entries) == sorted(EXPECTED_TOOLS)
    for tool, entry in sorted(entries.items()):
        assert set(entry) == ENTRY_KEYS, tool
        for field in ("package", "purpose", "false_positive_notes"):
            assert isinstance(entry[field], str) and entry[field].strip(), \
                (tool, field)
        patterns = entry["command_patterns"]
        assert isinstance(patterns, list) and 2 <= len(patterns) <= 4, tool
        for pattern in patterns:
            assert isinstance(pattern, str), (tool, pattern)
            assert pattern.strip() == pattern, (tool, pattern)
        references = entry["references"]
        assert isinstance(references, list) and \
            1 <= len(references) <= 2, tool
        assert len(references) == len(set(references)), tool
        for url in references:
            assert url.startswith("https://"), (tool, url)
            assert "://" in url and not any(c.isspace() for c in url), url


def test_first_pattern_token_is_the_registry_binary():
    for tool, expected_binary in sorted(EXPECTED_FIRST_BINARIES.items()):
        entry = KB.tool_kb_get(tool)
        assert entry is not None, tool
        first_token = entry["command_patterns"][0].split(" ", 1)[0]
        assert first_token == expected_binary, tool


def test_placeholder_policy_per_tool():
    entries = _entries_by_tool()
    launchers = BUILD.INTERACTIVE_LAUNCHERS
    for tool, entry in sorted(entries.items()):
        has_placeholder = any(
            PLACEHOLDER.search(p) for p in entry["command_patterns"])
        if tool in launchers:
            continue
        assert has_placeholder, tool


def test_override_map_pins_the_kept_binary_exception():
    assert BUILD.BINARY_OVERRIDES == {"empire": "powershell-empire"}
    assert BUILD.INTERACTIVE_LAUNCHERS == {
        "empire", "mimikatz", "setoolkit", "hash_identifier"}


def test_package_spot_pins():
    for tool, package in sorted(EXPECTED_PACKAGES_SPOT.items()):
        assert KB.tool_kb_get(tool)["package"] == package, tool


def test_placeholders_are_the_only_angle_brackets():
    for value in _string_values(_committed()):
        stripped = PLACEHOLDER.sub("", value)
        assert not any(c in FORBIDDEN_CHARS for c in stripped), value


def test_no_payload_or_hostile_strings_in_values():
    for value in _string_values(_committed()):
        low = value.lower()
        for needle in FORBIDDEN_SUBSTRINGS:
            assert needle not in low, (needle, value[:60])


def test_no_targeting_tokens_or_blobs_in_values():
    for value in _string_values(_committed()):
        low = value.lower()
        for token in TARGETING_TOKENS:
            assert token not in low, (token, value[:60])
        for blob in BLOB_PATTERNS:
            assert not blob.search(value), value[:60]


def test_meta_totals_and_url_count_consistent():
    data = _committed()
    entries = data["entries"]
    totals = data["meta"]["totals"]
    assert set(totals) == {"command_patterns", "references", "tools"}
    assert totals["tools"] == len(entries)
    assert totals["command_patterns"] == sum(
        len(e["command_patterns"]) for e in entries)
    assert totals["references"] == sum(
        len(e["references"]) for e in entries)
    unique_urls = {url for e in entries for url in e["references"]}
    assert data["meta"]["url_count"] == len(unique_urls)
    assert data["meta"]["policy"].strip()
    assert data["meta"]["source"].strip()


def test_builder_purity_and_lazy_network():
    source = TOOL.read_text(encoding="utf-8")
    for marker in ("subprocess", "os.system", "eval(", "exec(",
                   "__import__"):
        assert marker not in source, marker
    assert "--live" in source
    assert BUILD.USER_AGENT == (
        "Mozilla/5.0 (compatible; bedimsecurity-linkcheck/1.0)")
    offline_part = source.split("def check_url_once", 1)[0]
    assert offline_part.strip(), "check_url_once not found in builder"
    for needle in ("urllib", "requests", "http.client"):
        assert needle not in offline_part, needle


def test_consumer_purity():
    source = CONSUMER.read_text(encoding="utf-8")
    for marker in ("subprocess", "os.system", "exec(", "eval(",
                   "__import__", "urllib", "requests", "socket",
                   "http.client"):
        assert marker not in source, marker


def test_kb_path_resolves_to_the_repo_data_file():
    assert KB.KB_PATH == REPO / "data" / "tool_kb.json"
    assert KB.KB_PATH.is_file()


def test_consumer_get_shape():
    entry = KB.tool_kb_get("nmap")
    assert set(entry) == ENTRY_KEYS
    assert entry["tool"] == "nmap"
    assert 2 <= len(entry["command_patterns"]) <= 4
    assert 1 <= len(entry["references"]) <= 2


def test_consumer_get_normalizes_case_and_whitespace():
    assert KB.tool_kb_get("  NMAP  ") == KB.tool_kb_get("nmap")
    assert KB.tool_kb_get("THEHARVESTER")["tool"] == "theHarvester"
    first = KB.tool_kb_get("nmap")
    first["command_patterns"].append("tampered")
    first["references"].append("tampered")
    assert "tampered" not in KB.tool_kb_get("nmap")["command_patterns"]
    assert "tampered" not in KB.tool_kb_get("nmap")["references"]


def test_consumer_get_misses():
    for tool in (None, 123, "", "   ", "nope"):
        assert KB.tool_kb_get(tool) is None, tool


def test_consumer_get_returns_every_catalog_tool():
    for tool in EXPECTED_TOOLS:
        entry = KB.tool_kb_get(tool)
        assert entry is not None and entry["tool"] == tool, tool


def test_consumer_search_rank():
    # exact tool-key hits first, then the tools whose planning prose
    # and command shapes mention the query term
    assert [e["tool"] for e in KB.tool_kb_search("nmap")] == (
        ["nmap", "nmap_exploit", "nmap_vuln", "masscan", "searchsploit"])


def test_consumer_search_pins():
    for query, expected in SEARCH_PINS:
        got = [e["tool"] for e in KB.tool_kb_search(query)]
        assert got == expected, query


def test_consumer_search_empty_query_returns_capped_catalog_order():
    entries = _committed()["entries"]
    got = KB.tool_kb_search("")
    assert len(got) == KB.SEARCH_DEFAULT_CAP == 25
    assert [e["tool"] for e in got] == [
        e["tool"] for e in entries[:25]]


def test_consumer_search_zero_or_negative_cap_is_empty():
    assert KB.tool_kb_search("nmap", cap=0) == []
    assert KB.tool_kb_search("nmap", cap=-3) == []


def test_consumer_search_cap_is_respected_and_clamped():
    assert len(KB.tool_kb_search("", cap=3)) == 3
    got_full = KB.tool_kb_search("")
    got_capped = KB.tool_kb_search("", cap=8)
    assert [e["tool"] for e in got_capped] == [
        e["tool"] for e in got_full[:8]]
    # above the house cap it stays at 25
    assert len(KB.tool_kb_search("", cap=9999)) == 25


def test_consumer_search_miss_returns_empty():
    assert KB.tool_kb_search("aardvark-wibble") == []


def test_consumer_stats_shape_and_counts():
    stats = KB.tool_kb_stats()
    assert stats == {"tools": 52, "with_patterns": 52, "with_notes": 52}


def test_offline_build_is_deterministic_and_matches_committed(tmp_path):
    totals = _committed()["meta"]["totals"]
    prefix = "TOOLKB-OK tools=%d patterns=%d references=%d out=" % (
        totals["tools"], totals["command_patterns"],
        totals["references"])
    outs = []
    for name in ("one.json", "two.json"):
        out = tmp_path / name
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, str(TOOL), "--out", str(out)],
            cwd=str(REPO), capture_output=True, text=True, timeout=300)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert proc.stdout.startswith(prefix), proc.stdout
        outs.append(out)
    assert outs[0].read_bytes() == outs[1].read_bytes()
    assert outs[0].read_bytes() == DATA.read_bytes()


def test_committed_data_is_canonical_json():
    raw = DATA.read_bytes()
    re_canon = (json.dumps(_committed(), indent=1, sort_keys=True)
                + "\n").encode("utf-8")
    assert raw == re_canon


def test_builder_rejects_unknown_flags():
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(TOOL), "--bogus"],
        cwd=str(REPO), capture_output=True, text=True, timeout=120)
    assert proc.returncode != 0
    assert "unknown build-tool flag" in proc.stderr + proc.stdout


def test_builder_validate_rows_rejects_tampered_rows():
    import copy as _copy
    for tamper, message in TAMPER_CASES:
        rows = _copy.deepcopy(BUILD.CURATED_ROWS)
        registry = dict(KALI_TOOLS_DB)
        if tamper == "drop-tool":
            del rows["nmap"]
        elif tamper == "extra-tool":
            rows["not_a_tool"] = dict(rows["nmap"])
        elif tamper == "first-token":
            rows["nmap"]["patterns"][0] = "wrongbinary <target>"
        elif tamper == "one-pattern":
            rows["nmap"]["patterns"] = ["nmap <target>"]
        elif tamper == "five-patterns":
            rows["nmap"]["patterns"] = ["nmap <target>"] * 5
        elif tamper == "no-placeholder":
            rows["gobuster"]["patterns"] = ["gobuster dir",
                                            "gobuster vhost"]
        elif tamper == "three-refs":
            rows["nmap"]["references"] = [
                "https://nmap.org/book/",
                "https://nmap.org/book/man.html",
                "https://nmap.org/book/perf.html"]
        elif tamper == "no-refs":
            rows["nmap"]["references"] = []
        elif tamper == "empty-package":
            rows["nmap"]["package"] = " "
        with pytest.raises(ValueError, match=message):
            BUILD.validate_rows(rows, registry)


def test_builder_validates_untampered_rows_cleanly():
    BUILD.validate_rows(dict(BUILD.CURATED_ROWS),
                        dict(KALI_TOOLS_DB))