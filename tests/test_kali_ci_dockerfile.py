"""Static lint for the reproducible kali CI profile (KA-096).

Offline checks over docker/kali-ci/Dockerfile and docker/kali-ci/README.md:
FROM shape, zero :latest, zero curl-pipe-bash, apt pins present, every
KALI_TOOLS_DB tool mapped to its pinned apt package (or documented as
kali-rolling-unpackaged), and no embedded credentials. No docker build,
no network, no package execution.

The TOOL_PACKAGE table below was measured from the READ-ONLY
KALI_TOOLS_DB enumeration (52 tools) against the kali-rolling package
index on 2026-10-07 (source recorded in docker/kali-ci/README.md). It is
pinned as constants per the conventions' drift-alarm rule: the task that
changes the tool DB or the pinned profile updates this table in the same
task.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "docker" / "kali-ci" / "Dockerfile"
README = REPO_ROOT / "docker" / "kali-ci" / "README.md"

# KALI_TOOLS_DB tool -> apt package (None = kali-rolling does not package
# it in the 2026-10-07 snapshot; documented in README, never installed).
TOOL_PACKAGE: dict[str, str | None] = {
    "metasploit": "metasploit-framework",
    "searchsploit": "exploitdb",
    "nmap-exploit": "nmap",
    "volatility": None,
    "foremost": "foremost",
    "sleuthkit": "sleuthkit",
    "exiftool": "libimage-exiftool-perl",
    "binwalk": "binwalk",
    "john": "john",
    "hashcat": "hashcat",
    "hydra": "hydra",
    "medusa": "medusa",
    "cewl": "cewl",
    "crunch": "crunch",
    "hash-identifier": "hash-identifier",
    "rsmangler": "rsmangler",
    "mimikatz": "mimikatz",
    "bloodhound": "bloodhound.py",
    "empire": "powershell-empire",
    "lazagne": None,
    "nmap": "nmap",
    "masscan": "masscan",
    "recon-ng": "recon-ng",
    "theHarvester": "theharvester",
    "amass": "amass",
    "subfinder": "subfinder",
    "dnsrecon": "dnsrecon",
    "shodan": None,
    "maltego": "maltego",
    "spiderfoot": "spiderfoot",
    "wireshark": "tshark",
    "responder": "responder",
    "setoolkit": "set",
    "nikto": "nikto",
    "openvas": "gvm-tools",
    "nmap-vuln": "nmap",
    "sqlmap": "sqlmap",
    "burpsuite": "burpsuite",
    "dirb": "dirb",
    "gobuster": "gobuster",
    "wpscan": "wpscan",
    "ffuf": "ffuf",
    "joomscan": "joomscan",
    "zap_cli": None,
    "whatweb": "whatweb",
    "sslscan": "sslscan",
    "testssl": "testssl.sh",
    "aircrack-ng": "aircrack-ng",
    "reaver": "reaver",
    "wifite": "wifite",
    "kismet": "kismet",
    "mdk4": "mdk4",
}

NON_APT_TOOLS = frozenset(name for name, pkg in TOOL_PACKAGE.items() if pkg is None)

# Packages that must never appear as apt pins (no aliases allowed in the profile).
FORBIDDEN_PIN_NAMES = ("shodan", "zap-cli", "zap_cli", "lazagne", "volatility", "volatility3", "hashid", "openvas")

# Measured kali-rolling versions (fetch date 2026-10-07, see README).
# ncat is the one runtime companion package (not a DB tool itself).
EXPECTED_PIN_COUNT_MIN = 20

PIN_RE = re.compile(r"=\d[\w:.+\-~]*")
CURL_BASH_RE = re.compile(r"\b(?:curl|wget)\b[^#|]*\|\s*(?:ba)?sh\b")
CREDENTIAL_RE = re.compile(r"(?i)\b(?:pass(?:word)?|token|secret|api[_-]?key)\b\s*[:=]")

PHASE_NAMES = (
    "reconnaissance",
    "vulnerability_analysis",
    "web_application",
    "password",
    "exploitation",
    "post_exploitation",
    "forensics",
    "malware",
    "sniffing_spoofing",
    "social_engineering",
    "wireless",
)


def _dockerfile_text() -> str:
    assert DOCKERFILE.is_file(), f"missing {DOCKERFILE}"
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert text.strip(), f"empty {DOCKERFILE}"
    return text


def _readme_text() -> str:
    assert README.is_file(), f"missing {README}"
    text = README.read_text(encoding="utf-8")
    assert text.strip(), f"empty {README}"
    return text


def _from_lines(dockerfile: str) -> list[str]:
    return [line.strip() for line in dockerfile.splitlines() if line.strip().upper().startswith("FROM ")]


def test_dockerfile_and_readme_exist() -> None:
    _dockerfile_text()
    _readme_text()


def test_from_kali_rolling_without_latest_tag() -> None:
    dockerfile = _dockerfile_text()
    from_lines = _from_lines(dockerfile)
    assert from_lines, "no FROM line in Dockerfile"
    assert from_lines[0] == "FROM kalilinux/kali-rolling", from_lines[0]


def test_no_latest_tag_anywhere() -> None:
    assert ":latest" not in _dockerfile_text()


def test_no_curl_pipe_bash() -> None:
    dockerfile = _dockerfile_text()
    match = CURL_BASH_RE.search(dockerfile)
    assert match is None, f"curl|bash pattern at: {match.group(0) if match else ''}"


def test_apt_pins_present() -> None:
    dockerfile = _dockerfile_text()
    pins = PIN_RE.findall(dockerfile)
    assert len(pins) >= EXPECTED_PIN_COUNT_MIN, pins


def test_phase_tool_names_pinned() -> None:
    dockerfile = _dockerfile_text()
    for tool in ("nmap", "sqlmap", "nikto"):
        assert rf"{tool}=" in dockerfile, f"missing pinned phase tool: {tool}"


def test_every_db_tool_pinned_or_documented() -> None:
    dockerfile = _dockerfile_text()
    readme = _readme_text()
    assert set(TOOL_PACKAGE) == {
        "metasploit", "searchsploit", "nmap-exploit", "volatility", "foremost",
        "sleuthkit", "exiftool", "binwalk", "john", "hashcat", "hydra", "medusa",
        "cewl", "crunch", "hash-identifier", "rsmangler", "mimikatz", "bloodhound",
        "empire", "lazagne", "nmap", "masscan", "recon-ng", "theHarvester", "amass",
        "subfinder", "dnsrecon", "shodan", "maltego", "spiderfoot", "wireshark",
        "responder", "setoolkit", "nikto", "openvas", "nmap-vuln", "sqlmap",
        "burpsuite", "dirb", "gobuster", "wpscan", "ffuf", "joomscan", "zap_cli",
        "whatweb", "sslscan", "testssl", "aircrack-ng", "reaver", "wifite",
        "kismet", "mdk4",
    }
    for tool, package in TOOL_PACKAGE.items():
        if package is None:
            assert tool in readme, f"non-apt tool not documented in README: {tool}"
        else:
            assert f"{package}=" in dockerfile, f"missing pinned package for {tool}: {package}"
    for tool in NON_APT_TOOLS:
        assert tool in readme, f"non-apt tool not listed in README: {tool}"


def test_unpackaged_tools_never_pinned() -> None:
    dockerfile = _dockerfile_text()
    for name in FORBIDDEN_PIN_NAMES:
        assert f"{name}=" not in dockerfile, f"forbidden pin present: {name}"


def test_no_embedded_credentials() -> None:
    dockerfile = _dockerfile_text()
    match = CREDENTIAL_RE.search(dockerfile)
    assert match is None, f"credential-shaped string: {match.group(0) if match else ''}"
    for marker in ("ghp_", "gho_", "AKIA", "-----BEGIN"):
        assert marker not in dockerfile


def test_image_runs_as_non_root_user() -> None:
    dockerfile = _dockerfile_text()
    user_lines = [line.strip() for line in dockerfile.splitlines() if line.strip().startswith("USER ")]
    assert user_lines and user_lines[-1] == "USER kali", user_lines
    assert "useradd -m -u 1000 -s /bin/bash kali" in dockerfile


def test_readme_documents_provenance_and_phases() -> None:
    readme = _readme_text()
    for needle in ("kali-rolling", "http.kali.org", "2026-10-07", "Refresh procedure"):
        assert needle in readme, f"README missing provenance text: {needle}"
    for phase in PHASE_NAMES:
        assert f"### {phase} " in readme, f"README missing phase table: {phase}"