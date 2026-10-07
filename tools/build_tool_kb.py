#!/usr/bin/env python3
"""Build data/tool_kb.json - KA-087 per-tool in-house one-pagers.

Imports KALI_TOOLS_DB (read-only) from agentic_ai/agents/cyber/kali.py
and re-serializes it as planning knowledge: one curated one-pager per
registry tool. One-pager fields (shape pinned by tests/test_tool_kb.py):
  tool (the registry dict key the planner uses), package (the Kali /
  Debian package token that provides the tool's binary, or its upstream
  pip channel where no distro package carries it), purpose (in-house
  one-liner, re-authored, never verbatim source text),
  command_patterns (2-4 SAFE GENERIC planning shapes with <placeholder>
  fields: scoped targets, port ranges, wordlist file paths, output
  paths, doc-level flags - no shell metachars, no hostile or payload
  strings of any kind, no credentials, no hex/base64 blobs),
  false_positive_notes (1-2 in-house sentences on interpreting/mistrust
  of planner results before acting on them), references (1-2 official
  documentation URLs).

Policy for the emitted data: planning shapes and doc-level flags only
- no offensive strings, no credential material, no exploit content,
no shell metachars outside the <placeholder> bracket convention.
External material is re-authored in-house; kali.py's own descriptions
are never shipped verbatim.

URL discipline (mirrors the KA-072 builder): every emitted reference
was verified live (HTTP 200) on 2026-10-07 with the bounded polite
sequential sweep (--live below; UA "Mozilla/5.0 (compatible;
bedimsecurity-linkcheck/1.0)", one request per URL, a 2s minimum gap
per host, 429/Retry-After honored once). Dead candidates are dropped
and recorded HERE, in this docstring only - never in the emitted data
and never in tests. Candidates dropped during curation:
  - www.kali.org/tools/social-engineer-toolkit/ (404; the SET page
    lives at www.kali.org/tools/set/ and is cited instead)
  - www.kali.org/tools/openvas/ (404; no kali.org tools page for the
    Greenbone stack - openvas cites the project sites instead)
  - www.kali.org/tools/zapcli/ (404; zap-cli is pip-distributed - the
    entry cites the upstream project repo only)
  - www.kali.org/tools/shodan/ (404; shodan cites the upstream project
    repo and the developer portal instead)
  - www.kali.org/tools/exiftool/ (404; the entry cites the official
    exiftool.org project site instead)
  - www.kali.org/tools/lazagne/ (404; LaZagne has no kali.org tools
    page and no distro package - the entry cites the upstream project
    repo and the package token names the upstream github channel)
  - www.kali.org/tools/volatility/ (404; the entry cites the upstream
    project repo instead, with the package token confirmed through the
    Kali package tracker)

The default run is OFFLINE and deterministic: it reads the registry
dict, validates the curated rows against it (a registry add/remove is
a loud build failure, matching the test pins), and writes the JSON
canonically. The data evolves by editing the literals below, never by
hand-editing the JSON. --live is opt-in URL verification only, never
in CI or tests.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "tool_kb.json"

URLS_VERIFIED = "2026-10-07"
USER_AGENT = "Mozilla/5.0 (compatible; bedimsecurity-linkcheck/1.0)"
HOST_MIN_INTERVAL = 2.0  # minimum gap between two hits on one host
URL_TIMEOUT = 20

SOURCE = (
    "one-pagers curated in-house over the kali agent KALI_TOOLS_DB "
    "registry at agentic_ai/agents/cyber/kali.py as a read-only "
    "import. Purposes re-authored in-house from each tool's own "
    "official documentation and project manuals. Package tokens "
    "from the kali.org tool pages and the Kali package tracker, "
    "using the upstream pip:NAME or github:OWNER/REPO channel prefix "
    "when no distro package carries the binary")

POLICY = (
    "safe generic planning shapes with placeholder fields only - no "
    "hostile strings, no credential material, no exploitation content, "
    "no shell metachars, no encoded blobs. Every reference verified "
    "live at build time. Output deterministic")

KALI_TOOLS = "https://www.kali.org/tools/"

# Curated per-tool one-pagers, keyed by the registry dict key. First
# pattern token must be the registry row's command binary (validated at
# build). All text in-house; no shell metachars anywhere.
#
# NOTE on the kali pages: kali.org tool slugs mirror the package names.

# kali.py's empire row carries the pre-rename launcher name; Kali's
# current package runs powershell-empire - the one-pager cites the
# kali.org tools page for that binary. Validated exception, pinned by
# the consuming test.
BINARY_OVERRIDES = {
    "empire": "powershell-empire",
}

# Tools whose whole curated surface is the interactive launcher - their
# honest planning shapes are bare starts and help/version probes, so
# they are exempt from the at-least-one-placeholder rule. Every other
# tool must carry at least one placeholder-bearing pattern.
INTERACTIVE_LAUNCHERS = {
    "empire", "mimikatz", "setoolkit", "hash_identifier",
}

CURATED_ROWS = {
    # -------------------------------------------------- recon
    "nmap": {
        "package": "nmap",
        "purpose": (
            "maps live hosts and services across an authorized scope: "
            "port states, service versions and host details that "
            "anchor every later planning step"),
        "patterns": [
            "nmap -sV -sC <target>",
            "nmap -p <port-range> <target>",
            "nmap -sV -sC --script=<nse-scripts> <target>",
            "nmap -sV -oX <output-file> <target>",
        ],
        "notes": (
            "a port showing closed is a definite answer, but filtered "
            "results often mean a firewall and not an absent service - "
            "re-read filtered rows against a slower pass before "
            "planning anything around them"),
        "references": [
            "https://www.kali.org/tools/nmap/",
            "https://nmap.org/book/",
        ],
    },

    "nmap_vuln": {
        "package": "nmap",
        "purpose": (
            "the classification-script face of nmap: pairs detected "
            "service versions with known-issue signatures so planning "
            "can rank services worth a closer look"),
        "patterns": [
            "nmap --script=<nse-vuln-classes> -p <port-range> <target>",
            "nmap -sV --script=<nse-vuln-classes> <target>",
        ],
        "notes": (
            "classification scripts match version banners, not proof "
            "- treat every reported issue as unverified until a "
            "version banner and a doc reference agree"),
        "references": [
            "https://www.kali.org/tools/nmap/",
            "https://nmap.org/book/nse.html",
        ],
    },

    "nmap_exploit": {
        "package": "nmap",
        "purpose": (
            "the heavier exploitation-classification scripts of nmap: "
            "high-signal service probes for known-issue checks during "
            "authorized engagements"),
        "patterns": [
            "nmap --script=<nse-exploit-classes> -p <port-range> "
            "<target>",
            "nmap -sV --script=<nse-exploit-classes> <target>",
        ],
        "notes": (
            "these scripts reach deeper into services than the "
            "classification set and are easier to trip over - keep "
            "them to tightly scoped targets and read their "
            "documentation before choosing a script class"),
        "references": [
            "https://www.kali.org/tools/nmap/",
            "https://nmap.org/book/nse.html",
        ],
    },

    "masscan": {
        "package": "masscan",
        "purpose": (
            "asynchronous whole-range port sweep for the authorized "
            "address space: when nmap is too slow, masscan answers "
            "'what is listening' first"),
        "patterns": [
            "masscan <target-range> -p <port-range>",
            "masscan <target-range> -p <port-range> --rate=<rate>",
            "masscan <target-range> -p <port-range> -oX <output-file>",
        ],
        "notes": (
            "asynchronous sweeping over UDP or rate-limited links "
            "silently reports fewer answers than the truth - plan a "
            "slower nmap confirmation pass over anything masscan "
            "misses on lossy routes"),
        "references": [
            "https://www.kali.org/tools/masscan/",
            "https://github.com/robertdavidgraham/masscan",
        ],
    },

    "recon_ng": {
        "package": "recon-ng",
        "purpose": (
            "workspace-based OSINT framework: module-by-module "
            "harvesting of names, hosts, contacts and leaks into a "
            "single queryable workspace"),
        "patterns": [
            "recon-ng -w <workspace-name>",
            "recon-ng -w <workspace-name> -m <module-path>",
            "recon-ng -w <workspace-name> -r <resource-file>",
        ],
        "notes": (
            "module result counts differ wildly between free and "
            "paid upstream data providers - a module returning few "
            "rows may be quota throttling, not silence"),
        "references": [
            "https://www.kali.org/tools/recon-ng/",
            "https://github.com/lanmaster53/recon-ng",
        ],
    },

    "theHarvester": {
        "package": "theharvester",
        "purpose": (
            "public-source harvesting of domain surface: subdomains, "
            "mail contacts and host names pulled from open "
            "collections and search providers"),
        "patterns": [
            "theHarvester -d <domain> -b <source-name>",
            "theHarvester -d <domain> -b <source-name> -l <limit>",
            "theHarvester -d <domain> -b <source-name> -f <output-file>",
        ],
        "notes": (
            "aggregated public records are stale by nature - treat "
            "harvested contacts and subdomains as leads to confirm "
            "with live probing, never as current truth"),
        "references": [
            "https://www.kali.org/tools/theharvester/",
            "https://github.com/laramies/theHarvester",
        ],
    },

    "amass": {
        "package": "amass",
        "purpose": (
            "deep attack-surface mapping: DNS enumeration, archived "
            "certificate reading and graph building for a scoped "
            "domain set"),
        "patterns": [
            "amass enum -d <domain>",
            "amass intel -d <domain>",
            "amass enum -d <domain> -o <output-file>",
        ],
        "notes": (
            "passive and active enumeration return different sized "
            "answers - a short passive run says nothing about what "
            "active probing would find, so read the mode before "
            "judging coverage"),
        "references": [
            "https://www.kali.org/tools/amass/",
            "https://github.com/owasp-amass/amass",
        ],
    },

    "subfinder": {
        "package": "subfinder",
        "purpose": (
            "fast passive subdomain discovery from public sources: "
            "the cheap first pass before any active DNS work"),
        "patterns": [
            "subfinder -d <domain>",
            "subfinder -d <domain> -o <output-file>",
            "subfinder -d <domain> -t <threads>",
        ],
        "notes": (
            "passive-only by design - it cannot see what public "
            "sources never recorded, so its answer is a floor, not "
            "the full subdomain set"),
        "references": [
            "https://www.kali.org/tools/subfinder/",
            "https://github.com/projectdiscovery/subfinder",
        ],
    },

    "dnsrecon": {
        "package": "dnsrecon",
        "purpose": (
            "structured DNS enumeration: zone walking, record "
            "collection and optional cache probing against a scoped "
            "domain and its name servers"),
        "patterns": [
            "dnsrecon -d <domain>",
            "dnsrecon -d <domain> -t <enum-type>",
            "dnsrecon -d <domain> -n <name-server> -t std",
        ],
        "notes": (
            "zone-transfer style probes can be loud on monitored "
            "name servers - and a refused transfer is a hardening "
            "signal, not a failure of the tool"),
        "references": [
            "https://github.com/darkoperator/dnsrecon",
        ],
    },

    "shodan": {
        "package": "python3-shodan",
        "purpose": (
            "command-line access to the public service registry: "
            "searches indexed banners and host records for authorized "
            "scope without touching the hosts directly"),
        "patterns": [
            "shodan search <query-string>",
            "shodan host <ip-address>",
            "shodan domain <domain>",
        ],
        "notes": (
            "indexed banners lag reality - an indexed service may be "
            "gone and a live service may be unindexed. Never treat "
            "the registry as engagement-current"),
        "references": [
            "https://github.com/achillean/shodan-python",
            "https://developer.shodan.io/",
        ],
    },

    "maltego": {
        "package": "maltego",
        "purpose": (
            "graph-based link analysis: turns harvested people, "
            "domains, hosts and records into a visualized relationship "
            "graph for manual review"),
        "patterns": [
            "maltego",
            "maltego --transform=<transform-name>",
        ],
        "notes": (
            "transforms chain public data of uneven freshness - a "
            "graph edge is a lead, and manual confirmation separates "
            "the graph from reality"),
        "references": [
            "https://www.kali.org/tools/maltego/",
        ],
    },

    "spiderfoot": {
        "package": "spiderfoot",
        "purpose": (
            "automated OSINT collection across many public sources, "
            "producing a consolidated report over one scoped target"),
        "patterns": [
            "spiderfoot-cli",
            "spiderfoot-cli -q <query-string>",
            "spiderfoot-cli -l",
        ],
        "notes": (
            "automated harvesters occasionally flag unrelated "
            "third-party targets in aggregated results - confirm "
            "every row is in-scope before it shapes planning"),
        "references": [
            "https://www.kali.org/tools/spiderfoot/",
            "https://github.com/smicallef/spiderfoot",
        ],
    },

    # ------------------------------------------ vulnerability analysis
    "nikto": {
        "package": "nikto",
        "purpose": (
            "web server assessment scanner: server software "
            "fingerprinting, configuration review and known-issue "
            "surface checks over one scoped host"),
        "patterns": [
            "nikto -h <url>",
            "nikto -h <host> -p <port-range>",
            "nikto -h <url> -o <output-file>",
        ],
        "notes": (
            "loud by design and notoriously noisy - many reported "
            "rows are version guesses or headers misread as "
            "weaknesses. Rank only rows with confirmed matches"),
        "references": [
            "https://www.kali.org/tools/nikto/",
            "https://github.com/sullo/nikto",
        ],
    },

    "openvas": {
        "package": "gvm-tools",
        "purpose": (
            "greenbone vulnerability-management client: drives "
            "authenticated and unauthenticated scan configs against "
            "authorized targets and reports ranked findings"),
        "patterns": [
            "gvm-cli socket --xml <command-string>",
            "gvm-cli tls --xml <command-string>",
            "gvm-cli tls --xml <command-string> -o <output-file>",
        ],
        "notes": (
            "scanner feeds need regular updating or every report "
            "skews stale - and generic scan configs inflate "
            "informational findings that read scarier than they are"),
        "references": [
            "https://www.openvas.org/",
            "https://github.com/greenbone/gvm-tools",
        ],
    },

    # ---------------------------------------------------- web apps
    "sqlmap": {
        "package": "sqlmap",
        "purpose": (
            "automated backend testing: safely maps parameter "
            "behavior on an authorized endpoint before committing to "
            "any deeper action"),
        "patterns": [
            "sqlmap -u <url> --batch --level=<level> --risk=<risk>",
            "sqlmap -u <url> --data=<post-body> --batch",
            "sqlmap -u <url> --batch -v <verbosity-level>",
        ],
        "notes": (
            "at default settings it fires a high query volume - keep "
            "level and risk low on production-facing targets and "
            "expect duplicate row reports across parameter "
            "permutations"),
        "references": [
            "https://www.kali.org/tools/sqlmap/",
            "https://sqlmap.org/",
        ],
    },

    "burpsuite": {
        "package": "burpsuite",
        "purpose": (
            "interactive web proxy and assessment workbench: manual "
            "request interception, replay and surface mapping in one "
            "driven-by-a-human session"),
        "patterns": [
            "burpsuite",
            "burpsuite --project-file=<project-file>",
            "burpsuite --config-file=<config-file>",
        ],
        "notes": (
            "proxying is as invasive as any inline tool - a "
            "mis-scoped target list will funnel production traffic "
            "through the proxy. Verify scope in the project options "
            "before the browser points at it"),
        "references": [
            "https://www.kali.org/tools/burpsuite/",
            "https://portswigger.net/burp",
        ],
    },

    "dirb": {
        "package": "dirb",
        "purpose": (
            "dictionary-based endpoint discovery on a scoped web "
            "root: walks a wordlist against the server to surface "
            "unlinked paths"),
        "patterns": [
            "dirb <url>",
            "dirb <url> <wordlist>",
            "dirb <url> <wordlist> -o <output-file>",
        ],
        "notes": (
            "servers answer wrong-path probes differently per "
            "stack - without tuning the recursion off or adjusting "
            "wordlists, common wrong-path handling can read as found "
            "content"),
        "references": [
            "https://www.kali.org/tools/dirb/",
        ],
    },

    "gobuster": {
        "package": "gobuster",
        "purpose": (
            "fast brute-forcer for directory, virtual-host and DNS "
            "names over scoped targets: the threaded sibling of dirb "
            "with machine-readable output"),
        "patterns": [
            "gobuster dir -u <url> -w <wordlist>",
            "gobuster vhost -u <url> -w <wordlist>",
            "gobuster dir -u <url> -w <wordlist> -x <extensions>",
            "gobuster dir -u <url> -w <wordlist> -o <output-file>",
        ],
        "notes": (
            "status-code and length heuristics misreport on "
            "catch-all responses - an app that answers all paths "
            "with soft redirects buries real rows in noise. Check "
            "the excluded-length settings before trusting a list"),
        "references": [
            "https://www.kali.org/tools/gobuster/",
            "https://github.com/OJ/gobuster",
        ],
    },

    "wpscan": {
        "package": "wpscan",
        "purpose": (
            "focused WordPress site auditing: core version, plugin "
            "and theme enumeration with upstream issue references"),
        "patterns": [
            "wpscan --url <url>",
            "wpscan --url <url> --api-token=<token>",
            "wpscan --url <url> --enumerate=<enum-classes>",
        ],
        "notes": (
            "without an upstream reference token many issue rows "
            "stay hidden - and enumeration without passive mode can "
            "be loud enough to trip monitoring on the target"),
        "references": [
            "https://www.kali.org/tools/wpscan/",
            "https://github.com/wpscanteam/wpscan",
        ],
    },

    "ffuf": {
        "package": "ffuf",
        "purpose": (
            "general-purpose web fuzzer: fast request fuzzing over "
            "scoped endpoints with flexible filtering and "
            "machine-readable output"),
        "patterns": [
            "ffuf -u <url> -w <wordlist>",
            "ffuf -u <url> -w <wordlist> -X <method>",
            "ffuf -u <url> -w <wordlist> -o <output-file>",
        ],
        "notes": (
            "filtering by response size alone mislabels results on "
            "apps with per-route padding - pair size filters with "
            "status or word-count filters before treating a row as "
            "real"),
        "references": [
            "https://www.kali.org/tools/ffuf/",
            "https://github.com/ffuf/ffuf",
        ],
    },

    "joomscan": {
        "package": "joomscan",
        "purpose": (
            "focused Joomla site auditing: version probing, "
            "component enumeration and configuration review over "
            "one scoped instance"),
        "patterns": [
            "joomscan -u <url>",
            "joomscan -u <url> -ec <component-name>",
            "joomscan -u <url> -o <output-file>",
        ],
        "notes": (
            "version banners misreport on heavily themed installs - "
            "cross-check component rows against the site's own "
            "manifests before ranking them"),
        "references": [
            "https://www.kali.org/tools/joomscan/",
            "https://github.com/OWASP/joomscan",
        ],
    },

    "zap_cli": {
        "package": "pip:zapcli",
        "purpose": (
            "command-line driver for the OWASP proxy above: "
            "scriptable scans, spidering and report generation "
            "against a running engine"),
        "patterns": [
            "zap-cli quick-scan <url>",
            "zap-cli status",
            "zap-cli open-url <url>",
        ],
        "notes": (
            "drives a separate engine process that must already be "
            "running - connection refusals at startup are a state "
            "problem, not a finding. Quick-scan profiles vary "
            "sharply in noise between scanner versions"),
        "references": [
            "https://github.com/Grunny/zap-cli",
        ],
    },

    "whatweb": {
        "package": "whatweb",
        "purpose": (
            "web fingerprinting: identifies content systems, "
            "libraries and server traits from one scoped URL set in "
            "a single fast pass"),
        "patterns": [
            "whatweb <url>",
            "whatweb -a <aggression-level> <url>",
            "whatweb -v <url>",
        ],
        "notes": (
            "fingerprint signatures key on visible markup - "
            "heavily customized front-ends misreport, and one "
            "wrong identification row can mislead an entire "
            "planning branch"),
        "references": [
            "https://www.kali.org/tools/whatweb/",
            "https://github.com/urbanadventurer/WhatWeb",
        ],
    },

    "sslscan": {
        "package": "sslscan",
        "purpose": (
            "cipher-suite and certificate checks on one scoped host: "
            "what protocol versions and cipher choices the endpoint "
            "actually offers"),
        "patterns": [
            "sslscan <host>",
            "sslscan <host>:<port>",
            "sslscan --no-colour <host>",
        ],
        "notes": (
            "endpoint ciphers depend on the client hello it sees - "
            "results differ between scanner versions, and an "
            "end-of-line verdict on one port says little about "
            "another port on the same host"),
        "references": [
            "https://www.kali.org/tools/sslscan/",
            "https://github.com/rbsec/sslscan",
        ],
    },

    "testssl": {
        "package": "testssl.sh",
        "purpose": (
            "deeper protocol assessment than the scanner above: "
            "certificate chains, protocol support and configuration "
            "review for one scoped endpoint"),
        "patterns": [
            "testssl.sh <url>",
            "testssl.sh --severity <severity-level> <url>",
            "testssl.sh --log <url>",
        ],
        "notes": (
            "its grading thresholds are opinionated by design - "
            "medium rows are improvements, not failures. Plan "
            "around the low rows and read the notes column, not "
            "just the grade"),
        "references": [
            "https://www.kali.org/tools/testssl.sh/",
            "https://testssl.sh/",
        ],
    },

    # -------------------------------------------------- password work
    "john": {
        "package": "john",
        "purpose": (
            "audits recovered credential digests on authorized "
            "material only: candidate-word testing to measure and "
            "report the real-world strength of the assessed set"),
        "patterns": [
            "john <hash-file>",
            "john --wordlist=<wordlist> <hash-file>",
            "john --wordlist=<wordlist> --rules <hash-file>",
            "john --show <hash-file>",
        ],
        "notes": (
            "an empty answer after a short dictionary pass means "
            "'not cracked here', not 'strong' - duration, wordlist "
            "and rules all bound the claim. Report scope honestly"),
        "references": [
            "https://www.kali.org/tools/john/",
            "https://www.openwall.com/john/",
        ],
    },

    "hashcat": {
        "package": "hashcat",
        "purpose": (
            "hardware-accelerated sibling of the digest auditor "
            "above: same authorized archives, GPU-scale candidate "
            "testing with explicit attack-mode selection"),
        "patterns": [
            "hashcat -m <hash-type> -a <attack-mode> <hash-file>",
            "hashcat -m <hash-type> -a <attack-mode> <hash-file> "
            "<wordlist>",
            "hashcat -m <hash-type> -a <attack-mode> <hash-file> "
            "<wordlist> -o <output-file>",
        ],
        "notes": (
            "mis-set type numbers silently produce zero candidates "
            "matched while appearing to run normally - always "
            "verify the type against a known sample before "
            "trusting a blank result"),
        "references": [
            "https://www.kali.org/tools/hashcat/",
            "https://hashcat.net/hashcat/",
        ],
    },

    "hydra": {
        "package": "hydra",
        "purpose": (
            "parallel login-audit across supported network services "
            "on authorized scope: tests recovered or approved "
            "credential sets against live service endpoints"),
        "patterns": [
            "hydra -L <userlist> -P <passlist> <target> <service>",
            "hydra -l <username> -P <passlist> <target> <service>",
            "hydra -L <userlist> -P <passlist> -t <threads> <target> "
            "<service>",
        ],
        "notes": (
            "account lockout is a real side effect - throttle "
            "thread counts and confirm the authorization scope "
            "covers the named accounts before any pass. Service "
            "modules misreport on custom banner handling as a bad "
            "credential match"),
        "references": [
            "https://www.kali.org/tools/hydra/",
            "https://github.com/vanhauser-thc/thc-hydra",
        ],
    },

    "medusa": {
        "package": "medusa",
        "purpose": (
            "another parallel login auditor: smaller module family "
            "than the tool above but with steadier threading for "
            "long authorized runs"),
        "patterns": [
            "medusa -H <host-list> -U <userlist> -P <passlist> -M "
            "<service>",
            "medusa -h <target> -U <userlist> -P <passlist> -M "
            "<service>",
            "medusa -H <host-list> -U <userlist> -P <passlist> -M "
            "<service> -t <threads>",
        ],
        "notes": (
            "some service modules treat connection failures as "
            "candidate rejections - verify module version and "
            "hand-check failures before trusting a clean-looking "
            "answer"),
        "references": [
            "https://www.kali.org/tools/medusa/",
            "https://github.com/jmk-foofus/medusa",
        ],
    },

    "cewl": {
        "package": "cewl",
        "purpose": (
            "builds candidate wordlists from the visible vocabulary "
            "of one scoped web property for later authorized digest "
            "or login auditing"),
        "patterns": [
            "cewl <url>",
            "cewl -d <depth> -m <min-length> <url>",
            "cewl <url> -w <output-file>",
        ],
        "notes": (
            "marketing vocabulary and legal boilerplate dominate "
            "the output - the useful candidate material sits in "
            "product names and terms of art, not page text volume"),
        "references": [
            "https://www.kali.org/tools/cewl/",
            "https://github.com/digininja/CeWL",
        ],
    },

    "crunch": {
        "package": "crunch",
        "purpose": (
            "deterministic candidate-sequence generator: expands "
            "character-set rules into exact candidate streams for "
            "later authorized auditing"),
        "patterns": [
            "crunch <min-length> <max-length>",
            "crunch <min-length> <max-length> <charset>",
            "crunch <min-length> <max-length> <charset> -o "
            "<output-file>",
        ],
        "notes": (
            "output size grows combinatorially with length and "
            "charset width - compute the file size before running "
            "or the host runs out of disk as the 'failure'"),
        "references": [
            "https://www.kali.org/tools/crunch/",
        ],
    },

    "hash_identifier": {
        "package": "hash-identifier",
        "purpose": (
            "digest-format classifier over recovered material: "
            "propose the encoding family so later auditing uses the "
            "right mode"),
        "patterns": [
            "hash-identifier",
            "hash-identifier <digest-string>",
        ],
        "notes": (
            "similar digest families have near-identical shapes - "
            "top guesses can be wrong in both family and length, so "
            "propose a ranked candidate list rather than a single "
            "answer. The upstream binary opens an interactive "
            "prompt - the digest-string shape mirrors the registry "
            "arg schema, fed through the prompt in practice"),
        "references": [
            "https://www.kali.org/tools/hash-identifier/",
        ],
    },

    "rsmangler": {
        "package": "rsmangler",
        "purpose": (
            "mangles a seed vocabulary into permuted candidate "
            "variations for later authorized auditing - the "
            "dictionary layer between harvest and audit"),
        "patterns": [
            "rsmangler --file <input-file>",
            "rsmangler --file <input-file> --output <output-file>",
            "rsmangler -f <input-file> --min-length=<min-length>",
        ],
        "notes": (
            "permutation count explodes with seed size - cap the "
            "seed list or the mangled output is unusable by the "
            "time it finishes writing"),
        "references": [
            "https://www.kali.org/tools/rsmangler/",
            "https://github.com/digininja/RSMangler",
        ],
    },

    # -------------------------------------------------- exploitation
    "metasploit": {
        "package": "metasploit-framework",
        "purpose": (
            "console-driven assessment framework: query the module "
            "inventory, review module options and record engagement "
            "sessions in authorized workspaces"),
        "patterns": [
            "msfconsole",
            "msfconsole -q",
            "msfconsole -q -r <resource-file>",
        ],
        "notes": (
            "module option defaults are engagement-specific - "
            "trusting a module's defaults without review is the "
            "fastest path to noisy, out-of-scope behavior. Keep the "
            "module inventory query as the planning step"),
        "references": [
            "https://www.kali.org/tools/metasploit-framework/",
            "https://docs.metasploit.com/",
        ],
    },

    "searchsploit": {
        "package": "exploitdb",
        "purpose": (
            "offline search over the public known-issue archive: "
            "pairs service and software versions with matching "
            "archive entries during authorized planning"),
        "patterns": [
            "searchsploit <query-string>",
            "searchsploit --exact <query-string>",
            "searchsploit --nmap <output-file>",
        ],
        "notes": (
            "archive rows frequently carry version-pinned titles "
            "that overstate applicability - verify the exact "
            "affected-version range before ranking a row as "
            "plausible"),
        "references": [
            "https://www.kali.org/tools/exploitdb/",
            "https://www.exploit-db.com/searchsploit",
        ],
    },

    # -------------------------------------------- post-exploitation
    "mimikatz": {
        "package": "mimikatz",
        "purpose": (
            "windows credential-material review for authorized "
            "post-position work only: documents what the assessed "
            "host exposes when an assessor reaches it"),
        "patterns": [
            "mimikatz",
            "mimikatz -h",
        ],
        "notes": (
            "this is high-impact and heavily monitored tooling - "
            "run it only where engagement paperwork explicitly "
            "covers it and record every invocation"),
        "references": [
            "https://www.kali.org/tools/mimikatz/",
            "https://github.com/gentilkiwi/mimikatz",
        ],
    },

    "bloodhound": {
        "package": "bloodhound.py",
        "purpose": (
            "maps directory-domain trust relationships over "
            "authorized scope: collects relationships for graph "
            "analysis of path surfaces in the assessed domain"),
        "patterns": [
            "bloodhound-python -d <domain> -u <username> -p "
            "<authorized-credential> -c <collection-classes>",
            "bloodhound-python -d <domain> -u <username> -p "
            "<authorized-credential> -ns <name-server>",
            "bloodhound-python -d <domain> -u <username> -p "
            "<authorized-credential> -c <collection-classes> --zip",
        ],
        "notes": (
            "collection classes vary hugely in volume - the full "
            "class set can take tens of minutes and stands out in "
            "monitoring - prefer the minimum classes that answer "
            "the planning question"),
        "references": [
            "https://www.kali.org/tools/bloodhound/",
            "https://github.com/fox-it/BloodHound.py",
        ],
    },

    "empire": {
        "package": "powershell-empire",
        "purpose": (
            "post-position framework with listener and staging "
            "surface for authorized, paperwork-covered engagements "
            "only - planned here, executed only by the operator"),
        "patterns": [
            "powershell-empire server --version",
            "powershell-empire server --help",
        ],
        "notes": (
            "listener state lingers between console sessions - "
            "record listener teardown in the engagement notes or "
            "the assessed side keeps visible surfaces up after "
            "the test window closes"),
        "references": [
            "https://www.kali.org/tools/powershell-empire/",
        ],
    },

    "lazagne": {
        "package": "github:AlessandroZ/LaZagne",
        "purpose": (
            "recover-stored-material review for authorized "
            "post-position work: inventories locally retained "
            "credential stores and reports what the host exposes"),
        "patterns": [
            "lazagne <command-class>",
            "lazagne <command-class> -o <output-file>",
        ],
        "notes": (
            "antivirus engines flag it by name, not behavior - a "
            "detection is expected and not a finding by itself. "
            "authorization paperwork should anticipate it"),
        "references": [
            "https://github.com/AlessandroZ/LaZagne",
        ],
    },

    # ------------------------------------------------------- wireless
    "aircrack_ng": {
        "package": "aircrack-ng",
        "purpose": (
            "wireless assessment suite over authorized captures: "
            "digest auditing of collected handshakes and network "
            "survey analysis"),
        "patterns": [
            "aircrack-ng <capture-file>",
            "aircrack-ng -b <bssid> <capture-file>",
            "aircrack-ng -w <wordlist> -b <bssid> <capture-file>",
        ],
        "notes": (
            "capture quality dominates - partial or noisy captures "
            "produce empty answers that read as impossible targets "
            "when the real problem is the capture"),
        "references": [
            "https://www.kali.org/tools/aircrack-ng/",
            "https://www.aircrack-ng.org/",
        ],
    },

    "kismet": {
        "package": "kismet",
        "purpose": (
            "wireless survey tool: detects and inventories nearby "
            "networks and channels for authorized site reviews"),
        "patterns": [
            "kismet",
            "kismet -c <capture-interface>",
            "kismet -c <capture-interface> --log-title <label>",
        ],
        "notes": (
            "channel-hopping spreads detection thin - quick runs "
            "under-report quiet networks, so surveys need a stated "
            "residence time to mean anything"),
        "references": [
            "https://www.kali.org/tools/kismet/",
            "https://www.kismetwireless.net/",
        ],
    },

    "reaver": {
        "package": "reaver",
        "purpose": (
            "provisioning-protocol weakness assessment for "
            "authorized wireless scope only: tests the enrollment "
            "protocol's exposure on a scoped access point"),
        "patterns": [
            "reaver -i <interface> -b <bssid>",
            "reaver -i <interface> -b <bssid> -t <timeout>",
        ],
        "notes": (
            "runs are slow and access points can rate-limit or "
            "lock during the protocol exchange - a stop without an "
            "answer may be the target hardening mid-test"),
        "references": [
            "https://www.kali.org/tools/reaver/",
            "https://github.com/t6x/reaver-wps-fork-t6x",
        ],
    },

    "wifite": {
        "package": "wifite",
        "purpose": (
            "automated orchestrator over the wireless suite: chains "
            "survey, capture and digest work into one guided flow "
            "for authorized scope"),
        "patterns": [
            "wifite",
            "wifite --kill",
            "wifite --target=<target-bssid>",
        ],
        "notes": (
            "automation chains several noisy steps in one go - "
            "confirm every stage it picks is inside the authorized "
            "scope before letting it continue"),
        "references": [
            "https://www.kali.org/tools/wifite/",
            "https://github.com/derv82/wifite2",
        ],
    },

    "mdk4": {
        "package": "mdk4",
        "purpose": (
            "protocol-level wireless testing modes for authorized "
            "lab and controlled-scope work: beacon, denial and "
            "roaming test modes exercised deliberately"),
        "patterns": [
            "mdk4 <interface> <attack-mode>",
            "mdk4 <interface> <attack-mode> -b <bssid>",
        ],
        "notes": (
            "affecting the shared spectrum is not scoped to one "
            "client - every mode here disturbs third parties on "
            "those channels. Lab-only unless paperwork says "
            "otherwise"),
        "references": [
            "https://github.com/aircrack-ng/mdk4",
        ],
    },

    # -------------------------------------------------------------- io
    "wireshark": {
        "package": "tshark",
        "purpose": (
            "protocol analysis on scoped captures or live "
            "interfaces: the command-line face for reading traffic "
            "and captures during assessment"),
        "patterns": [
            "tshark -i <interface>",
            "tshark -i <interface> -a <capture-cap>",
            "tshark -r <capture-file>",
            "tshark -r <capture-file> -Y <display-filter>",
        ],
        "notes": (
            "display filters and capture filters have different "
            "grammars - a filter that parses under the wrong "
            "grammar silently returns nothing instead of erroring "
            "for the common field-name mistakes"),
        "references": [
            "https://www.kali.org/tools/wireshark/",
            "https://www.wireshark.org/docs/",
        ],
    },

    "responder": {
        "package": "responder",
        "purpose": (
            "name-resolution exposure testing on authorized "
            "networks only: observes whether name-resolution trust "
            "on the local segment leaks credentials to the "
            "assessor"),
        "patterns": [
            "responder -I <interface>",
            "responder -I <interface> -A",
            "responder -I <interface> -w <output-file>",
        ],
        "notes": (
            "any capture here is a real finding by itself, and the "
            "analyze-mode flag changes what is captured - log the "
            "mode used or the evidence is not reproducible"),
        "references": [
            "https://www.kali.org/tools/responder/",
            "https://github.com/lgandx/Responder",
        ],
    },

    # ------------------------------------------------------ forensics
    "volatility": {
        "package": "volatility",
        "purpose": (
            "memory-image analysis: profile identification and "
            "process, network and artifact enumeration over one "
            "authorized memory capture"),
        "patterns": [
            "volatility -f <memory-file> <plugin>",
            "volatility -f <memory-file> --profile=<profile> <plugin>",
            "volatility -f <memory-file> -o <output-file> <plugin>",
        ],
        "notes": (
            "profile mismatch yields zero rows rather than an "
            "error - a quiet answer usually means the wrong "
            "profile guess, not an empty image"),
        "references": [
            "https://github.com/volatilityfoundation/volatility",
        ],
    },

    "binwalk": {
        "package": "binwalk",
        "purpose": (
            "firmware and image inspection: signature walking over "
            "one authorized image to find embedded filesystems and "
            "payload-free sections for analysis"),
        "patterns": [
            "binwalk <image-file>",
            "binwalk -e <image-file>",
            "binwalk <image-file> --dd=<extension-class>",
        ],
        "notes": (
            "auto-extraction can execute bundled compression "
            "tooling on untrusted content - do extraction only in "
            "disposable environments and keep signature scanning "
            "read-only while surveying"),
        "references": [
            "https://www.kali.org/tools/binwalk/",
            "https://github.com/ReFirmLabs/binwalk",
        ],
    },

    "sleuthkit": {
        "package": "sleuthkit",
        "purpose": (
            "filesystem analysis over authorized disk images: "
            "directory listings, file metadata and timeline "
            "enumeration without mounting"),
        "patterns": [
            "fls <image-file>",
            "fls -r <image-file>",
            "fls -o <sector-offset> <image-file>",
        ],
        "notes": (
            "sector offsets differ between partition layouts - "
            "listing from the wrong offset shows an empty or "
            "garbled root instead of an error"),
        "references": [
            "https://www.kali.org/tools/sleuthkit/",
            "https://www.sleuthkit.org/sleuthkit/",
        ],
    },

    "foremost": {
        "package": "foremost",
        "purpose": (
            "signature-based file carving over authorized images: "
            "recovers embedded files by structure where filesystem "
            "views stop resolving"),
        "patterns": [
            "foremost -i <input-file> -o <output-dir>",
            "foremost -i <input-file> -o <output-dir> -t "
            "<type-list>",
        ],
        "notes": (
            "carving over-claims: media containers and archives "
            "fragment, so recovered rows include false positives "
            "that look intact - verify each recovered file "
            "actually parses"),
        "references": [
            "https://www.kali.org/tools/foremost/",
        ],
    },

    "exiftool": {
        "package": "libimage-exiftool-perl",
        "purpose": (
            "metadata reading and writing over one or many "
            "authorized files: the standard reader for authored "
            "timestamps, device traces and document properties"),
        "patterns": [
            "exiftool <file>",
            "exiftool -r <dir>",
            "exiftool -s <file>",
        ],
        "notes": (
            "metadata rows are trivially editable - treat them as "
            "an assertion by whoever last touched the file, never "
            "as ground truth"),
        "references": [
            "https://exiftool.org/",
        ],
    },

    # ------------------------------------------------ social / malware
    "setoolkit": {
        "package": "set",
        "purpose": (
            "guided social-engineering exercise framework for "
            "authorized, paperwork-covered engagements: structures "
            "awareness-testing campaigns the engagement owns"),
        "patterns": [
            "setoolkit",
            "setoolkit <menu-selection>",
        ],
        "notes": (
            "campaign surfaces touch real people - every step "
            "needs explicit authorization for the affected "
            "workforce, and template content must match the "
            "engagement's documented scope before launch. The "
            "toolkit is strictly menu-driven - the menu-selection "
            "shape notes the interactive path, not a command flag"),
        "references": [
            "https://www.kali.org/tools/set/",
            "https://github.com/trustedsec/social-engineer-toolkit",
        ],
    },
}


def kali_registry() -> dict:
    sys.path.insert(0, str(ROOT))
    from agentic_ai.agents.cyber.kali import KALI_TOOLS_DB
    return dict(KALI_TOOLS_DB)


_PLACEHOLDER = re.compile(r"<[a-z][a-z0-9-]*>")


def validate_rows(rows: dict, registry: dict) -> None:
    """Loud invariants between the curated literals and the registry.

    Exact key-set equality (both directions) so a registry add/remove
    or a curation typo fails the build instead of shipping a stale or
    missing one-pager. Every curated reference must be https, every
    pattern a string of 2..4, notes and purpose non-empty, and the
    first pattern token must be the registry row's command binary.
    """
    if set(rows) != set(registry):
        missing = sorted(set(registry) - set(rows))
        extra = sorted(set(rows) - set(registry))
        raise ValueError(
            "curated/tool key mismatch: missing=%s extra=%s"
            % (missing, extra))
    for tool, row in sorted(rows.items()):
        binary = BINARY_OVERRIDES.get(tool,
                                      registry[tool].command)
        patterns = row["patterns"]
        if not isinstance(patterns, list) or \
                not 2 <= len(patterns) <= 4:
            raise ValueError("%s: want 2-4 patterns" % tool)
        first_token = patterns[0].split(" ", 1)[0]
        if first_token != binary:
            raise ValueError(
                "%s: first pattern token %r is not the command "
                "binary %r" % (tool, first_token, binary))
        for pattern in patterns:
            if not pattern.strip() or pattern.strip() != pattern:
                raise ValueError(
                    "%s: pattern not a bare token string: %r"
                    % (tool, pattern))
        if tool not in INTERACTIVE_LAUNCHERS and not any(
                _PLACEHOLDER.search(p) for p in patterns):
            raise ValueError(
                "%s: no pattern carries a <placeholder>" % tool)
        for field in ("package", "purpose", "notes"):
            if not str(row[field]).strip():
                raise ValueError("%s: empty %s" % (tool, field))
        references = row["references"]
        if not isinstance(references, list) or \
                not 1 <= len(references) <= 2:
            raise ValueError(
                "%s: want 1-2 verified references" % tool)
        for url in references:
            if not url.startswith("https://"):
                raise ValueError("%s: non-https url %r" % (tool, url))


def build_catalog(registry: dict) -> dict:
    """Canonical catalog: entries sorted by tool key, keys sorted at
    serialization, meta totals computed by count (drift alarm)."""
    entries = [
        {
            "tool": tool,
            "package": CURATED_ROWS[tool]["package"],
            "purpose": CURATED_ROWS[tool]["purpose"],
            "command_patterns": list(CURATED_ROWS[tool]["patterns"]),
            "false_positive_notes": CURATED_ROWS[tool]["notes"],
            "references": list(CURATED_ROWS[tool]["references"]),
        }
        for tool in sorted(CURATED_ROWS)
    ]
    entries.sort(key=lambda entry: entry["tool"])
    totals = {
        "command_patterns": sum(
            len(entry["command_patterns"]) for entry in entries),
        "references": sum(
            len(entry["references"]) for entry in entries),
        "tools": len(entries),
    }
    return {
        "entries": entries,
        "meta": {
            "policy": POLICY,
            "source": SOURCE,
            "totals": totals,
            "url_count": len({
                url for entry in entries for url in entry["references"]}),
            "urls_verified": URLS_VERIFIED,
        },
    }


def check_url_once(url: str, timeout: int = URL_TIMEOUT):
    """One polite bounded live check of a single catalog URL.

    Returns the final HTTP status code (after redirects), or an error
    string. Honors 429/Retry-After once (bounded wait), then gives up -
    candidates that fail here are dropped from the curated rows, never
    shipped dead.
    """
    import time
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
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


def polite_sweep(urls, timeout: int = URL_TIMEOUT):
    """Bounded polite sequential sweep: sorted unique urls, per-host
    politeness gap between host hits, one pass, no retries except the
    single 429 re-check. Returns a results list [(url, code-or-error)].
    """
    import time
    from urllib.parse import urlsplit

    ordered = sorted(set(urls))
    results = []
    last_seen = {}
    for url in ordered:
        host = urlsplit(url).netloc
        wait = last_seen.get(host, 0.0) + HOST_MIN_INTERVAL - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        last_seen[host] = time.monotonic()
        results.append((url, check_url_once(url, timeout=timeout)))
    return results


def _candidate_urls() -> list:
    return sorted({
        url for row in CURATED_ROWS.values()
        for url in row["references"]})


def main() -> int:
    registry = kali_registry()
    validate_rows(CURATED_ROWS, registry)
    catalog = build_catalog(registry)

    args = sys.argv[1:]
    if args and args[0] == "--live":
        results = polite_sweep(_candidate_urls())
        dead = [(url, outcome) for url, outcome in results
                if outcome != 200]
        for url, outcome in dead:
            print("DEAD: %s -> %s" % (url, outcome))
        print("TOOLKB-LIVE checked=%d dead=%d"
              % (len(results), len(dead)))
        return 1 if dead else 0

    out = OUT
    rest = list(args)
    if rest and rest[0] == "--out":
        if len(rest) < 2:
            raise SystemExit("--out needs a path argument")
        out = pathlib.Path(rest[1])
        rest = rest[2:]
    if rest and rest[0].startswith("--"):
        raise SystemExit("unknown build-tool flag: %s" % rest[0])
    if rest:
        raise SystemExit("unexpected build-tool argument: %r" % (rest[0],))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(catalog, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")
    totals = catalog["meta"]["totals"]
    print("TOOLKB-OK tools=%d patterns=%d references=%d out=%s"
          % (totals["tools"], totals["command_patterns"],
             totals["references"], out))
    return 0


if __name__ == "__main__":
    sys.exit(main())