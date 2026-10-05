#!/usr/bin/env python3
"""Build agentic_ai/agents/cyber/data/xss_tools.json.

XSS tooling catalog for the kali agents: callback/OOB infrastructure,
browser control, fuzzing, analysis, and proxying. Unlike the red-team
builder (which parses a 725-link directory), this curation is small enough
to live entirely in the builder: entries are hand-curated rows and the
source sheet is a methodology cheat sheet, not a link directory, so the
tool table is what imports.

Source material: structure inspired by evanesoteric's public XSS
exploitation cheat sheet gist cfd5fadc6cf2c4d7f7d8b960d797b3d1 (no
license) - re-authored in-house. Rows carry NAMES + REPOSITORY/HOME LINKS
+ PURPOSES only - no payloads, no exploit code, no evasion snippets
(policy is in the file's meta and enforced by tests). Every URL was
verified live (HTTP 200) on 2026-10-04 before landing; unverifiable
candidates were dropped (the firesun/xsshunter-express fork, ezxss.net,
beefproject.com's own site all failed that check and are not here). The
dalfox row is a house standard added beyond the source sheet, noted in
meta.
"""
import json
import pathlib

OUT = pathlib.Path('/home/wez/agentic-ai/agentic_ai/agents/cyber/data/xss_tools.json')
OUT.parent.mkdir(parents=True, exist_ok=True)

SOURCE = ("inspired by evanesoteric's public XSS exploitation cheat sheet "
          "gist cfd5fadc6cf2c4d7f7d8b960d797b3d1 (no license) - re-authored "
          "in-house; dalfox added as a house standard")
POLICY = ("names + links + purposes only; no payloads, exploit code, or "
          "evasion snippets")

# phase <- section mapping (in-house canonical phases)
# sections record which source-sheet areas the rows came from
PHASES = {
    "callback-infra": {
        "sections": ["Payload Delivery & Callback Infrastructure",
                     "Tooling Cheat Sheet (OOB Callbacks, Blind XSS Platform)"],
        "tools": [
            {"name": "Burp Collaborator",
             "url": "https://portswigger.net/burp/documentation/collaborator",
             "purpose": "OOB interaction DNS/HTTP callbacks auto-injected as "
                        "unique subdomains; built into Burp Pro"},
            {"name": "Interactsh",
             "url": "https://github.com/projectdiscovery/interactsh",
             "purpose": "Free OOB interaction client, self-hostable server; "
                        "records DNS/HTTP/SMTP callbacks"},
            {"name": "XSS Hunter",
             "url": "https://xsshunter.com",
             "purpose": "Blind XSS collection service: screenshots, DOM and "
                        "cookie capture on trigger"},
            {"name": "ezXSS",
             "url": "https://github.com/ssl/ezXSS",
             "purpose": "Self-hostable blind-XSS callback platform with "
                        "reporting"},
            {"name": "Canarytokens",
             "url": "https://canarytokens.org",
             "purpose": "Token-based beacons usable where a full callback "
                        "platform is overkill"},
        ],
    },
    "browser-control": {
        "sections": ["Tooling Cheat Sheet (Browser Control)"],
        "tools": [
            {"name": "BeEF",
             "url": "https://github.com/beefproject/beef",
             "purpose": "Browser exploitation framework: hooked-browser "
                        "command modules (authorized engagements only)"},
        ],
    },
    "fuzzing": {
        "sections": ["Tooling Cheat Sheet (Payload Fuzzing)"],
        "tools": [
            {"name": "ffuf",
             "url": "https://github.com/ffuf/ffuf",
             "purpose": "Fast web fuzzer; reflection-detection mode over "
                        "parameter wordlists"},
            {"name": "XSStrike",
             "url": "https://github.com/s0md3v/XSStrike",
             "purpose": "XSS detection suite: fuzzer, context analysis, "
                        "blind-mode scanning"},
            {"name": "dalfox",
             "url": "https://github.com/hahwul/dalfox",
             "purpose": "Parameter-analysis and XSS scanner CLI (house "
                        "standard; url/pix/pipe modes)"},
        ],
    },
    "analysis": {
        "sections": ["Tooling Cheat Sheet (CSP Analysis, Encoding, DOM Sinks)"],
        "tools": [
            {"name": "Google CSP Evaluator",
             "url": "https://csp-evaluator.withgoogle.com",
             "purpose": "Content-Security-Policy strength inspection"},
            {"name": "CyberChef",
             "url": "https://gchq.github.io/CyberChef",
             "purpose": "Encoding/decoding workbench (Magic mode); analysis "
                        "side and report payload use"},
            {"name": "domloggerpp",
             "url": "https://github.com/kevin-mizu/domloggerpp",
             "purpose": "Burp extension logging DOM sink invocations "
                        "(taint-style DOM XSS review)"},
        ],
    },
    "proxying": {
        "sections": ["Tooling Cheat Sheet (Proxy)"],
        "tools": [
            {"name": "Burp Suite",
             "url": "https://portswigger.net/burp",
             "purpose": "Intercepting proxy; Intruder and Repeater drive "
                        "reflection work"},
            {"name": "Caido",
             "url": "https://caido.io",
             "purpose": "Proxy alternative with replay automations"},
            {"name": "OWASP ZAP",
             "url": "https://www.zaproxy.org",
             "purpose": "Proxy/scanner; headless CLI available for "
                        "pipeline scans"},
        ],
    },
}


def main():
    tools_total = sum(len(p["tools"]) for p in PHASES.values())
    data = {
        "phases": {p: {"sections": e["sections"],
                       "tools": [dict(t) for t in e["tools"]]}
                   for p, e in sorted(PHASES.items())},
        "meta": {
            "source": SOURCE,
            "policy": POLICY,
            "totals": {"phases": len(PHASES), "tools": tools_total},
        },
    }
    OUT.write_text(json.dumps(data, indent=1) + "\n")
    print("XSS-CATALOG-OK phases=%d tools=%d out=%s"
          % (len(PHASES), tools_total, OUT))


if __name__ == "__main__":
    main()