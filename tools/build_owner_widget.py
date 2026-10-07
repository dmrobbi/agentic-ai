#!/usr/bin/env python3
"""Build data/owner_widget.json - KA-100 owner one-glance widget sample.

Thin CLI over the pure module
agentic_ai/agents/cyber/owner_widget.py: the module holds ALL structure
and never runs pytest, never touches disk or network; this script alone
wires the real sources in and degrades each one to None whenever it is
unavailable - the widget can never crash on a missing input:

- suite state: the committed offline sample ships the degraded ("unknown")
  state; ONLY --probe runs the real pytest suite (a --collect-only pass
  for the total + a -q pass for the summary verdict, read through the
  module's grep-equivalent parsers, never tail). The script is the only
  place this builder pair runs pytest, and only when asked.
- CVE-DB coverage %: a read-only parse of the committed match eval
  corpus (tests/fixtures/cve/cve_eval_corpus.json - the 80+ real CVEs
  pinning the expected exploit modules) + a lazy, read-only import of
  the real CVEMatchingEngine / CVE_EXPLOIT_DB (agentic_ai/agents/cyber/
  kali_v2.py); any import/parse failure degrades the inputs to None and
  the metric to unknown.
- last battery run: only from --battery-log PATH (a transcript of the
  owner-gated scripts/lab/pve-lab-battery.sh; the parse convention is
  documented in the module). No path -> metric skipped (unknown); the
  recipe lives in docs/KA-LAB-TARGET.md.
- evidence count: artifact files discovered recursively under
  kali_agent_v4/evidence/ (the EVIDENCE_PACKAGE pattern) when the tree
  is discoverable, else None.

Links are curated constants only - every URL was verified live at
curation time (2026-10-07, bounded fetch); dead candidates are dropped
and recorded HERE, in this docstring only - never in the emitted data:
  - https://github.com/wezzels/kaliagent-v4 -> 404 while the kali
    agent's GITHUB_MIRROR.md still asserts the mirror lives; not linked.

Curated (verified live 2026-10-07):
  - https://github.com/dmrobbi/agentic-ai (public mirror of this repo)
  - https://github.com/dmrobbi/agentic-ai/blob/main/tests/fixtures/cve/
    cve_eval_corpus.json (the committed coverage corpus)

The default run is OFFLINE and deterministic: no wall-clock reads (the
"generated" stamp is the curated date constant in the module), and the
committed sample stays byte-stable across reruns of the same committed
sources (suite state is only measured under --probe, so regenerating is
an explicit refresh, exactly as the committed file's docstring-ish meta
records). Output: {schema, generated, blocks: [metrics, table, links?]}
written indent-1 with a trailing newline - canonical field order.

Flags:
  --json PATH       output path override (default data/owner_widget.json)
  --battery-log P   optional battery transcript to parse (skipped when absent)
  --probe           run the real pytest collect-only + suite (tool-only)
  --json-text       print the payload JSON instead of writing it

Purity: this script may import the engine lazily and may run pytest
under --probe only; the module it wraps stays pure forever.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentic_ai.agents.cyber import owner_widget as OW  # the pure module

OUT = ROOT / "data" / "owner_widget.json"
CORPUS_FIXTURE = (ROOT / "tests" / "fixtures" / "cve"
                  / "cve_eval_corpus.json")
EVIDENCE_DIR = ROOT / "kali_agent_v4" / "evidence"
GENERATED = OW.GENERATED
PROBE_TIMEOUT = 900

LINKS_VERIFIED = "2026-10-07"
CURATED_LINKS = [
    {
        "label": "kali fleet repo (public github mirror)",
        "url": "https://github.com/dmrobbi/agentic-ai",
        "detail": "repo the widget sample ships in; link verified live "
                  + LINKS_VERIFIED,
    },
    {
        "label": "CVE matching eval corpus (the coverage source)",
        "url": "https://github.com/dmrobbi/agentic-ai/blob/main/tests/"
               "fixtures/cve/cve_eval_corpus.json",
        "detail": "committed 83-entry corpus the coverage % is measured "
                  "over; link verified live " + LINKS_VERIFIED,
    },
]

SAMPLE_SUITE_NOTE = (
    "sample regenerates any time via tools/build_owner_widget.py;"
    " --probe measures the suite live")


def lazy_coverage():
    """The real corpus + engine, lazily and read-only: (corpus, matcher)
    or (None, None) on any failure - a missing fixture or import can
    never crash the build."""
    try:
        corpus = json.loads(CORPUS_FIXTURE.read_text(encoding="utf-8"))
        from agentic_ai.agents.cyber.kali_v2 import CVEMatchingEngine
        return corpus, CVEMatchingEngine()
    except Exception as exc:
        print("WARN coverage unavailable: %s" % exc, file=sys.stderr)
        return None, None


def discover_evidence(path=EVIDENCE_DIR):
    """Evidence artifact FILES under path, recursively (the EVIDENCE_PACKAGE
    pattern); [] when the tree is missing - the caller degrades."""
    if not path.is_dir():
        return []
    return sorted(
        str(found.relative_to(path))
        for found in path.rglob("*") if found.is_file())


def battery_from_log(path):
    """Parse the battery transcript at path, or None when no path was
    given or the file is absent (the metric then skips - never crashes)."""
    if not path:
        return None
    log_path = pathlib.Path(path)
    if not log_path.is_file():
        print("WARN battery log absent: %s (metric skipped)" % log_path,
              file=sys.stderr)
        return None
    return OW.parse_battery_log(
        log_path.read_text(encoding="utf-8", errors="replace"))


def probe_suite(timeout=PROBE_TIMEOUT):
    """--probe ONLY: run the real pytest collect-only pass (the total) and
    the suite (the verdict), parsed by the module's grep-equivalent
    parsers; (None, None) on timeout/exec failure."""
    def run(*args):
        return subprocess.run(
            [sys.executable, "-m", "pytest", *args, "-p", "no:cacheprovider"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=timeout)

    try:
        collect = run("--collect-only", "-q", "tests/")
        suite = run("-q", "tests/")
    except (subprocess.TimeoutExpired, OSError) as exc:
        print("WARN suite probe failed: %s" % exc, file=sys.stderr)
        return None, None
    output = "\n".join(part for part in (suite.stdout, suite.stderr) if part)
    return OW.parse_collect_total(collect.stdout), OW.parse_verdict(output)


def offline_payload_text():
    """The OFFLINE sample payload text - the exact committed data/
    owner_widget.json bytes: lazily imported coverage inputs, discovered
    evidence count, no suite probe, no battery log."""
    corpus, matcher = lazy_coverage()
    evidence = discover_evidence()
    payload = OW.build_payload(
        corpus=corpus,
        matcher=matcher,
        battery=None,
        evidence_count=len(evidence) or None,
        links=CURATED_LINKS,
        generated=GENERATED,
        suite_note=SAMPLE_SUITE_NOTE,
        evidence_note="regenerate via tools/build_owner_widget.py when the"
                      " evidence tree changes",
    )
    return OW.payload_json_text(payload)


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    out, battery_path, probe, print_text = OUT, None, False, False
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag == "--json":
            if index + 1 >= len(argv):
                raise SystemExit("--json needs a path argument")
            out = pathlib.Path(argv[index + 1])
            index += 2
        elif flag == "--battery-log":
            if index + 1 >= len(argv):
                raise SystemExit("--battery-log needs a path argument")
            battery_path = argv[index + 1]
            index += 2
        elif flag == "--probe":
            probe = True
            index += 1
        elif flag == "--json-text":
            print_text = True
            index += 1
        elif flag.startswith("-"):
            raise SystemExit("unknown build-owner-widget flag: %s" % flag)
        else:
            raise SystemExit("unexpected argument: %r" % (flag,))

    collected = verdict = None
    if probe:
        collected, verdict = probe_suite()
    corpus, matcher = lazy_coverage()
    battery = battery_from_log(battery_path)
    evidence = discover_evidence()
    payload = OW.build_payload(
        collected_total=collected,
        verdict=verdict,
        corpus=corpus,
        matcher=matcher,
        battery=battery,
        evidence_count=len(evidence) or None,
        links=CURATED_LINKS,
        generated=GENERATED,
        suite_note=None if probe else SAMPLE_SUITE_NOTE,
        evidence_note="regenerate via tools/build_owner_widget.py when the"
                      " evidence tree changes",
    )
    text = OW.payload_json_text(payload)
    if print_text:
        sys.stdout.write(text)
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    metrics = payload["blocks"][0]["items"]
    print("OWNER-WIDGET-OK out=%s blocks=%d suite=%s coverage=%s battery=%s"
          " evidence=%s" % (out, len(payload["blocks"]),
                            metrics[0]["value"], metrics[1]["value"],
                            metrics[2]["value"], metrics[3]["value"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())