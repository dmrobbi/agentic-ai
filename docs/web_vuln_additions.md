# KA-048 · WEB_VULN_CLASSES +10 — proposed catalog

Status: **proposal, pre-merge**. Authored by builder KA-048 (option [48],
"Planner/methodology depth"). The merge into the module is **KA-INT-3**'s
task; KA-048 ships only this document and `tests/test_web_vuln_extended.py`.

## The proposed rows (single source of truth)

The block below is the complete proposed addition. The test file parses
THIS block (ast.literal_eval of the assignment — no code execution) and
pins everything: key set, field parity, scrub survival, payload policy.
Merge it exactly as written.

```python
WEB_VULN_ADDITIONS = {
    "insecure-deserialization":
        ("serialization-baseline",
         ("phpggc -l",
          "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -x jar,ser,bin -t 20")),
    "xxe": ("xxe-probes",
            ("gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -x xml,dtd -t 20",
             "curl -sS -I --max-time 15 http://{target}/xmlrpc.php")),
    "race-conditions": ("race-probes",
                        ("nuclei -u http://{target} -t race-gate.yaml",
                         "ab -n 500 -c 50 http://{target}/single-use-endpoint")),
    "prototype-pollution": ("pollution-probes",
                            ("arjun -u http://{target}",
                             "waybackurls {target}")),
    "idor": ("idor-probes",
             ("arjun -u http://{target}",
              "ffuf -u http://{target}/account/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301")),
    "request-smuggling": ("smuggling-probes",
                          ("python3 smuggler.py -u http://{target}",
                           "python3 smuggler.py -u http://{target} -x")),
    "cache-poisoning": ("cache-probes",
                        ("curl -sS -D - -o /dev/null http://{target}/",
                         "curl -sS -D - -o /dev/null -H Via:cache-probe http://{target}/")),
    "webdav-traversal": ("webdav-probes",
                         ("davtest -url http://{target}/dav/",
                          "nmap -p 80,443 --script http-webdav-scan {target}",
                          "cadaver http://{target}/dav/")),
    "graphql": ("graphql-baseline",
                ("python3 graphql-cop.py -t http://{target}",
                 "python3 main.py -f -t http://{target}/graphql")),
    "dns-rebinding-ssrf": ("rebinding-probes",
                           ("dig +trace {target}",
                            "curl -sS -I --max-time 15 http://{target}/")),
}
```

## Field parity contract

Each row mirrors `agentic_ai/agents/cyber/web_pentest.py::WEB_VULN_CLASSES`
exactly — same keys/shapes as the existing ten rows: the value is a
2-tuple `(<step>, (<command>, ...))`, the step label is lowercase kebab,
and every command is a non-empty string. At least one command per class
carries the `{target}` slot, which is rendered **only** inside
`WebPentestMixin.web_vuln_commands` after the target passes
`wp_scrub_target`. Commands without the slot are harmless offline
inventory (same precedent as the existing `auth` row's hashcat line).

## Scrub + payload policy (no payload drift)

- Every command above, and its rendered form, must survive the module's
  real scrubber (`wp_scrub_target`) with **zero deviations** except
  word-separator spaces: command templates legitimately contain spaces
  (the scrubber's home ground is targets), so the pin maps separator
  spaces to a stand-in character and then requires the scrubber to
  return the template unchanged — no control characters, no shell
  metacharacters (`; | & backtick $ ( ) < > " '`), no traversal dots
  (`..`).
- The `{target}` slot is the only input channel: rendering substitutes a
  scrubbed target (no control characters, no shell tricks) and every
  occurrence must be replaced.
- No proposed row contains payload or exploit strings — this is a
  methodology catalog: tool invocations, wordlist references, discovery
  surfaces and benign marker strings only. Gadget, payload and malformed
  request construction stays with the operator, subject to the normal
  execution gates; nothing lands in the catalog that could double as a
  copy-paste exploit.

## Per-class methodology notes (in-house wording)

- `insecure-deserialization`: PHP gadget-chain inventory and discovery of
  serialized-object file surfaces (jar/ser/bin extensions).
- `xxe`: XML/DTD surface discovery plus reachability probe of XML-RPC
  interfaces, the classic entry point for XML external-entity flows.
- `race-conditions`: nuclei run over an operator-authored race-gate
  template (upstream mechanism: `race: true` gate attribute with
  `race_count` simultaneous requests), plus a controlled-concurrency
  load pair with ab against a single-use endpoint. The template with the
  gate stays operator-owned; the catalog references no target request.
- `prototype-pollution`: hidden-parameter mining and historical
  URL/parameter harvesting to build the sink-candidate list.
- `idor`: hidden-parameter discovery plus alternate-identifier path-slot
  enumeration; the role-pair response comparison runs at operator level
  with scrubbed authentication states.
- `request-smuggling`: desync scanner baseline and its stop-at-first-
  finding variant, for evidence-first operator review.
- `cache-poisoning`: response-header baseline, then the same request
  with one benign marker header, to compare cache-key behaviour and
  cache-storage echo. Marker choice is operator-owned.
- `webdav-traversal`: WebDAV method testing, NSE surface scan, and
  interactive client baseline.
- `graphql`: security-audit checklist run (iterates common GraphQL paths
  when none is given) and engine fingerprinting.
- `dns-rebinding-ssrf`: resolution-path tracing and a server-side fetch
  surface probe; rebinding DNS infrastructure, when needed, is lab-gated
  and never part of catalog rows.

## Tooling notes

`smuggler`, `graphw00f` and `GraphQL-Cop` are git/checkout tools, not
Kali packages; rows use the invocation each tool's own repository
documents (`python3 smuggler.py`, `python3 main.py`, `python3
graphql-cop.py`). All other tools (nuclei, phpggc, davtest, cadaver,
nmap, ab, arjun, ffuf, gobuster, waybackurls, dig, curl) are standard
Kali inventory or universally present.

## Sources consulted (re-authored; nothing verbatim)

Flags and semantics re-verified against upstream usage documentation
while authoring this wave (KA-048, October 2026): projectdiscovery nuclei
docs (race-condition gate templates, `-t`/`-u` flags), defparam/smuggler
README (`-u`, `-x`), dolevf/graphw00f README (`-f`, `-d`, `-t`, `-l`),
dolevf/GraphQL-Cop README (`-t`, common-path iteration), plus the Kali
pages for phpggc, davtest, cadaver, nmap NSE `http-webdav-scan`, ab,
arjun, ffuf and gobuster. No external text is quoted.

## Integration handoff (KA-INT-3)

1. Merge the python block above into `WEB_VULN_CLASSES` **additively** —
   the ten existing rows stay byte-identical (the test file guards this
   in both states).
2. Flip `MODULE_INT3_LANDED = True` in `tests/test_web_vuln_extended.py`
   — a one-line edit that switches the state pins to the landed catalog:
   module set == existing ∪ proposed (20 classes), new rows byte-equal
   to this block, and `web_vuln_commands` serving all ten new classes.
3. Update `BASELINE_SUITE_TOTAL` in `tests/test_ka_conventions.py` to the
   suite total after landing (this wave's pins move the collect-only
   count).
4. `tests/test_kali_web_pentest.py` keeps passing unmodified: its
   vuln-class checks are subset-based and the report/outline ops are
   untouched.