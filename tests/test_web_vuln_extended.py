"""KA-048 (WEB_VULN_CLASSES +10) — pre-integration acceptance pins.

WHAT IS PINNED NOW (green before any module edit):
- PROPOSED catalog: the fenced python block WEB_VULN_ADDITIONS in
  docs/web_vuln_additions.md must define exactly the ten option-[48]
  classes, with field parity to the existing WEB_VULN_CLASSES rows
  (same keys/shapes: ('<step>', ('<command>', ...))), at least one
  {target}-slotted command per class, and kebab-style key/step labels.
- SCRUB tested with the module's REAL scrubber:
  web_pentest.wp_scrub_target is applied to EVERY proposed sample
  command and to its rendered form. Command templates legitimately
  contain word-separator spaces (the scrubber's home ground is targets,
  not trusted in-house command templates), so the check maps separator
  spaces to a stand-in character and then requires the scrubber to
  return the template unchanged — every other scrub rule (control
  characters, shell metacharacters, traversal dots) must pass with zero
  deviations. The {target} slot renders only a scrubbed target: every
  occurrence replaced, no shell tricks added.
- CATALOG policy (methodology only): no proposed row contains
  payload/exploit strings; tool invocations, wordlist references and
  benign marker strings only. The proposed dict is parsed with
  ast.literal_eval, never eval/import — no execution here.
- ADDITIVE state pin: web_pentest.WEB_VULN_CLASSES still holds exactly
  the pre-existing ten classes with byte-identical rows, the op class
  list is exactly those ten (sorted), and a new class name is still
  unknown to the op.

INT-3 WIRING THESE ASSERTIONS AWAIT (KA-INT-3, WEB_VULN_CLASSES +10):
1. KA-INT-3 merges WEB_VULN_ADDITIONS verbatim into
   agentic_ai/agents/cyber/web_pentest.py::WEB_VULN_CLASSES, additive
   only — existing rows must stay byte-identical (guarded in both
   states below).
2. KA-INT-3 then flips the module constant MODULE_INT3_LANDED below to
   True — a single-line edit — which switches the state pins to the
   landed catalog: module dict == existing ∪ proposed (20 classes,
   byte-equal to the doc block) and WebPentestMixin.web_vuln_commands
   serving every new class with the doc shapes while still rejecting
   unknown class names.
3. Every other assertion here is written to hold in BOTH states without
   edits (doc parse, key set, parity, scrub survival, payload scan,
   execution-free source scan).

House style: no subprocess/os.system/eval in this file, no network, no
skips (the state flip is an if on a module constant, so collection
totals are identical before and after integration).
"""

import ast
import inspect
import pathlib
import re

import pytest

from agentic_ai.agents.cyber import web_pentest

REPO = pathlib.Path(__file__).resolve().parents[1]
DOC_PATH = REPO / "docs" / "web_vuln_additions.md"

# The ten proposed classes, from option [48]: deserialization, XXE, race
# conditions, prototype pollution, IDOR, request smuggling, cache
# poisoning, WebDAV traversal, GraphQL, DNS-rebinding SSRF.
NEW_CLASS_KEYS = (
    "cache-poisoning",
    "dns-rebinding-ssrf",
    "graphql",
    "idor",
    "insecure-deserialization",
    "prototype-pollution",
    "race-conditions",
    "request-smuggling",
    "webdav-traversal",
    "xxe",
)

# Drift alarm for the pre-existing catalog: byte-exact snapshots of the
# module rows as verified at KA-048 authoring time (2026-10-05). KA-INT-3's
# edit must leave every one of these untouched.
EXPECTED_EXISTING_ROWS = {
    'auth': ('auth-tests', (
        "hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect' -t 8",
        'hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt --show',
    )),
    'automated': ('scanner-pass', (
        'nikto -h http://{target} -C all',
    )),
    'cmd-injection': ('cmdi-probes', (
        "commix -u 'http://{target}/?ip=127.0.0.1' --batch",
    )),
    'cms': ('cms-tests', (
        'wpscan --url http://{target} --enumerate u,vp,vt --random-user-agent',
    )),
    'file-inclusion': ('lfi-probes', (
        "curl -sS 'http://{target}/?page=../../../../etc/passwd'",
        "curl -sS 'http://{target}/?file=php://filter/resource=/etc/passwd'",
    )),
    'sqli': ('sqlmap-baseline', (
        "sqlmap -u 'http://{target}/?id=1' -p id --batch --level=1 --risk=1",
        "sqlmap -u 'http://{target}/?id=1' --forms --batch --crawl=1",
    )),
    'ssl-tls': ('tls-tests', (
        'testssl.sh --quiet http://{target}',
        'sslscan http://{target}:443',
    )),
    'ssrf': ('ssrf-probes', (
        "curl -sS 'http://{target}/fetch?url=http://127.0.0.1:80/'",
    )),
    'waf-evasion': ('waf-baseline', (
        'wafw00f -a http://{target}',
    )),
    'xss': ('xss-probes', (
        "dalfox url 'http://{target}/?q=1'",
        "curl -sS 'http://{target}/?q=<svg/onload=alert(1)>'",
    )),
}
EXPECTED_EXISTING_KEYS = frozenset(EXPECTED_EXISTING_ROWS)

# Target the rendered {target} slots use in tests; picked to pass the
# real scrubber itself (the op renders only scrub-approved targets).
SAFE_TARGET = "lab-target.local"

# INT3-WIRING: flip to True in the SAME integration task that merges the
# doc block into web_pentest.WEB_VULN_CLASSES (see module docstring).
MODULE_INT3_LANDED = False

# Scan mirrors for the scrubber's explicit rejection classes, kept local
# for readable failures; the scrubber itself is still run on every row.
META_CHARS = re.compile(r"[;|&`$()<>'\"]")

# Payload/exploit policy for proposed rows: methodology-only catalog, so
# concrete exploit payloads, hostile command fragments and payload
# encodings must never appear. Substring scan is case-insensitive; the
# scrubber rules still own the char-class problem.
FORBIDDEN_ROW_SNIPPETS = (
    "alert(", "<script", "onerror", "onload", "passwd", "/etc/",
    "php://", "gopher", "file://", "dict:", "127.0.", "localhost",
    "192.168.", "172.16.", "10.0.", "${", "%00", "sleep", "cat /",
    "rm -rf", "whoami", "bash", "sh -c", "nc ",
)


def _doc_python_blocks(text):
    """Extract (list of (fence-info, body) blocks, was_a_fence_left_open)."""
    blocks, opened, info = [], None, ""
    for line in text.splitlines():
        stripped = line.strip()
        if opened is None:
            if stripped.startswith("```"):
                opened, info = [], stripped[3:].strip()
        elif stripped == "```":
            blocks.append((info, "\n".join(opened)))
            opened = None
        else:
            opened.append(line)
    return blocks, opened is not None


def _load_doc():
    """Parse the doc's single python fence; literal_eval only, no eval."""
    text = DOC_PATH.read_text(encoding="utf-8")
    blocks, unclosed = _doc_python_blocks(text)
    assert not unclosed, "docs/web_vuln_additions.md has an unbalanced fence"
    python_blocks = [body for info, body in blocks if info == "python"]
    assert len(python_blocks) == 1, "doc must hold exactly one python fence"
    tree = ast.parse(python_blocks[0])
    assigns = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "WEB_VULN_ADDITIONS"
                for t in node.targets)
    ]
    assert len(assigns) == 1, "doc block must define WEB_VULN_ADDITIONS once"
    return text, ast.literal_eval(assigns[0].value)


DOC_TEXT, PROPOSED = _load_doc()

SHAPE_ROWS = sorted(PROPOSED)
ALL_CMDS = sorted(
    (cls, cmd)
    for cls, (_, cmds) in PROPOSED.items()
    for cmd in cmds
)
SLOTTED_CMDS = sorted(
    (cls, cmd) for cls, cmd in ALL_CMDS if "{target}" in cmd
)


def _assert_scrub_survives(text, where):
    """Real scrubber + explicit scans: no control chars, no shell tricks."""
    assert not any(ord(c) < 32 or ord(c) == 127 for c in text), (where, text)
    assert ".." not in text, (where, text)
    assert META_CHARS.search(text) is None, (where, text)
    stand_in = text.replace(" ", "_")
    assert web_pentest.wp_scrub_target(stand_in) == stand_in, (
        where, "scrub deviation beyond separator spaces", text)


def _check_row_shape(cls, row):
    """2-tuple of (kebab step str, non-empty str-tuple) like existing rows."""
    assert isinstance(row, tuple) and len(row) == 2, (cls, row)
    step, cmds = row
    assert isinstance(step, str) and step and step == step.strip(), (cls, step)
    assert step == step.lower() and all(p.isalnum() for p in step.split("-")), (
        cls, step)
    assert isinstance(cmds, tuple) and len(cmds) >= 1, (cls, cmds)
    assert all(isinstance(c, str) and c and c == c.strip() for c in cmds), (
        cls, cmds)
    assert cls == cls.lower() and all(p.isalnum() for p in cls.split("-")), cls
    return step, cmds


def _render_slotted(cls, cmd):
    """Render {target} exactly like the op would: scrubber-first."""
    scrubbed = web_pentest.wp_scrub_target(SAFE_TARGET)
    assert scrubbed == SAFE_TARGET, SAFE_TARGET
    assert "{target}" in cmd, (cls, cmd)
    rendered = cmd.replace("{target}", scrubbed)
    assert "{target}" not in rendered, (cls, rendered)
    assert rendered.count(scrubbed) == cmd.count("{target}"), (cls, rendered)
    _assert_scrub_survives(rendered, (cls, rendered))
    return rendered


def test_doc_holds_exactly_one_python_catalog_block():
    blocks, unclosed = _doc_python_blocks(DOC_TEXT)
    assert not unclosed
    python_blocks = [body for info, body in blocks if info == "python"]
    assert len(python_blocks) == 1
    assert isinstance(PROPOSED, dict)


def test_doc_documents_the_integration_contract():
    for phrase in ("KA-INT-3", "field parity", "MODULE_INT3_LANDED",
                   "WEB_VULN_CLASSES"):
        assert phrase in DOC_TEXT, phrase


def test_proposed_keys_exactly_match_option_48():
    assert set(PROPOSED) == set(NEW_CLASS_KEYS)
    assert len(PROPOSED) == 10
    assert set(PROPOSED).isdisjoint(EXPECTED_EXISTING_KEYS)


@pytest.mark.parametrize("cls", SHAPE_ROWS)
def test_proposed_row_shape_and_slot(cls):
    step, cmds = _check_row_shape(cls, PROPOSED[cls])
    # field parity: the same field contract as the existing rows
    assert isinstance(step, str)
    assert isinstance(cmds, tuple) and all(isinstance(c, str) for c in cmds)
    assert any("{target}" in c for c in cmds), cls


@pytest.mark.parametrize("cls", SHAPE_ROWS)
def test_proposed_row_is_methodology_only(cls):
    step, cmds = PROPOSED[cls]
    for field in (step, *cmds):
        for bad in FORBIDDEN_ROW_SNIPPETS:
            assert bad not in field.lower(), (cls, bad, field)


@pytest.mark.parametrize(["cls", "cmd"], ALL_CMDS)
def test_proposed_commands_survive_the_real_scrubber(cls, cmd):
    _assert_scrub_survives(cmd, (cls, cmd))


@pytest.mark.parametrize(["cls", "cmd"], SLOTTED_CMDS)
def test_rendered_commands_inject_only_a_scrubbed_target(cls, cmd):
    _render_slotted(cls, cmd)


def test_module_web_vuln_classes_additive_state_pin():
    module = web_pentest.WEB_VULN_CLASSES
    for cls, row in EXPECTED_EXISTING_ROWS.items():
        assert module.get(cls) == row, ("existing row drifted", cls)
    if not MODULE_INT3_LANDED:
        # INT3-WIRING pre-state: module holds exactly the existing ten
        assert dict(module) == EXPECTED_EXISTING_ROWS
    else:
        # INT3-WIRING landed state: doc rows merged verbatim, additively
        assert dict(module) == {**EXPECTED_EXISTING_ROWS, **PROPOSED}
        for cls in NEW_CLASS_KEYS:
            _check_row_shape(cls, module[cls])


def test_web_vuln_commands_op_state_pin():
    mixin = web_pentest.WebPentestMixin()
    first_new = sorted(NEW_CLASS_KEYS)[0]
    if not MODULE_INT3_LANDED:
        # INT3-WIRING pre-state: new classes still unknown to the op
        catalog = mixin.web_vuln_commands(SAFE_TARGET)
        assert catalog["classes"] == sorted(EXPECTED_EXISTING_KEYS)
        assert catalog["classes"] == sorted(catalog["classes"])
        assert catalog["target"] == SAFE_TARGET
        with pytest.raises(ValueError) as exc:
            mixin.web_vuln_commands(SAFE_TARGET, vuln_class=first_new)
        assert first_new in str(exc.value)
    else:
        # INT3-WIRING landed state: every new class served in doc shapes
        for cls in sorted(NEW_CLASS_KEYS):
            out = mixin.web_vuln_commands(SAFE_TARGET, vuln_class=cls)
            step, cmds = PROPOSED[cls]
            assert out == {"target": SAFE_TARGET, "vuln_class": cls,
                           "step": step,
                           "commands": [c.replace("{target}", SAFE_TARGET)
                                        for c in cmds]}
        with pytest.raises(ValueError) as exc:
            mixin.web_vuln_commands(SAFE_TARGET, vuln_class="not-a-class")
        assert "known:" in str(exc.value)


def test_web_pentest_source_stays_execution_free():
    src = pathlib.Path(inspect.getsourcefile(web_pentest)).read_text(
        encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(", "exec(", "Popen",
                   "__import__"):
        assert banned not in src, banned