"""KA-074 / Healthcheck row (OPT-74): pin the builder spec doc's contract.

docs/ka_healthcheck_row.md is the builder output the [INTEGRATION] task
applies verbatim to the shared SOC healthcheck script
(/opt/soc-openclaw/deploy/healthcheck.sh on thing1 - integration-owned,
never edited by builders). These tests validate that contract offline:
the row block exists, parses as valid bash, calls the script's bare
ok()/bad() helpers, respects the script's section placement and SOC_* env
override style, and is planner-only (a read-only import+count probe). Two
live cross-checks stay owner-gated behind KA074_LIVE_SCRIPT=1; they verify
the doc's quoted helper reference against the real script on its host and
are allowed to skip everywhere else (opt-in precedent: lab batteries).

No network anywhere in this file.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_DOC = REPO_ROOT / "docs" / "ka_healthcheck_row.md"
LIVE_SCRIPT = Path(
    os.environ.get("KA074_LIVE_SCRIPT_PATH",
                   "/opt/soc-openclaw/deploy/healthcheck.sh")
)

SECTION_HEADER = 'echo "--- kali-agent op-presence ---"'
INSERT_ANCHOR = 'echo "--- secrets perms (assert, never rewrite) ---"'
OK_CALL = 'ok "kali-agent ops: $KALI_N"'
BAD_CALL = ('bad "kali-agent ops: $KALI_N (want >0) — '
            'kali import or composition failed; repo at $KALI_REPO"')
ENV_OVERRIDE = 'KALI_REPO="${SOC_KALI_REPO:-$HOME/agentic-ai}"'
EMPTY_GUARD = "KALI_N=${KALI_N:-0}"
THRESHOLD = '[ "$KALI_N" -gt 0 ] 2>/dev/null'
HELPER_OK = 'ok()  { echo "  ok   $1"; PASS=$((PASS+1)); }'
HELPER_BAD = 'bad() { echo "  FAIL $1"; FAIL=$((FAIL+1)); }'

AGENT_TARGETS = (
    ("kali", "importlib.import_module('agentic_ai.agents.cyber.kali').KaliAgent"),
    ("kali_v2", "importlib.import_module('agentic_ai.agents.cyber.kali_v2').KaliAgentV2"),
)

READ_ONLY_BANNED = (
    "curl ", "wget ", " nc ", "docker ", "systemctl ", "eval ",
    " rm ", " mv ", " chmod ", " chown ", "sudo ",
)

requires_live_script = pytest.mark.skipif(
    os.environ.get("KA074_LIVE_SCRIPT") != "1",
    reason="owner-gated live cross-check: set KA074_LIVE_SCRIPT=1 "
           "(opt-in precedent, KA-BUILDING-CONVENTIONS section 5)",
)

BASH_FENCE_RE = re.compile(r"```bash\n(.*?)\n```", re.S)


def _spec_text() -> str:
    try:
        text = SPEC_DOC.read_text(encoding="utf-8")
    except FileNotFoundError:  # pragma: no cover - builder omission
        pytest.fail(f"spec doc missing: {SPEC_DOC}")
    assert text.strip(), "spec doc is empty"
    return text


def _row_block() -> str:
    """The doc's single fenced bash block = the row the integrator inserts."""
    fences = BASH_FENCE_RE.findall(_spec_text())
    assert len(fences) == 1, (
        f"expected exactly one fenced bash block in {SPEC_DOC.name}, "
        f"found {len(fences)}"
    )
    return fences[0]


def _live_script_text() -> str:
    if not LIVE_SCRIPT.exists():
        pytest.skip(f"no deployed healthcheck script at {LIVE_SCRIPT}")
    return LIVE_SCRIPT.read_text(encoding="utf-8")


def test_spec_doc_exists_and_nonempty():
    assert len(_spec_text()) > 0


def test_spec_doc_cites_task_and_option():
    text = _spec_text()
    for needle in ("KA-074", "OPT-74", "[INTEGRATION]"):
        assert needle in text, needle


def test_spec_has_exactly_one_bash_fence_the_row():
    block = _row_block()
    assert block.strip() != ""
    assert block.lstrip().startswith('echo "---')


def test_row_block_is_valid_bash():
    block = _row_block()
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash not available on PATH")
    fh = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False,
                                     encoding="utf-8")
    try:
        fh.write(block)
        fh.close()
        proc = subprocess.run([bash, "-n", fh.name], capture_output=True,
                              text=True, timeout=30)
        assert proc.returncode == 0, f"bash -n rejected the row:\n{proc.stderr}"
    finally:
        Path(fh.name).unlink(missing_ok=True)


def test_row_declares_its_section_header():
    block = _row_block()
    assert SECTION_HEADER in block


@pytest.mark.parametrize(("name", "probe_line"), AGENT_TARGETS, ids=("kali", "kali_v2"))
def test_row_probe_imports_and_counts_each_kali_class(name, probe_line):
    assert probe_line in _row_block()


def test_row_calls_bare_ok_and_bad_not_parenthesized():
    block = _row_block()
    assert OK_CALL in block
    assert BAD_CALL in block
    assert "ok(" not in block, "ok/bad are called bare, never ok(...)"
    assert "bad(" not in block


def test_quoted_helper_reference_matches_script_helpers():
    text = _spec_text()
    assert HELPER_OK in text
    assert HELPER_BAD in text


def test_spec_pins_the_insertion_anchor():
    text = _spec_text()
    assert INSERT_ANCHOR in text
    assert re.search(r"immediately BEFORE the line", text)


def test_row_env_override_uses_soc_pattern():
    assert ENV_OVERRIDE in _row_block()


def test_row_guards_against_empty_count():
    assert EMPTY_GUARD in _row_block()


def test_row_threshold_compare_suppresses_odd_value():
    assert THRESHOLD in _row_block()


def test_row_failure_message_carries_cause_hint():
    block = _row_block()
    assert "repo at $KALI_REPO" in block
    assert "—" in block


def test_row_probe_is_read_only_and_planner_only():
    block = _row_block()
    for banned in READ_ONLY_BANNED:
        assert banned not in block, banned
    assert "python3 -c" in block
    assert "import_module" in block


def test_row_pins_op_floors_and_dir_count():
    block = _row_block()
    assert block.count(">= 100") == 2
    assert "startswith('_')" in block
    assert "dir(ka)" in block
    assert "dir(kv)" in block


@requires_live_script
def test_live_script_helpers_match_doc_reference():
    live = _live_script_text()
    assert HELPER_OK in live
    assert HELPER_BAD in live


@requires_live_script
def test_live_script_insert_anchor_is_unique():
    live = _live_script_text()
    assert live.count(INSERT_ANCHOR) == 1
