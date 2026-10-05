"""KA-056 tests - credential vaulting: emit-side commands carry ONLY
placeholder refs and never values, resolve-side values come strictly
from the caller-specified env-file path, the redact/scrub path proves
emitted and returned dict surfaces never embed resolved values,
missing/unreadable/malformed/unsatisfied env-file states yield
deterministic error dicts (never exceptions at the seam), and the
source-scan pin (no chassis import, no wall clock, no exec-style or
network facilities, exactly one file-read seam). No network; synthetic
values only - never real secret material."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.credvault import (
    ERROR_KIND,
    REASON_MALFORMED,
    REASON_NOT_FOUND,
    REASON_UNREADABLE,
    REASON_UNSATISFIED,
    REDACTED,
    EnvFile,
    EnvFileError,
    VaultPlan,
    build_command,
    build_plan,
    cred_ref,
    parse_env_file,
    plan_audit,
    read_env_file,
    redact,
    resolve,
)

APP_PW = "APP_PW"
BACKUP_PW = "BACKUP_PW"
STAGING_PW = "STAGING_PW"

APP_VALUE = "v4ault-alpha-s3cret"
BACKUP_VALUE = "v4ult-beta-s3cr3t"
STAGING_VALUE = "v4ult-gamma-s3cr3t"
NEEDLES = (APP_VALUE, BACKUP_VALUE, STAGING_VALUE)


ENV_PAIR_LINES = [
    "# synthetic vault - test fixture data only",
    APP_PW + "=" + APP_VALUE,
    BACKUP_PW + "=" + BACKUP_VALUE,
    STAGING_PW + "=" + STAGING_VALUE,
]


def _json_default(obj):
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    raise TypeError("unexpected in needle scan: " + repr(obj))


def _needles_absent(payload: object) -> None:
    dumped = json.dumps(payload, default=_json_default)
    for needle in NEEDLES:
        assert needle not in dumped, needle


def test_cred_ref_builds_and_validates_names():
    assert cred_ref("TOKEN_A") == "@cred:TOKEN_A@"
    assert cred_ref("TOKEN_A") == "@cred:TOKEN_A@"  # deterministic
    assert cred_ref("app.token") == "@cred:app.token@"
    assert cred_ref("app-token") == "@cred:app-token@"
    assert cred_ref("A1") == "@cred:A1@"


@pytest.mark.parametrize(
    "name", ["", "a b", "a=b", "a#b", "a:b", "a,b", "a\nb", "a\n", None, 42]
)
def test_cred_ref_rejects_hostile_names(name):
    with pytest.raises(ValueError):
        cred_ref(name)


def test_build_command_emits_refs_only_never_values(tmp_path):
    # needles exist on disk in a synthetic env file, yet the emit path
    # (which never reads any file) still produces refs-only output
    env = tmp_path / "creds.env"
    env.write_text("\n".join(ENV_PAIR_LINES) + "\n", encoding="utf-8")
    plan = build_command(
        ["vaultctl", "login", "--password", APP_PW, "--user", "svc-ops",
         "--extra", BACKUP_PW, "--password", APP_PW],
        [APP_PW, BACKUP_PW, STAGING_PW],
    )
    assert plan.command == (
        "vaultctl login --password @cred:APP_PW@ --user svc-ops "
        "--extra @cred:BACKUP_PW@ --password @cred:APP_PW@"
    )
    # manifest: first appearance, deduplicated, declared-unused omitted
    assert plan.required == (APP_PW, BACKUP_PW)
    assert isinstance(plan, VaultPlan)
    _needles_absent(plan.command)
    emit_view = plan_audit(plan)
    assert emit_view == {
        "command": plan.command,
        "required": [APP_PW, BACKUP_PW],
    }
    _needles_absent(emit_view)


def test_build_command_ignores_partial_and_undeclared():
    plan = build_command(["APP_PW_suffix", APP_PW], [APP_PW])
    assert plan.command == "APP_PW_suffix @cred:APP_PW@"
    assert plan.required == (APP_PW,)
    plan = build_command(["vaultctl", "login", "--pw", APP_PW], [])
    assert plan.command == "vaultctl login --pw APP_PW"  # undeclared = untouched
    assert plan.required == ()


def test_build_command_rejects_bad_declared_names_and_nonstr(tmp_path):
    for bad in ["", "bad name", "a=b"]:
        with pytest.raises(ValueError):
            build_command(["x"], [bad])
    with pytest.raises(TypeError):
        build_command([b"not-a-str", APP_PW], [APP_PW])


def test_build_plan_extracts_manifest_with_dedup():
    command = "auth --k @cred:APP_PW@ --k2 @cred:BACKUP_PW@ --k3 @cred:APP_PW@"
    plan = build_plan(command)
    assert isinstance(plan, VaultPlan)
    assert plan.command == command  # passthrough, unmodified
    assert plan.required == (APP_PW, BACKUP_PW)  # first appearance, deduped


def test_build_plan_accepts_ref_free_command():
    plan = build_plan("vaultctl login --host host")
    assert plan.command == "vaultctl login --host host"
    assert plan.required == ()


@pytest.mark.parametrize(
    "command", [
        "echo @cred:",
        "echo @cred:@",
        "echo @cred:bad name@",
        "echo @cred:a=b@",
    ]
)
def test_build_plan_rejects_malformed_refs(command):
    with pytest.raises(ValueError):
        build_plan(command)


@pytest.mark.parametrize("command", [123, None, b"cmd"])
def test_build_plan_rejects_non_string(command):
    with pytest.raises(TypeError):
        build_plan(command)


def test_resolve_reads_values_from_caller_specified_path(tmp_path):
    # pin 2: the values depend ONLY on the path the caller passes
    env_a = tmp_path / "alpha.env"
    env_b = tmp_path / "beta.env"
    env_a.write_text(
        APP_PW + "=" + APP_VALUE + "\n" + BACKUP_PW + "=" + BACKUP_VALUE,
        encoding="utf-8",
    )
    env_b.write_text(
        APP_PW + "=pb-alpha-only\n" + BACKUP_PW + "=pb-beta-only",
        encoding="utf-8",
    )
    plan = build_plan("auth @cred:APP_PW@ @cred:BACKUP_PW@")
    got_a = resolve(plan, env_a)
    got_b = resolve(plan, env_b)
    assert got_a["ok"] is True
    assert got_b["ok"] is True
    assert got_a["env"] == {APP_PW: APP_VALUE, BACKUP_PW: BACKUP_VALUE}
    assert got_b["env"] == {APP_PW: "pb-alpha-only", BACKUP_PW: "pb-beta-only"}
    assert got_a["audit"]["env_path"] == str(env_a)
    assert got_b["audit"]["env_path"] == str(env_b)


def test_resolve_success_shape_exact(tmp_path):
    env = tmp_path / "creds.env"
    env.write_text(
        APP_PW + "=" + APP_VALUE + "\n" + BACKUP_PW + "=" + BACKUP_VALUE,
        encoding="utf-8",
    )
    plan = build_plan("auth @cred:APP_PW@ @cred:BACKUP_PW@")
    result = resolve(plan, env)
    assert sorted(result.keys()) == ["audit", "env", "ok"]
    assert result["ok"] is True
    assert result["env"] == {APP_PW: APP_VALUE, BACKUP_PW: BACKUP_VALUE}
    assert result["audit"] == {
        "command": "auth @cred:APP_PW@ @cred:BACKUP_PW@",
        "required": [APP_PW, BACKUP_PW],
        "resolved_count": 2,
        "env_path": str(env),
    }


def test_resolve_delivers_only_required_refs(tmp_path):
    env = tmp_path / "creds.env"
    env.write_text("\n".join(ENV_PAIR_LINES) + "\n", encoding="utf-8")
    plan = build_plan("auth @cred:APP_PW@ @cred:BACKUP_PW@")
    result = resolve(plan, env)
    assert result["env"] == {APP_PW: APP_VALUE, BACKUP_PW: BACKUP_VALUE}
    assert list(result["env"].keys()) == [APP_PW, BACKUP_PW]
    _needles_absent(result["audit"])  # audit projection stays values-free


def test_resolve_command_stays_ref_form(tmp_path):
    env = tmp_path / "creds.env"
    env.write_text(APP_PW + "=" + APP_VALUE, encoding="utf-8")
    plan = build_plan("auth @cred:APP_PW@")
    result = resolve(plan, env)
    assert result["ok"] is True
    # never materialized: the command keeps its reference form
    assert result["audit"]["command"] == plan.command
    assert "@cred:APP_PW@" in result["audit"]["command"]


def test_resolve_missing_file_is_deterministic_error_dict(tmp_path):
    missing = tmp_path / "absent.env"
    plan = build_plan("auth @cred:APP_PW@ @cred:BACKUP_PW@")
    result = resolve(plan, missing)
    assert result == {
        "ok": False,
        "error": ERROR_KIND,
        "reason": REASON_NOT_FOUND,
        "detail": "env file not found",
        "env_path": str(missing),
        "required": [APP_PW, BACKUP_PW],
    }
    assert result == resolve(plan, missing)  # deterministic across calls
    _needles_absent(result)
    direct = read_env_file(missing)
    assert isinstance(direct, EnvFile)
    assert direct.entries is None
    assert direct.error == {
        "ok": False,
        "error": ERROR_KIND,
        "reason": REASON_NOT_FOUND,
        "detail": "env file not found",
        "env_path": str(missing),
    }


@pytest.mark.parametrize(
    "content,expected_detail", [
        (APP_PW + "=" + APP_VALUE + "\n=oops\n",
         "malformed env file: empty key at line 2"),
        (APP_PW + "=v4ault-dup-one\nAPP_PW=v4ault-dup-two\n",
         "malformed env file: conflicting duplicate entry for key 'APP_PW' at line 2"),
    ]
)
def test_resolve_malformed_env_is_deterministic_error_dict(
    tmp_path, content, expected_detail
):
    env = tmp_path / "malformed.env"
    env.write_text(content, encoding="utf-8")
    plan = build_plan("auth @cred:APP_PW@ @cred:BACKUP_PW@")
    result = resolve(plan, env)
    assert result == {
        "ok": False,
        "error": ERROR_KIND,
        "reason": REASON_MALFORMED,
        "detail": expected_detail,
        "env_path": str(env),
        "required": [APP_PW, BACKUP_PW],
    }
    assert result == resolve(plan, env)  # deterministic across calls
    # a malformed (or duplicated) value never leaks through the error path
    for needle in (APP_VALUE, "v4ault-dup-one", "v4ault-dup-two", "oops"):
        assert needle not in json.dumps(result)


def test_resolve_unsatisfied_missing_and_empty_refs(tmp_path):
    plan = build_plan(
        "auth @cred:APP_PW@ @cred:BACKUP_PW@ @cred:TOKEN_C@"
    )
    env_missing = tmp_path / "missing-ref.env"
    env_missing.write_text(
        APP_PW + "=" + APP_VALUE + "\n" + BACKUP_PW + "=" + BACKUP_VALUE,
        encoding="utf-8",
    )
    result = resolve(plan, env_missing)
    assert result == {
        "ok": False,
        "error": ERROR_KIND,
        "reason": REASON_UNSATISFIED,
        "detail": "required references missing from env file: TOKEN_C",
        "env_path": str(env_missing),
        "required": [APP_PW, BACKUP_PW, "TOKEN_C"],
    }
    env_empty = tmp_path / "empty-ref.env"
    env_empty.write_text(
        APP_PW + "=" + APP_VALUE + "\n" + BACKUP_PW + "=\n"
        + "TOKEN_C=not-empty\n",
        encoding="utf-8",
    )
    result = resolve(plan, env_empty)
    assert result["ok"] is False
    assert result["reason"] == REASON_UNSATISFIED
    assert result["detail"] == "empty value for required references: BACKUP_PW"
    _needles_absent(result)


def test_read_env_file_never_raises_on_unreadable(tmp_path):
    plan = build_plan("auth @cred:APP_PW@")
    directory = tmp_path / "not-a-file"
    directory.mkdir()
    result = resolve(plan, directory)
    assert result["ok"] is False
    assert result["reason"] == REASON_UNREADABLE
    assert result["detail"] == "env file unreadable: IsADirectoryError"
    binary = tmp_path / "binary.env"
    binary.write_bytes(b"\xff\xfe\x01")
    result = resolve(plan, binary)
    assert result["ok"] is False
    assert result["reason"] == REASON_UNREADABLE
    assert result["detail"] == "env file unreadable: UnicodeDecodeError"


def test_parse_env_file_house_convention():
    content = (
        "# comment line\n"
        + "\n"
        + APP_PW + " = " + APP_VALUE + "  \n"
        + BACKUP_PW + "=" + BACKUP_VALUE + "\n"
        + "not-an-entry\n"
        + "EQTEST=v-w=x"
    )
    assert parse_env_file(content) == {
        APP_PW: APP_VALUE,
        BACKUP_PW: BACKUP_VALUE,
        "EQTEST": "v-w=x",  # first = splits
    }


def test_parse_env_file_rejects_and_accepts_duplicates():
    assert parse_env_file("K=v\nK=v") == {"K": "v"}  # identical dup accepted
    with pytest.raises(EnvFileError, match="conflicting duplicate entry for key 'K' at line 2"):
        parse_env_file("K=v4ault-dup-one\nK=v4ault-dup-two\n")
    with pytest.raises(EnvFileError, match="empty key at line 1"):
        parse_env_file("=oops\n")
    with pytest.raises(TypeError):
        parse_env_file(b"APP_PW=x")


def test_redact_scrubs_resolved_result_end_to_end(tmp_path):
    env = tmp_path / "creds.env"
    env.write_text("\n".join(ENV_PAIR_LINES) + "\n", encoding="utf-8")
    plan = build_plan("auth @cred:APP_PW@ @cred:BACKUP_PW@")
    result = resolve(plan, env)
    assert result["ok"] is True
    safe = redact(result, result["env"])
    _needles_absent(safe)
    assert safe["env"] == {APP_PW: REDACTED, BACKUP_PW: REDACTED}
    assert safe["audit"] == result["audit"]
    # error dicts carry no values: redaction leaves them unchanged
    plan_full = build_plan("auth @cred:APP_PW@ @cred:BACKUP_PW@ @cred:TOKEN_C@")
    failure = resolve(plan_full, env)
    assert failure["ok"] is False
    assert redact(failure, result["env"]) == failure


def test_redact_deep_structures_and_repeats(tmp_path):
    values = {APP_PW: APP_VALUE, BACKUP_PW: BACKUP_VALUE}
    payload = {
        "s": "pre " + APP_VALUE + " post",
        "l": ["plain " + APP_VALUE, (BACKUP_VALUE, 1)],
        "d": {"x": BACKUP_VALUE + APP_VALUE},
        "st": {APP_VALUE, "clean"},
        "repeat": APP_VALUE + "-" + APP_VALUE,
        "n": None,
        "i": 7,
    }
    safe = redact(payload, values)
    assert safe["s"] == "pre <redacted> post"
    assert safe["l"][0] == "plain <redacted>"
    assert safe["l"][1] == ("<redacted>", 1)
    assert isinstance(safe["l"][1], tuple)
    assert safe["d"] == {"x": "<redacted><redacted>"}
    assert safe["st"] == {REDACTED, "clean"}
    assert safe["repeat"] == "<redacted>-<redacted>"
    assert safe["n"] is None and safe["i"] == 7
    _needles_absent(safe)


def test_redact_order_and_passthrough_edges():
    values = {"big": "aab", "small": "aa"}
    # longest value replaced first: the contained "aa" cannot survive
    assert redact("aabaab", values) == "<redacted><redacted>"
    assert redact(7, values) == 7
    assert redact(None, values) is None
    assert redact(True, values) is True
    # empty and whitespace-only values cannot scrub payloads
    assert redact("abc", {"K": "", "K2": "  "}) == "abc"
    # mapping keys are scrubbed too
    assert redact({"x" + "aab" + "y": 1}, values) == {"x<redacted>y": 1}


def test_redact_guards_poisoned_plan_literals(tmp_path):
    # build_plan cannot detect caller-supplied literals; redact is the
    # guaranteed scrub for any derived dict
    poisoned = "curl -u admin:" + APP_VALUE + " @cred:APP_PW@"
    plan = build_plan(poisoned)
    assert plan.required == (APP_PW,)
    assert APP_VALUE in plan_audit(plan)["command"]  # accepted as-is
    safe = redact(plan_audit(plan), {APP_PW: APP_VALUE})
    assert safe["command"] == "curl -u admin:<redacted> @cred:APP_PW@"
    _needles_absent(safe)


@pytest.mark.parametrize("plan", ["not-a-plan", None, {"command": "x", "required": []}])
def test_resolve_raises_typeerror_for_non_plan(tmp_path, plan):
    with pytest.raises(TypeError):
        resolve(plan, tmp_path / "creds.env")


def test_module_purity_source_scan():
    module = importlib.import_module("agentic_ai.agents.cyber.credvault")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for token in [
        "subprocess",
        "eval(",
        "exec(",
        "socket",
        "urllib",
        "os.environ",
        "getenv",
        "utcnow",
        "time.time",
        "datetime",
        "from agentic_ai",
        "import agentic_ai",
        "import os",
    ]:
        assert token not in source, token
    # exactly ONE file-read seam: the caller-provided env-file path
    assert source.count("open(") == 1


def test_end_to_end_vault_roundtrip(tmp_path):
    env_path = tmp_path / "creds.env"
    env_path.write_text("\n".join(ENV_PAIR_LINES) + "\n", encoding="utf-8")
    plan = build_command(
        ["vaultctl", "login", "--password", APP_PW, "--fallback", BACKUP_PW],
        [APP_PW, BACKUP_PW],
    )
    # emit side: refs only, values never present
    emit_view = plan_audit(plan)
    assert emit_view == {
        "command": "vaultctl login --password @cred:APP_PW@ "
                   "--fallback @cred:BACKUP_PW@",
        "required": [APP_PW, BACKUP_PW],
    }
    _needles_absent(emit_view)
    # resolve side: the caller-specified path supplies the values
    result = resolve(plan, env_path)
    assert result["ok"] is True
    assert result["env"] == {APP_PW: APP_VALUE, BACKUP_PW: BACKUP_VALUE}
    # reporting side: the redaction path scrubs every resolved value
    safe = redact(result, result["env"])
    _needles_absent(safe)
    assert safe["env"] == {APP_PW: REDACTED, BACKUP_PW: REDACTED}