"""KA-097 builder tests - the CI-matrix proposal doc pins.

docs/KA-CI-MATRIX-PROPOSAL.md carries the EXACT yaml block the
[INTEGRATION] task appends to .gitlab-ci.yml (the shared CI file is
integration-owned; builders never touch it). Pinned here, offline and
local-file-only: the doc's single ```yaml fence parses; stages are
declared (test, lab); the suite job (`pytest-suite`) exists with MR + main
rules, the verdict-grep script, and always()-artifacts; the lab job
(`lab-battery`) is manual-only with allow_failure: false and the compose
up -> consent-gated pytest -> down -v battery sequence; the consent gate is
referenced BY NAME only (protected CI/CD variable - never inline values)
and no secret-VALUE markers or secret-valued keys appear in the yaml.
Without pyyaml the file still pins the shape offline: the parse-dependent
tests guard with pytest.importorskip("yaml") and the text-level tests
(including the regex fallback) always run.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DOC = REPO_ROOT / "docs" / "KA-CI-MATRIX-PROPOSAL.md"

FENCE_RE = re.compile(r"^```yaml\n(.*?)\n```$", re.DOTALL | re.MULTILINE)
ENV_REF_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
FORBIDDEN_VALUE_MARKERS = (
    "ghp_", "gho_", "ghu_", "github_pat_", "sk-", "xox", "akia", "agpa",
    "begin rsa private key", "begin openssh private key",
    "begin ec private key", "password=", "passwd=", "token=", "secret=",
    "api_key=", "apikey=",
)
SECRET_VALUED_KEYS = {
    "token", "tokens", "secret", "password", "passwd", "api_key",
    "apikey", "private_key", "access_token", "bearer",
}
CONSENT_GATE = "KA_LAB_BATTERY"


def _doc_text() -> str:
    assert DOC.is_file(), f"missing {DOC}"
    return DOC.read_text(encoding="utf-8")


def _fence_text() -> str:
    fences = FENCE_RE.findall(_doc_text())
    assert len(fences) == 1, f"expected exactly one ```yaml fence, got {len(fences)}"
    return fences[0]


def _parsed() -> dict:
    # importorskip returns the module: a clean skip when pyyaml is absent,
    # a clean parse otherwise. No bare imports - collection must not die.
    yaml_mod = pytest.importorskip("yaml")
    data = yaml_mod.safe_load(_fence_text())
    assert isinstance(data, dict)
    return data


# --- the fence and its structure --------------------------------------------

def test_doc_has_single_yaml_fence():
    fences = FENCE_RE.findall(_doc_text())
    assert len(fences) == 1, f"expected exactly one ```yaml fence, got {len(fences)}"


def test_stages_declared():
    # parse-dependent: guards itself when pyyaml is absent
    assert _parsed()["stages"] == ["test", "lab"]


# --- the suite job ------------------------------------------------------------

def test_suite_job_exists_with_expected_shape():
    job = _parsed()["pytest-suite"]
    assert job["stage"] == "test"
    script = "\n".join(job["script"])
    # the suite runner, output teed to the verdict log
    assert "python3 -m pytest tests/ -q" in script
    assert "tee pytest-verdict.log" in script
    # verdicts come from the house grep filter, never tail
    assert 'grep -E "[0-9]+ (passed|failed|error)" pytest-verdict.log' in script
    # the purity scan slice, kept as its own artifact
    assert "tee purity-scan.log" in script
    # rules: MRs + the default branch only
    assert [rule["if"] for rule in job["rules"]] == [
        '$CI_PIPELINE_SOURCE == "merge_request_event"',
        '$CI_COMMIT_BRANCH == "main"',
    ]
    artifacts = job["artifacts"]
    assert artifacts["when"] == "always"
    assert artifacts["paths"] == ["pytest-verdict.log", "purity-scan.log"]
    assert str(artifacts["expire_in"]) == "1 day"
    assert str(job["timeout"]).endswith("m")
    assert job["retry"]["max"] >= 1


# --- the lab job --------------------------------------------------------------

def test_lab_job_manual_only():
    job = _parsed()["lab-battery"]
    assert job["stage"] == "lab"
    assert job["allow_failure"] is False
    assert job["rules"], "lab-battery must carry rules"
    for rule in job["rules"]:
        assert rule.get("when") == "manual", rule
    assert {rule["if"] for rule in job["rules"]} == {
        '$CI_PIPELINE_SOURCE == "merge_request_event"',
        '$CI_COMMIT_BRANCH == "main"',
    }


def test_lab_job_battery_sequence():
    job = _parsed()["lab-battery"]
    script = "\n".join(job["script"])
    # the consent refusal comes FIRST: a manual run without the protected
    # consent variable aborts before anything lab-touching starts
    assert f'test "${{{CONSENT_GATE}}}" = "1"' in script
    # the documented KA-009 recipe: compose up -> pytest -> down -v
    assert "docker compose -f docker/lab-targets/docker-compose.yml up -d" in script
    assert "docker compose -f docker/lab-targets/docker-compose.yml ps" in script
    assert "python3 -m pytest tests/lab -q" in script
    assert 'grep -E "[0-9]+ (passed|failed|error)" lab-battery.log' in script
    after = "\n".join(job["after_script"])
    assert "docker/lab-targets/docker-compose.yml down -v" in after


# --- consent + secret discipline ----------------------------------------------

def test_consent_gate_by_name_never_inline_value():
    fence = _fence_text()
    # the gate VALUE lives in a protected CI/CD variable; the refusal test
    # compares the injected value, it never inlines one
    assert f'test "${{{CONSENT_GATE}}}" = "1"' in fence
    # the inline GATE=value form is banned in the yaml
    assert f"{CONSENT_GATE}=" not in fence
    assert "KA_FLEET_HARNESS=" not in fence
    assert "KA_BATTERY_CONSENT=" not in fence


def test_no_secret_value_markers_in_yaml():
    fence = _fence_text().lower()
    hits = [marker for marker in FORBIDDEN_VALUE_MARKERS if marker in fence]
    assert hits == [], hits


def test_yaml_has_no_secret_valued_keys():
    # no secret-VALUED keys anywhere in the parsed fragment (secret keys,
    # when they ever appear, must be GitLab variable REFERENCES, not keys)
    yaml_mod = pytest.importorskip("yaml")
    data = yaml_mod.safe_load(_fence_text())
    findings: list[str] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                key_path = f"{path}.{key}"
                if str(key).lower() in SECRET_VALUED_KEYS:
                    findings.append(key_path)
                walk(value, key_path)
        elif isinstance(node, list):
            for item in node:
                walk(item, path)

    walk(data, "")
    assert findings == [], findings


def test_env_refs_are_names_only():
    fence = _fence_text()
    names = ENV_REF_RE.findall(fence)
    assert names, "expected variable references in the fragment"
    bad = [name for name in names if name != name.upper()]
    assert bad == [], bad


# --- regex fallback: the SHAPE stays pinned offline (no yaml needed) ----------

def test_regex_fallback_pins_the_offline_shape():
    fence = _fence_text()
    assert re.search(r"^stages:", fence, re.MULTILINE)
    assert re.search(r"^\s+- test$", fence, re.MULTILINE)
    assert re.search(r"^\s+- lab$", fence, re.MULTILINE)
    assert "pytest-suite:" in fence
    assert "lab-battery:" in fence
    assert re.search(r"when: manual", fence)
    assert "allow_failure: false" in fence
    # the suite runner + the battery recipe + the documented teardown
    assert "python3 -m pytest tests/ -q" in fence
    assert "docker compose -f docker/lab-targets/docker-compose.yml up -d" in fence
    assert "down -v" in fence
    # the protected-variable note lives inside the fragment
    assert "protected" in fence.lower()