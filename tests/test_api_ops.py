"""KA-041 tests - APIPentestMixin: the per-style REST/GraphQL plans (the
aliases + the unknown ValueError, the policy on every phase), the
per-style step catalogs (raw {target} templates preserved), the
auth-surface rows (surface/check/detection), the per-class SAFE command
sets, the scrub + host-gate consult, the recon-only command allowlist,
and the never-executes + no-payload source scans. No network; no live
API touching anywhere."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.api_pentest import (APIPentestMixin,
                                                 API_POLICY)

REST_PHASES = ["1-scope", "2-spec", "3-discovery", "4-auth-surface",
               "5-methodology", "6-evidence", "7-report"]
GQL_PHASES = ["1-scope", "2-endpoint", "3-schema", "4-auth-surface",
              "5-methodology", "6-evidence", "7-report"]

# every planned command is a recon/methodology probe or a planner note
ALLOWED_CMD_PREFIXES = ("curl -sS", "curl -sSI", "kr ", "gobuster ",
                        "arjun ", "#")

# payload/hostile-pattern markers that must never appear in the module
FORBIDDEN_MODULES_MARKERS = ("<script", "alert(", "onload", "' 1=1",
                             "1=1--", "../../etc/passwd", "/etc/passwd",
                             "DROP TABLE", "rm -rf", "whoami")


@pytest.mark.parametrize("style,input_value", [
    ("rest", "rest"), ("rest", "RESTFUL"),
    ("graphql", "graphql"), ("graphql", "gql"), ("graphql", "GraphQL"),
])
def test_plan_api_per_style_and_aliases(style, input_value):
    plan = APIPentestMixin().plan_api("api-fixed.example", input_value)
    assert plan["style"] == style
    assert plan["target"] == "api-fixed.example"
    assert plan["policy"] == API_POLICY
    ids = [p["phase"] for p in plan["phases"]]
    assert ids == (REST_PHASES if style == "rest" else GQL_PHASES)
    for phase in plan["phases"]:
        assert phase["policy"] == API_POLICY
        assert phase["activities"]
        assert all("{target}" not in c and "<target" not in c
                   for c in phase["sample_commands"])


def test_plan_refuses_unknown_style():
    with pytest.raises(ValueError) as err:
        APIPentestMixin().plan_api("api-fixed.example", "grpc")
    assert "known: rest, graphql" in str(err.value)


def test_step_catalog_rest():
    cat = APIPentestMixin().api_step_catalog("rest")
    assert cat["style"] == "rest"
    assert cat["policy"] == API_POLICY
    names = [s["step"] for s in cat["steps"]]
    assert names == ["doc-paths", "route-enum", "param-discovery",
                     "headers", "version-walk"]
    doc = cat["steps"][0]["commands"]
    assert all(c.startswith("curl -sS --max-time 15 http://{target}/")
               for c in doc)
    assert "kr scan" in str(cat["steps"][1]["commands"])
    assert "arjun" in str(cat["steps"][2]["commands"])
    # raw templates: {target} placeholders survive, un-replaced
    assert "{target}" in cat["steps"][0]["commands"][0]


def test_step_catalog_graphql():
    cat = APIPentestMixin().api_step_catalog("graphql")
    names = [s["step"] for s in cat["steps"]]
    assert names == ["endpoint-loc", "fingerprint", "introspection",
                     "schema-tools", "persisted"]
    gql_probe = cat["steps"][2]["commands"][0]
    assert "__schema" in gql_probe and "{target}" in gql_probe


@pytest.mark.parametrize("style,surface_name", [
    ("rest", "authorization"), ("graphql", "introspection"),
])
def test_auth_surface_catalog(style, surface_name):
    cat = APIPentestMixin().api_auth_surface_catalog(style)
    assert cat["style"] == style
    assert cat["policy"] == API_POLICY
    assert len(cat["surfaces"]) == 6
    for row in cat["surfaces"]:
        assert set(row) == {"surface", "check", "detection"}
        assert row["surface"] and row["check"] and row["detection"]
    assert surface_name in {row["surface"] for row in cat["surfaces"]}


def test_vuln_classes_lists():
    mixin = APIPentestMixin()
    rest = mixin.api_vuln_classes("rest")
    gql = mixin.api_vuln_classes("graphql")
    assert rest["classes"] == ["cors", "idor", "mass-assignment",
                               "rate-limiting", "versioning"]
    assert gql["classes"] == ["batching", "depth-limiting",
                              "field-suggestion", "introspection",
                              "persisted-queries"]


def test_vuln_commands_rest_exact_shape():
    out = APIPentestMixin().api_vuln_commands("api-fixed.example",
                                              "rest", "idor")
    assert out["target"] == "api-fixed.example"
    assert out["style"] == "rest" and out["vuln_class"] == "idor"
    assert out["step"] == "object-access-diff"
    assert out["policy"] == API_POLICY
    assert out["commands"] == [
        "curl -sS 'http://api-fixed.example/api/v1/items/1'"]


def test_vuln_commands_cors_origin_probe():
    out = APIPentestMixin().api_vuln_commands("api-fixed.example",
                                              "rest", "cors")
    assert out["step"] == "origin-echo"
    assert any(c.startswith("curl -sSI -H 'Origin: ")
               for c in out["commands"])


@pytest.mark.parametrize("style", ["rest", "graphql"])
def test_vuln_commands_every_class_returns_safe_commands(style):
    mixin = APIPentestMixin()
    for name in mixin.api_vuln_classes(style)["classes"]:
        out = mixin.api_vuln_commands("api-fixed.example", style, name)
        assert out["vuln_class"] == name
        assert out["commands"]
        assert all("{target}" not in c for c in out["commands"])
        assert all(any(c.startswith(p) for p in ALLOWED_CMD_PREFIXES)
                   for c in out["commands"])


def test_vuln_commands_unknown_class_refused():
    with pytest.raises(ValueError) as err:
        APIPentestMixin().api_vuln_commands("api-fixed.example",
                                            "graphql", "idor")
    txt = str(err.value)
    assert "unknown vuln class" in txt and "'graphql'" in txt
    with pytest.raises(ValueError):
        APIPentestMixin().api_vuln_commands("api-fixed.example",
                                            "rest", "introspection")


@pytest.mark.parametrize("evil", [
    "api.example.com; rm -rf /",
    "api.example.com && id",
    "$(whoami).api.example.com",
    "api.example.com|cat /etc/passwd",
    "`id`",
    "api.example.com\nid",
    "../api.example.com",
    "a b.api.example.com",
    "",
    None,
])
def test_scrub_rejects_hostile_targets(evil):
    with pytest.raises(ValueError):
        APIPentestMixin().plan_api(evil, "rest")
    with pytest.raises(ValueError):
        APIPentestMixin().api_vuln_commands(evil, "graphql",
                                            "introspection")


class _RejectingGate(APIPentestMixin):
    def validate_target(self, target):
        return False, "lab-range only"


class _AllowingGate(APIPentestMixin):
    def validate_target(self, target):
        return True, ""


def test_host_gate_consulted_and_can_reject():
    gated = _RejectingGate()
    with pytest.raises(ValueError) as err:
        gated.plan_api("api-fixed.example", "rest")
    assert "target rejected by host agent gate: lab-range only" in \
        str(err.value)


def test_host_gate_allow_passes_through():
    plan = _AllowingGate().plan_api("api-fixed.example", "graphql")
    assert plan["target"] == "api-fixed.example"


def test_index_and_policy_rows():
    mixin = APIPentestMixin()
    assert mixin.api_index() == {"styles": ["graphql", "rest"],
                                 "policy": API_POLICY}
    assert mixin.api_policy() == API_POLICY


def test_ops_surface_present():
    for op in ("api_index", "api_policy", "plan_api", "api_step_catalog",
               "api_auth_surface_catalog", "api_vuln_classes",
               "api_vuln_commands"):
        assert callable(getattr(APIPentestMixin, op, None)), op


def test_all_sample_commands_are_recon_or_planner_notes():
    mixin = APIPentestMixin()
    all_cmds = []
    for style in ("rest", "graphql"):
        cat = mixin.api_step_catalog(style)
        all_cmds += [c for s in cat["steps"] for c in s["commands"]]
        plan = mixin.plan_api("api-fixed.example", style)
        all_cmds += [c for p in plan["phases"]
                     for c in p["sample_commands"]]
        for name in mixin.api_vuln_classes(style)["classes"]:
            all_cmds += mixin.api_vuln_commands("api-fixed.example",
                                                style,
                                                name)["commands"]
    assert len(all_cmds) > 20
    for cmd in all_cmds:
        assert any(cmd.startswith(prefix)
                   for prefix in ALLOWED_CMD_PREFIXES), cmd[:60]


def test_module_never_executes():
    import agentic_ai.agents.cyber.api_pentest as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned


def test_module_has_no_payload_blobs():
    import agentic_ai.agents.cyber.api_pentest as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for marker in FORBIDDEN_MODULES_MARKERS:
        assert marker not in source, marker