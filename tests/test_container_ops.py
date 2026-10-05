"""KA-034 tests - ContainerMixin: the per-runtime plans + aliases + the
unknown ValueError, the sandbox-only policy on every phase, the k8s
RBAC checklist rows, the tool catalog shapes (and the whitespace quirk
in the catalog's tool names pinned as an index artifact to normalize in
a future regen), the label guard, and the never-executes scan."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.container_pentest import ContainerMixin


@pytest.mark.parametrize("runtime,input_value", [
    ("docker", "docker"), ("containerd", "containerd"),
    ("k8s", "k8s"), ("k8s", "kubernetes"), ("k8s", "K8S-Cluster"),
])
def test_plan_container_escape_per_runtime(runtime, input_value):
    plan = ContainerMixin().plan_container_escape("sandbox-ctx-a", input_value)
    assert plan["runtime"] == runtime
    assert plan["context_label"] == "sandbox-ctx-a"
    assert plan["policy"] == {"sandbox_contexts_only": True}
    ids = [p["phase"] for p in plan["phases"]]
    assert ids == ["1-scope", "2-enumerate", "3-escape-fit",
                   "4-escape-strategy", "5-evidence", "6-hardening"]
    for phase in plan["phases"]:
        assert phase["policy"] == {"sandbox_contexts_only": True}
    cmds = [c for p in plan["phases"] for c in p["sample_commands"]]
    assert cmds and all("{context_label}" not in c and "<runtime>" not in c
                        for c in cmds)


def test_unknown_runtime_refused():
    with pytest.raises(ValueError) as err:
        ContainerMixin().plan_container_escape("ctx", "lxc")
    assert "known: docker, containerd, k8s" in str(err.value)


def test_context_label_guard():
    with pytest.raises(ValueError):
        ContainerMixin().plan_container_escape("", "docker")
    with pytest.raises(ValueError):
        ContainerMixin().plan_container_escape(None, "docker")


def test_k8s_rbac_checklist():
    checklist = ContainerMixin().k8s_rbac_checklist()
    assert checklist["policy"] == {"sandbox_contexts_only": True}
    assert len(checklist["checklist"]) == 6
    assert "serviceaccount with cluster-admin" in checklist["checklist"][0]


def test_container_tool_catalog_shapes():
    catalog = ContainerMixin().container_tool_catalog()
    names = {t["name"] for t in catalog["tools"]}
    assert {"deepce", "cdk", "kubehound", "kube-bench"} <= names
    for tool in catalog["tools"]:
        assert tool["purpose"] and tool["url"].startswith("https://")
    # PINNED QUIRK (the index artifact to normalize in a future regen):
    # one row carried a leading space in the name (' kube-bench'); the
    # catalog strips it on load - pinned as the load-time normalization.
    assert " kube-bench" not in names


def test_module_never_executes():
    import agentic_ai.agents.cyber.container_pentest as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "import socket", "kubectl"):
        # NOTE: the bare 'socket' word = the domain language here (the
        # docker.sock greps are planned commands); the precise ban = the
        # import statement.
        assert banned not in source, banned
