"""KA-038 tests - ForensicsMixin: the kinds (the aliases + the
unknown), the per-kind catalogs (the raw templates), the 5-phase arc
with the read-only policy on every phase, the scrub, and the
never-executes scan. No execution."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.forensics_ops import ForensicsMixin


@pytest.mark.parametrize("kind,input_value", [
    ("memory", "memory"), ("memory", "RAM"),
    ("disk", "disk"), ("disk", "image"),
    ("metadata", "metadata"), ("metadata", "exif"),
])
def test_plan_forensics_kinds_and_aliases(kind, input_value):
    plan = ForensicsMixin().plan_forensics("artifact-fixed.img", input_value)
    assert plan["kind"] == kind
    assert plan["artifact"] == "artifact-fixed.img"
    assert plan["policy"] == {"read_only_on_originals": True,
                              "work_on_copies": True}
    ids = [p["phase"] for p in plan["phases"]]
    assert ids == ["1-preserve", "2-acquire", "3-analyze", "4-timeline",
                   "5-report"]
    for phase in plan["phases"]:
        assert phase["policy"] == {"read_only_on_originals": True,
                                   "work_on_copies": True}
        assert "{artifact}" not in str(phase["sample_commands"])


def test_plan_unknown_kind_refused():
    with pytest.raises(ValueError) as err:
        ForensicsMixin().plan_forensics("artifact.img", "network")
    assert "known: memory, disk, metadata" in str(err.value)


def test_catalog_steps_per_kind():
    mixin = ForensicsMixin()
    memory = mixin.forensics_step_catalog("memory")
    assert memory["steps"][0]["commands"] == ["volatility -f {artifact} psinfo"]
    disk = mixin.forensics_step_catalog("disk")
    assert any(c.startswith("mmls ") for s in disk["steps"] for c in s["commands"])
    assert any(c.startswith("fls ") for s in disk["steps"] for c in s["commands"])
    metadata = mixin.forensics_step_catalog("metadata")
    assert any(c.startswith("exiftool ") for s in metadata["steps"]
               for c in s["commands"])
    kinds = mixin.forensics_step_catalog()
    assert kinds["kinds"] == ["disk", "memory", "metadata"]


def test_forensics_policy_rows():
    policy = ForensicsMixin().forensics_policy()
    assert policy["read_only_on_originals"] is True


def test_scrub_rejects_hostile():
    with pytest.raises(ValueError):
        ForensicsMixin().plan_forensics("img; calc", "memory")
    with pytest.raises(ValueError):
        ForensicsMixin().plan_forensics("", "memory")


def test_module_never_executes():
    import agentic_ai.agents.cyber.forensics_ops as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned
