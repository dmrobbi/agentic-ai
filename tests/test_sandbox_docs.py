"""KA-059 - the docker/sandbox PROFILE: parse-and-pin tests for the
deny-by-default posture artifacts. Pins: the dir layout, the README's
required sections, the manifest's required keys + deny-by-default
statements + egress tier semantics (KA-055 wave wording), the compose
fragment's per-service hardening set, the reference rule (fragment
images/paths exist in-repo or are documented integration mounts), and the
doctor-check spec. Parse/validate only: no container execution, no docker
socket, no network.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SBX = REPO / "docker" / "sandbox"
README_PATH = SBX / "README.md"
PROFILE_PATH = SBX / "sandbox-profile.yml"
FRAGMENT_PATH = SBX / "docker-compose.sandbox.yml"

# Measured layout: the dir carries exactly these three artifacts.
SANDBOX_FILES = frozenset({"README.md", "sandbox-profile.yml", "docker-compose.sandbox.yml"})

# Measured README structure: every required section heading, verbatim.
README_HEADINGS = (
    "## Files",
    "## Profile format",
    "## Deny-by-default posture",
    "## Mountable compose fragment",
    "## Egress posture",
    "## Doctor-check spec",
    "## Test pins",
)

# Measured manifest shape (yaml.safe_load over sandbox-profile.yml).
MANIFEST_TOP_KEYS = frozenset(
    {
        "profile",
        "default_deny",
        "mounts",
        "images",
        "network",
        "egress",
        "capabilities",
        "security",
        "environment",
        "runtime",
        "services",
        "doctor_checks",
        "integrations",
    }
)
MANIFEST_TOP_KEY_COUNT = 13  # measured

DENY_AXES = frozenset({"mounts", "network", "capabilities", "egress", "syscalls", "execution"})
DENY_AXIS_COUNT = 6  # measured

# KA-055 wave semantics, pinned verbatim from the manifest egress section.
EGRESS_TIERS = {"rfc1918": "lab-staging-required", "external": "auth-tag-required"}
DNS_STRATEGY = "staging-only"

DOCTOR_CHECK_COUNT = 12  # measured: SBX-01..SBX-12

FRAG_SERVICE_COUNT = 2  # measured: the two documented tiers
FRAG_SERVICES = {"sandbox-runtime", "sandbox-runtime-lab"}

TMPFS_SCRATCH = "/tmp:rw,noexec,nosuid,size=64m,mode=1777"  # measured single scratch entry
LAB_ENV_LITERAL = "SANDBOX_EGRESS=lab-staged"  # the single allowlisted literal

# Strings that must never appear in the RUNTIME fragment (host posture).
FRAGMENT_BANNED_STRINGS = (
    "privileged",
    "unconfined",
    "cap_add",
    "network_mode: host",
    "cgroup",
    "apparmor: unconfined",
    "seccomp: unconfined",
)

# Keys a sandbox service must never carry.
FRAGMENT_BANNED_KEYS = (
    "cap_add",
    "privileged",
    "devices",
    "pid",
    "ipc",
    "uts",
    "userns_mode",
    "cgroup_parent",
    "depends_on",
    "container_name",
)


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _readme_flat() -> str:
    """README text with whitespace normalized across wrapped lines."""
    return " ".join(README_PATH.read_text(encoding="utf-8").split())


# --- dir layout -----------------------------------------------------------


def test_sandbox_dir_layout():
    assert SBX.is_dir()
    files = {p.name for p in SBX.iterdir() if p.is_file()}
    assert files == SANDBOX_FILES, files
    assert len(files) == len(SANDBOX_FILES) == 3  # measured


# --- README structure -----------------------------------------------------


def test_readme_required_sections():
    readme = README_PATH.read_text(encoding="utf-8")
    first = readme.splitlines()[0]
    assert first.startswith("# docker/sandbox")
    assert "KA-059" in first
    for heading in README_HEADINGS:
        assert heading in readme, heading


def test_readme_documents_profile_format_and_integration_mounting():
    flat = _readme_flat()
    for needle in (
        "sandbox-profile.yml",
        "docker-compose.sandbox.yml",
        "KA-INT-4",
        "KA-055",
        "RFC1918",
        "compose fragment",
        "documentation, not implementation",
    ):
        assert needle in flat, needle


# --- manifest structure ---------------------------------------------------


def test_manifest_parses_with_required_top_keys():
    manifest = _load_yaml(PROFILE_PATH)
    assert set(manifest) == MANIFEST_TOP_KEYS
    assert len(manifest) == MANIFEST_TOP_KEY_COUNT  # measured: 13 sections
    header = manifest["profile"]
    assert header["name"] == "fleet-sandbox"
    assert header["version"] == 1
    assert header["format"] == 1
    assert header["status"] == "reviewed"  # acceptance: profile reviewed
    assert header["mounted_by"] == "KA-INT-4"


def test_manifest_deny_by_default_statements():
    manifest = _load_yaml(PROFILE_PATH)
    deny = manifest["default_deny"]
    assert set(deny) == DENY_AXES
    assert len(deny) == DENY_AXIS_COUNT  # measured: 6 axes
    for axis, value in deny.items():
        assert value is True, f"default_deny[{axis}] must stay True"
    assert manifest["capabilities"] == {"drop": ["ALL"], "add": []}
    network = manifest["network"]
    assert network["baseline"] == "none"
    assert network["attachable"] is False
    assert "DENY-BY-DEFAULT" in manifest["mounts"]["policy"]
    assert manifest["egress"]["baseline"] == "deny"
    assert manifest["security"]["no_new_privileges"] is True
    assert manifest["security"]["readonly_rootfs"] is True
    assert manifest["runtime"]["restart"] == "no"


def test_manifest_egress_wave_semantics():
    egress = _load_yaml(PROFILE_PATH)["egress"]
    for tier, tier_policy in EGRESS_TIERS.items():
        assert egress[tier] == tier_policy, tier
    assert egress["dns"]["strategy"] == DNS_STRATEGY


def test_manifest_images_and_mounts_documented():
    manifest = _load_yaml(PROFILE_PATH)
    images = manifest["images"]["allowlist"]
    assert images
    for entry in images:
        assert entry["integration_mount"] is True
        assert entry["exists_via"].strip()
    mounts = manifest["mounts"]["allowlist"]
    assert mounts
    for entry in mounts:
        assert set(entry) >= {"source", "target", "mode", "integration_mount", "note"}
        assert entry["mode"] == "ro"
        src = entry["source"]
        resolved = Path(src) if Path(src).is_absolute() else REPO / src
        # the reference rule: the path exists in-repo, or the entry is an
        # explicitly documented integration mount
        assert resolved.exists() or entry["integration_mount"] is True, src


def test_doctor_checks_specified():
    manifest = _load_yaml(PROFILE_PATH)
    checks = manifest["doctor_checks"]
    assert len(checks) == DOCTOR_CHECK_COUNT  # measured: 12 spec'd checks
    ids = [c["id"] for c in checks]
    assert ids == [f"SBX-{i:02d}" for i in range(1, DOCTOR_CHECK_COUNT + 1)]
    for check in checks:
        assert set(check) == {"id", "check", "expected"}
        assert check["check"].strip()
        assert check["expected"].strip()


def test_doctor_ids_surface_in_readme():
    readme = _readme_flat()
    for check in _load_yaml(PROFILE_PATH)["doctor_checks"]:
        assert check["id"] in readme, check["id"]


# --- compose fragment -----------------------------------------------------


def test_fragment_parses_with_two_documented_tiers():
    fragment = _load_yaml(FRAGMENT_PATH)
    assert set(fragment) == {"services", "networks"}
    assert set(fragment["services"]) == FRAG_SERVICES
    assert len(fragment["services"]) == FRAG_SERVICE_COUNT  # measured


@pytest.mark.parametrize("service_name", sorted(FRAG_SERVICES), ids=sorted(FRAG_SERVICES))
def test_fragment_service_hardened(service_name: str):
    fragment = _load_yaml(FRAGMENT_PATH)
    svc = fragment["services"][service_name]

    # opt-in tier: a bare up of the fragment alone starts nothing
    profiles = svc.get("profiles") or []
    assert len(profiles) == 1
    # noWHAT shipped: the integration supplies entrypoint/command
    assert "entrypoint" not in svc
    assert "command" not in svc
    # zero published ports, zero host bind mounts
    assert not svc.get("ports")
    assert not svc.get("volumes")
    # the hardening set
    assert svc["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in svc["security_opt"]
    assert svc["read_only"] is True
    assert svc["user"] == "65534:65534"
    assert svc["restart"] == "no"
    assert svc["pids_limit"] == 256
    assert svc["mem_limit"] == "2g"
    assert svc["tmpfs"] == [TMPFS_SCRATCH]
    for banned_key in FRAGMENT_BANNED_KEYS:
        assert banned_key not in svc, banned_key
    # environment only via the allowlisted literals
    env = svc.get("environment")
    if env is not None:
        for literal in env:
            assert literal in _load_yaml(PROFILE_PATH)["environment"]["literals_allowlist"]


def test_fragment_network_posture():
    fragment = _load_yaml(FRAGMENT_PATH)
    manifest = _load_yaml(PROFILE_PATH)
    base = fragment["services"]["sandbox-runtime"]
    assert base.get("network_mode") == "none"
    assert "networks" not in base

    lab = fragment["services"]["sandbox-runtime-lab"]
    lab_keys = lab.get("networks") or []
    assert lab_keys
    top_networks = fragment.get("networks") or {}
    assert set(lab_keys) <= set(top_networks)
    allowed_names = {a["name"] for a in manifest["network"]["allowlist"]}
    assert allowed_names == {"lab-targets_default"}  # measured
    for key in lab_keys:
        entry = top_networks[key]
        assert entry.get("external") is True
        assert entry["name"] in allowed_names


def test_fragment_references_only_documented_images():
    fragment = _load_yaml(FRAGMENT_PATH)
    manifest = _load_yaml(PROFILE_PATH)
    allowed = {e["image"]: e for e in manifest["images"]["allowlist"]}
    assert allowed == {"agentic-ai:latest": allowed["agentic-ai:latest"]}  # measured
    for name, svc in fragment["services"].items():
        image = svc.get("image")
        assert image in allowed, f"undocumented image in {name}: {image}"
        documented = allowed[image]
        assert documented["integration_mount"] is True
        # exists_via must reference repo files that really exist
        assert "docker-compose.yml" in documented["exists_via"]
        assert (REPO / "docker-compose.yml").is_file()
        assert (REPO / "Dockerfile").is_file()


def test_fragment_build_contexts_exist():
    fragment = _load_yaml(FRAGMENT_PATH)
    for name, svc in fragment["services"].items():
        if "build" not in svc:  # the shipped fragment ships no build section
            continue
        build = svc["build"]
        context = build if isinstance(build, str) else (build.get("context") or ".")
        context_path = Path(context) if Path(context).is_absolute() else SBX / context
        assert context_path.resolve().is_dir(), name


def test_fragment_runtime_surface_is_not_privileged():
    text = FRAGMENT_PATH.read_text(encoding="utf-8")
    for banned in FRAGMENT_BANNED_STRINGS:
        assert banned not in text, banned
    manifest_text = PROFILE_PATH.read_text(encoding="utf-8")
    for banned in ("unconfined", "privileged"):
        assert banned not in manifest_text, banned