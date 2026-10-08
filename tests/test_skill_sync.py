"""KA-099 tests - skill sync: the agentic-roles skill carries the lab
battery + runbook references additively, with gate names only (never
values), real repo-relative paths, and no emojis. Source-scan only: it
reads the SKILL.md file and asserts referenced paths exist on disk via
pathlib relative to the repo root. No git, no network, no execution.

History: the test originally synced BOTH skills (kali-agent +
agentic-roles); the kali-agent skill was the operating manual of the
standalone kali_agent_v4 CLI facade and left HEAD with the 2026-10-08
dead-generation cleanup (history c965747) - the sync is now
agentic-roles-only."""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SECTION = "## Lab battery + runbook references"
SKILLS = {
    "agentic-roles": REPO / "skills" / "agentic-roles" / "SKILL.md",
}

# Pictographic ranges only; typographic arrows/dashes are prose, not emojis.
EMOJI_RE = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF"
    "\U00002B00-\U00002BFF\U0000FE0F]"
)

# Repo-relative paths referenced from the sections must exist (files or dirs).
PREFIXES = ("docs/", "docker/", "scripts/", "tests/")


@pytest.mark.parametrize("key", sorted(SKILLS))
def test_battery_section_present_and_additive(key):
    text = SKILLS[key].read_text(encoding="utf-8")
    idx = text.find(SECTION)
    assert idx != -1, f"{key}: section header missing"
    # Additive sync: the first header before the section must be an earlier one.
    first_h2 = text.find("\n## ")
    assert first_h2 != -1 and first_h2 < idx


def test_referenced_section_paths_exist():
    missing = []
    for path in SKILLS.values():
        text = path.read_text(encoding="utf-8")
        section = text[text.find(SECTION):]
        for tok in sorted(set(re.findall(r"(?:docs|docker|scripts|tests)/[\w./-]+", section))):
            tok = tok.rstrip(".,)")
            if not tok.startswith(PREFIXES):
                continue
            if not (REPO / tok).exists():
                missing.append(f"{path.name}: {tok}")
    assert missing == []


@pytest.mark.parametrize("key", sorted(SKILLS))
def test_no_emojis(key):
    text = SKILLS[key].read_text(encoding="utf-8")
    match = EMOJI_RE.search(text)
    assert match is None, f"{key}: emoji {match.group(0)!r} in skills file"


@pytest.mark.parametrize("key", sorted(SKILLS))
def test_gates_referenced_by_name_not_value(key):
    text = SKILLS[key].read_text(encoding="utf-8")
    encoded = re.findall(r"\bKA_[A-Z_]+\s*=\s*\S", text)
    assert encoded == []


def test_content_markers():
    roles = SKILLS["agentic-roles"].read_text(encoding="utf-8")
    # agentic-roles: the battery/runbook set from the ROLE perspective.
    for marker in (
        "docker/fleet-harness",
        "docs/KA-LAB-DETECTION.md",
        "verify_soc_findings",
        "harness.sh reset",
        "scripts/lab/enroll-wazuh.sh",
        "scripts/lab/pve-lab-battery.sh",
        "KA_LAB_CONSENT",
        "KA_BATTERY_CONSENT",
    ):
        assert marker in roles, marker