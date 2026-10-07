"""KA-F01 builder conventions: suite-baseline pin + three-mixin import graph.

Pin discipline: BASELINE_SUITE_TOTAL equals the pytest --collect-only total
over tests/ (env-independent: conditional skips do not affect collection).
Every task that adds or removes tests updates this constant in its own task;
a mismatch fails loudly instead of drifting silently. The env-conditional
skip allowlist lives in docs/KA-BUILDING-CONVENTIONS.md.
"""
from __future__ import annotations

import importlib
import re
import subprocess
import sys
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.redteam_pentest import RedTeamMixin
from agentic_ai.agents.cyber.web_pentest import WebPentestMixin, wp_scrub_target
from agentic_ai.agents.cyber.xss_exploit import XssMixin
from agentic_ai.agents.cyber.ad_pentest import ADMixin
from agentic_ai.agents.cyber.api_pentest import APIPentestMixin
from agentic_ai.agents.cyber.chain_ops import ContractAnalysisMixin
from agentic_ai.agents.cyber.cloud_pentest import CloudMixin
from agentic_ai.agents.cyber.container_pentest import ContainerMixin
from agentic_ai.agents.cyber.forensics_ops import ForensicsMixin
from agentic_ai.agents.cyber.ics_iot import IcsIoTMixin
from agentic_ai.agents.cyber.full_engagement import FullEngagementMixin
from agentic_ai.agents.cyber.malware_ops import MalwareAnalysisMixin
from agentic_ai.agents.cyber.mobile_pentest import MobileMixin
from agentic_ai.agents.cyber.network_device import NetworkDeviceMixin
from agentic_ai.agents.cyber.osint_pentest import OSINTMixin
from agentic_ai.agents.cyber.postexp import PostExploitMixin
from agentic_ai.agents.cyber.privesc import PrivescMixin
from agentic_ai.agents.cyber.socialeng_ops import SocialEngMixin
from agentic_ai.agents.cyber.webauth_ops import WebAuthMixin
from agentic_ai.agents.cyber.wireless_pentest import WirelessMixin
from agentic_ai.agents.registry import create_agent, resolve_agent_class

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_SUITE_TOTAL = 4021

EXPECTED_MIXINS = (WebPentestMixin, RedTeamMixin, XssMixin, PrivescMixin,
    ADMixin, CloudMixin, ContainerMixin, MobileMixin, WirelessMixin,
    OSINTMixin, ForensicsMixin, MalwareAnalysisMixin, NetworkDeviceMixin,
    APIPentestMixin, SocialEngMixin, IcsIoTMixin, PostExploitMixin,
    WebAuthMixin, ContractAnalysisMixin, FullEngagementMixin)


def _collected_test_total():
    """Collect-count the whole tests/ tree in a subprocess (no run, no network)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, (
        "collection failed:" + proc.stdout[-4000:] + proc.stderr[-2000:]
    )
    match = re.search(r"(\d+) tests collected", proc.stdout)
    assert match, "unparsable collect-only summary:" + proc.stdout[-2000:]
    return int(match.group(1))


def test_baseline_suite_total_matches_pin():
    assert _collected_test_total() == BASELINE_SUITE_TOTAL


def test_mixin_modules_import_cleanly():
    # top-level imports above already prove acyclicity at collection time;
    # assert every mixin class surfaced on its module after import.
    for module_name, class_name in (
        ("web_pentest", "WebPentestMixin"),
        ("redteam_pentest", "RedTeamMixin"),
        ("xss_exploit", "XssMixin"),
    ):
        module = importlib.import_module("agentic_ai.agents.cyber." + module_name)
        assert hasattr(module, class_name), (module_name, class_name)


@pytest.mark.parametrize("agent_id", ["kali", "kali_v2"])
def test_kali_agents_mro_carries_all_three_mixins(agent_id):
    cls = resolve_agent_class(agent_id)
    for mixin in EXPECTED_MIXINS:
        assert issubclass(cls, mixin), (agent_id, mixin.__name__)


@pytest.mark.parametrize("agent_id", ["kali", "kali_v2"])
def test_registry_create_agent_planner_smoke(agent_id):
    agent = create_agent(agent_id)
    assert agent is not None
    assert callable(agent.plan_web_pentest)
    assert callable(agent.plan_redteam)
    assert callable(agent.plan_xss_exploit)


def test_shared_scrub_helper_rejects_hostile_targets():
    # the shared input gate: pure, offline, raises on hostile shapes
    with pytest.raises(ValueError):
        wp_scrub_target("127.0.0.1; rm -rf /")
    with pytest.raises(ValueError):
        wp_scrub_target("")
    assert wp_scrub_target(" 127.0.0.1 ") == "127.0.0.1"
