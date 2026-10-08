"""FullEngagementMixin (KA-050 / OPT-50): compose the landed planner
families into ONE ordered engagement plan (no execution).

COMPOSITION CONTRACT - documented here, returned as data by
full_engagement_index(), and pinned by tests/test_full_engagement.py:

Families: this mixin composes, by inheritance, ONLY the planner mixins
landed at build time: WebPentestMixin, RedTeamMixin, XssMixin,
PrivescMixin, ADMixin, CloudMixin, ContainerMixin, MobileMixin,
WirelessMixin, OSINTMixin, ForensicsMixin. All are stateless planner
classes (no __init__), so multiple inheritance is safe; the module
imports only these family modules. Sibling mixins landing in the same
wave (malware/network-device/api/social-eng/ics-iot/post-exp/web-auth/
chain) are deliberately NOT composed here.

Core arc: plan_full_engagement emits exactly the four core stages
below, in this fixed order - passive before active, assessment before
injection-class verification, escalation last (post-foothold):
    1 recon   (plan_osint + web_recon_commands)
    2 web     (plan_web_pentest + web_enum_commands)
    3 xss     (plan_xss_exploit)
    4 privesc (plan_privesc)
The core stages and their order are pinned; extension stages are
appended AFTER them and never reshuffle the core.

Shared context: the target is scrubbed ONCE through the shared helper
(wp_scrub_target) and then handed to every family guard, which scrubs
idempotently and consults the host agent's validate_target via getattr
with a silent fallback when no gate exists. Every planned command
string still passes the chassis's normal execution gates before anyone
would run it.

Knobs: target (the single scrubbed external string), platform (the
privesc slot; aliases are the family's business), osint_lane (the
recon lane; validated by the family), extensions (optional; a lane
name iterable that takes the registry's safe defaults, or a mapping
lane -> overrides for the registry's extra kwargs).

Extension contract: a future family plugs in as ONE EXTENSION_LANES
row - planner (the family op name), shared_slot (the kwarg that
receives the shared scrubbed target), extra_kwargs (override slots),
defaults (safe defaults for those slots), policy_note. Extra string
values pass the shared scrub, except the enum slots cloud/runtime/
kind, which the family alias tables validate themselves. Registry
order is the extension stage order: callers' ordering choices are
sorted back into registry order. No core change is ever needed, and
integrating an agent adds only THIS mixin to the chassis class line -
the families ride along through inheritance.
"""

from __future__ import annotations

from agentic_ai.agents.cyber.web_pentest import WebPentestMixin, wp_scrub_target
from agentic_ai.agents.cyber.redteam_pentest import RedTeamMixin
from agentic_ai.agents.cyber.xss_exploit import XssMixin
from agentic_ai.agents.cyber.privesc import PrivescMixin
from agentic_ai.agents.cyber.ad_pentest import ADMixin
from agentic_ai.agents.cyber.cloud_pentest import CloudMixin
from agentic_ai.agents.cyber.container_pentest import ContainerMixin
from agentic_ai.agents.cyber.mobile_pentest import MobileMixin
from agentic_ai.agents.cyber.wireless_pentest import WirelessMixin
from agentic_ai.agents.cyber.osint_pentest import OSINTMixin
from agentic_ai.agents.cyber.forensics_ops import ForensicsMixin

POLICY = {"planners_only": True, "no_execution": True, "shared_scrub": True}

# the core arc: stage name -> family planner ops, in contract order
CORE_STAGES = (
    ("recon", ("plan_osint", "web_recon_commands")),
    ("web", ("plan_web_pentest", "web_enum_commands")),
    ("xss", ("plan_xss_exploit",)),
    ("privesc", ("plan_privesc",)),
)

# extension registry: ONE row per future family; insertion order is the
# extension stage order. planner = the family op; shared_slot receives the
# shared scrubbed target (overridable only when itself listed); the rest
# are the family's extra kwargs with safe defaults.
EXTENSION_LANES = {
    "redteam": {
        "planner": "plan_redteam", "shared_slot": "scope",
        "extra_kwargs": ("scope",), "defaults": (None,),
        "policy_note": "the red-team phase arc plus the tool-catalog "
                       "framing; scope defaults to the shared target",
    },
    "ad": {
        "planner": "plan_ad", "shared_slot": "scope",
        "extra_kwargs": ("dc",), "defaults": (None,),
        "policy_note": "lab-only family policy; a public-domain scope "
                       "is refused by the family itself",
    },
    "cloud": {
        "planner": "plan_cloud", "shared_slot": "account_label",
        "extra_kwargs": ("cloud",), "defaults": ("aws",),
        "policy_note": "sandbox-account family policy; the cloud slot "
                       "goes through the family alias table",
    },
    "container": {
        "planner": "plan_container_escape", "shared_slot": "context_label",
        "extra_kwargs": ("runtime",), "defaults": ("docker",),
        "policy_note": "sandbox-context family policy; the runtime slot "
                       "goes through the family alias table",
    },
    "mobile": {
        "planner": "plan_mobile_apk", "shared_slot": "apk_label",
        "extra_kwargs": (), "defaults": (),
        "policy_note": "static-first family policy; the artifact label "
                       "defaults to the shared target",
    },
    "wireless": {
        "planner": "plan_wireless_capture", "shared_slot": "interface",
        "extra_kwargs": ("channel",), "defaults": (None,),
        "policy_note": "rf-lab-only family policy; the interface slot "
                       "defaults to the shared target",
    },
    "forensics": {
        "planner": "plan_forensics", "shared_slot": "artifact_label",
        "extra_kwargs": ("kind",), "defaults": ("memory",),
        "policy_note": "read-only-on-originals family policy; the kind "
                       "slot goes through the family alias table",
    },
}

# extras the family alias tables VALIDATE (so the shared scrub is not
# needed there); every other string extra passes wp_scrub_target
ENUM_EXTRAS = frozenset({"cloud", "runtime", "kind"})


def _resolve_extension_rows(extensions, registry):
    """Validate + normalize the extensions argument against a registry.

    Returns [(lane, registry_row, kwargs), ...] in REGISTRY order
    (caller ordering choices never leak into the stage order). A
    module-level helper so the extendability test can exercise a
    one-row registry without touching the real constant.
    """
    if extensions is None:
        return []
    if isinstance(extensions, dict):
        items = []
        for lane, overrides in extensions.items():
            if not isinstance(overrides, dict):
                raise ValueError(
                    "extension overrides for lane %r must be a dict" % (lane,))
            items.append((lane, overrides))
    elif isinstance(extensions, (list, tuple)):
        for name in extensions:
            if not isinstance(name, str):
                raise ValueError("extension lane names must be strings")
        items = [(lane, {}) for lane in extensions]
    else:
        raise ValueError(
            "extensions must be a lane iterable or a lane->overrides "
            "mapping, not %r" % (extensions,))
    seen = set()
    for lane, _ in items:
        if lane in seen:
            raise ValueError("duplicate extension lane %r" % (lane,))
        seen.add(lane)
    for lane, _ in items:
        if lane not in registry:
            raise ValueError("unknown extension lane %r - known: %s"
                             % (lane, ", ".join(registry)))
    order_index = {lane: i for i, lane in enumerate(registry)}
    items.sort(key=lambda item: order_index[item[0]])
    rows = []
    for lane, overrides in items:
        row = registry[lane]
        kwargs = dict(zip(row["extra_kwargs"], row["defaults"]))
        for key, value in overrides.items():
            if key not in row["extra_kwargs"]:
                raise ValueError(
                    "unknown override %r for extension lane %r - known: %s"
                    % (key, lane, ", ".join(row["extra_kwargs"])))
            if key not in ENUM_EXTRAS and isinstance(value, str):
                value = wp_scrub_target(value)
            kwargs[key] = value
        rows.append((lane, row, kwargs))
    return rows


class FullEngagementMixin(WebPentestMixin, RedTeamMixin, XssMixin, PrivescMixin,
                          ADMixin, CloudMixin, ContainerMixin, MobileMixin,
                          WirelessMixin, OSINTMixin, ForensicsMixin):
    """Ordered engagement-plan composition over the landed family
    mixins (planning only; the contract lives in this module's
    docstring and in full_engagement_index())."""

    @staticmethod
    def _fe_scrub(value):
        """Thin staticmethod wrapper over the shared target scrub."""
        return wp_scrub_target(value)

    def _fe_guard(self, value, what="target"):
        """Scrub, then consult the host agent's validate_target via
        getattr with a silent fallback when the chassis lacks one."""
        scrubbed = self._fe_scrub(value)
        gate = getattr(self, "validate_target", None)
        if callable(gate):
            ok, msg = gate(scrubbed)
            if not ok:
                raise ValueError(
                    "%s rejected by host agent gate: %s" % (what, msg))
        return scrubbed

    def full_engagement_index(self) -> dict:
        """The composition contract as data (stage order, per-stage
        ops, the extension registry, and the module policy); the test
        battery pins this shape."""
        return {
            "policy": dict(POLICY),
            "core_stages": [{"stage": stage, "kind": "core", "ops": list(ops)}
                            for stage, ops in CORE_STAGES],
            "extensions": [{"lane": lane, "planner": row["planner"],
                            "shared_slot": row["shared_slot"],
                            "extra_kwargs": list(row["extra_kwargs"]),
                            "defaults": list(row["defaults"]),
                            "policy_note": row["policy_note"]}
                           for lane, row in EXTENSION_LANES.items()],
        }

    def plan_full_engagement(self, target, platform="unix",
                             osint_lane="domain", extensions=None):
        """Compose recon, web, XSS, and privilege-escalation planning
        into one ordered engagement plan (optional extension lanes are
        appended in registry order)."""
        shared = self._fe_guard(target)
        # every family plan is computed against the SAME scrubbed target;
        # knob errors surface as the consuming family's ValueError
        recon_os = self.plan_osint(shared, osint_lane)
        recon_web = self.web_recon_commands(shared)
        web_plan = self.plan_web_pentest(shared)
        web_enum = self.web_enum_commands(shared)
        xss_plan = self.plan_xss_exploit(shared)
        privesc_plan = self.plan_privesc(shared, platform)
        core_plans = {
            "plan_osint": recon_os,
            "web_recon_commands": recon_web,
            "plan_web_pentest": web_plan,
            "web_enum_commands": web_enum,
            "plan_xss_exploit": xss_plan,
            "plan_privesc": privesc_plan,
        }
        stages = []
        order = 0
        for stage, ops in CORE_STAGES:
            order += 1
            stages.append({
                "stage": stage, "kind": "core", "order": order,
                "ops": list(ops),
                "plans": {op: core_plans[op] for op in ops},
            })
        for lane, row, kwargs in _resolve_extension_rows(extensions,
                                                         EXTENSION_LANES):
            kwargs[row["shared_slot"]] = kwargs.get(row["shared_slot"]) or shared
            plan = getattr(self, row["planner"])(**kwargs)
            order += 1
            stages.append({
                "stage": lane, "kind": "extension", "order": order,
                "ops": [row["planner"]],
                "plans": {row["planner"]: plan},
                "policy_note": row["policy_note"],
            })
        return {
            "target": shared,
            "platform": privesc_plan["platform"],
            "osint_lane": recon_os["lane"],
            "policy": dict(POLICY),
            "stages": stages,
        }
