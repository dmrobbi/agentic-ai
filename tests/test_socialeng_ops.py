"""KA-042 tests - SocialEngMixin: the consent gate (the refusals + the
with-consent path on synthetic records), the lab-only policy on every
phase, the exercise/channel/scenario aliases + the unknown ValueErrors,
the SOC watch pairings + the measurement rows, the scrub + the
host-gate consult, and the never-executes scan. Offline; no payload
texts anywhere."""
from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.socialeng_ops import POLICY, SocialEngMixin

BASELINE_POLICY = {"lab_only": True, "consent_required": True,
                   "no_payload_generation": True}

_FUTURE = (datetime.date.today()
           + datetime.timedelta(days=7)).isoformat()
_PAST = (datetime.date.today()
         - datetime.timedelta(days=30)).isoformat()


def _consent(**overrides):
    """A synthetic VALID consent record (the with-consent path seed)."""
    record = {"authorized_by": "lab-owner-e2e-marker",
              "scope": "lab cohort A; lab-day windows only",
              "expires": _FUTURE}
    record.update(overrides)
    return record


@pytest.mark.parametrize("consent,needle", [
    (None, "consent record required"),
    (True, "consent record required"),
    ({"authorized_by": "lab-owner-e2e-marker", "scope": "lab cohort"},
     "missing required fields: expires"),
    ({"authorized_by": "lab-owner-e2e-marker", "expires": _FUTURE},
     "missing required fields: scope"),
    ({"scope": "lab cohort", "expires": _FUTURE},
     "missing required fields: authorized_by"),
    ({"authorized_by": "", "scope": "lab cohort", "expires": _FUTURE},
     "'authorized_by' must be a non-empty string"),
    ({"authorized_by": "lab-owner-e2e-marker", "scope": "   ",
      "expires": _FUTURE}, "'scope' must be a non-empty string"),
    ({"authorized_by": "lab-owner-e2e-marker", "scope": "lab cohort",
      "expires": "2026-13-01"}, "ISO date"),
    ({"authorized_by": "lab-owner-e2e-marker", "scope": "lab cohort",
      "expires": _PAST}, "expired on"),
])
def test_consent_gate_refusals(consent, needle):
    """Every malformed consent record refuses on BOTH planners."""
    with pytest.raises(ValueError) as err:
        SocialEngMixin().plan_phishing_simulation(consent, "lab-cohort-a")
    assert needle in str(err.value)
    with pytest.raises(ValueError):
        SocialEngMixin().plan_impersonation_exercise(consent,
                                                     "lab-cohort-a")


def test_with_consent_phishing_structure():
    """The synthetic-with-consent path: the full phishing plan shape."""
    record = _consent()
    plan = SocialEngMixin().plan_phishing_simulation(record,
                                                     "lab-cohort-a")
    assert plan["exercise"] == "phishing"
    assert plan["audience_label"] == "lab-cohort-a"
    assert plan["channel"] == "email"          # the safe default
    assert plan["consent_summary"] == {
        "authorized_by": "lab-owner-e2e-marker",
        "scope": "lab cohort A; lab-day windows only",
        "expires": _FUTURE}
    assert plan["policy"] == BASELINE_POLICY == POLICY
    assert [p["phase"] for p in plan["phases"]] == [
        "1-consent", "2-audience", "3-channel-timing", "4-soc-watch",
        "5-measure", "6-debrief"]
    for phase in plan["phases"]:
        assert phase["policy"] == BASELINE_POLICY
        assert phase["goal"] and phase["activities"]
    commands = [cmd for p in plan["phases"]
                for cmd in p["sample_commands"]]
    assert all(cmd.startswith("# ") for cmd in commands)
    assert all("{audience_label}" not in cmd and "<channel>" not in cmd
               and "<exercise>" not in cmd for cmd in commands)
    assert all(set(row) == {"watch", "note"} and row["note"]
               for row in plan["soc_watch"])
    joined = " ".join(commands)
    assert "lab-owner-e2e-marker" not in joined
    assert "lab cohort" not in joined      # consent prose never inlined


def test_with_consent_impersonation_structure():
    """The synthetic-with-consent path: the impersonation arc shape."""
    plan = SocialEngMixin().plan_impersonation_exercise(_consent(),
                                                        "lab-cohort-b")
    assert plan["exercise"] == "impersonation"
    assert plan["scenario"] == "helpdesk"
    assert plan["channel"] == "voice"          # the safe default
    assert [p["phase"] for p in plan["phases"]] == [
        "1-consent", "2-audience", "3-scenario-class", "4-soc-watch",
        "5-measure", "6-debrief"]
    assert all(p["policy"] == BASELINE_POLICY for p in plan["phases"])
    for cmd in (c for p in plan["phases"]
                for c in p["sample_commands"]):
        assert cmd.startswith("# ") and "<scenario>" not in cmd


@pytest.mark.parametrize("scenario,input_value", [
    ("helpdesk", "helpdesk"), ("helpdesk", "service-desk"),
    ("vendor", "vendor"), ("vendor", "supply"),
    ("executive", "executive"), ("executive", "boss"),
])
def test_impersonation_scenario_aliases(scenario, input_value):
    plan = SocialEngMixin().plan_impersonation_exercise(
        _consent(), "lab-cohort-a", scenario=input_value)
    assert plan["scenario"] == scenario


@pytest.mark.parametrize("channel,input_value", [
    ("email", "email"), ("email", "MAIL"),
    ("sms", "sms"), ("sms", "text"),
    ("voice", "voice"), ("voice", "phone"),
])
def test_channel_aliases_in_planned_work(channel, input_value):
    plan = SocialEngMixin().plan_phishing_simulation(
        _consent(), "lab-cohort-a", channel=input_value)
    assert plan["channel"] == channel


def test_unknown_values_refused_naming_the_knowns():
    mixin = SocialEngMixin()
    with pytest.raises(ValueError) as err:
        mixin.plan_phishing_simulation(_consent(), "lab-cohort-a",
                                       channel="pigeon")
    assert "known: email, sms, voice" in str(err.value)
    with pytest.raises(ValueError) as err:
        mixin.plan_impersonation_exercise(_consent(), "lab-cohort-a",
                                          scenario="wizard")
    assert "known: executive, helpdesk, vendor" in str(err.value)
    with pytest.raises(ValueError) as err:
        mixin.soc_watch_pairing("watercooler")
    assert "known: impersonation, phishing" in str(err.value)
    with pytest.raises(ValueError) as err:
        mixin.channel_measurement("pigeon")
    assert "known: email, sms, voice" in str(err.value)


@pytest.mark.parametrize("label", [
    "", "lab; calc", "a b", "..", "cohort|whoami", "`id`", "x\ny",
    "x" * 90,
])
def test_scrub_rejects_hostile_labels(label):
    with pytest.raises(ValueError):
        SocialEngMixin().plan_phishing_simulation(_consent(), label)
    with pytest.raises(ValueError):
        SocialEngMixin().plan_impersonation_exercise(_consent(), label)


class _RefusingGate(SocialEngMixin):
    """A stand-in chassis whose validate_target refuses the label."""

    def validate_target(self, target):      # the chassis (ok, msg) form
        return (False, "only lab cohorts are valid")


class _PassingGate(SocialEngMixin):
    """A stand-in chassis whose validate_target accepts."""

    def validate_target(self, target):
        return (True, "ok")


def test_host_gate_consulted_and_silent_fallback():
    with pytest.raises(ValueError) as err:
        _RefusingGate().plan_phishing_simulation(_consent(),
                                                 "lab-cohort-a")
    assert "host agent gate" in str(err.value)
    assert "only lab cohorts are valid" in str(err.value)
    plan = _PassingGate().plan_impersonation_exercise(_consent(),
                                                      "lab-cohort-a")
    assert plan["exercise"] == "impersonation"
    # the bare mixin (no validate_target attribute) falls back silently
    assert SocialEngMixin().plan_phishing_simulation(
        _consent(), "lab-cohort-a")["channel"] == "email"


def test_soc_watch_pairing_rows():
    mixin = SocialEngMixin()
    for exercise in ("phishing", "impersonation"):
        pairing = mixin.soc_watch_pairing(exercise)
        assert pairing["exercise"] == exercise
        assert len(pairing["pairings"]) == 3
        for row in pairing["pairings"]:
            assert set(row) == {"watch", "note"} and row["note"]
    overview = mixin.soc_watch_pairing()
    assert overview["exercises"] == ["impersonation", "phishing"]
    assert overview["policy"] == BASELINE_POLICY


def test_channel_measurement_rows():
    mixin = SocialEngMixin()
    email = mixin.channel_measurement("email")
    assert email["channel"] == "email"
    assert {row["metric"] for row in email["metrics"]} == {
        "click-rate", "report-rate"}
    for row in email["metrics"]:
        assert set(row) == {"metric", "definition", "source"}
    assert {row["metric"] for row in
            mixin.channel_measurement("voice")["metrics"]} == {
        "callback-rate", "verify-rate"}
    assert {row["metric"] for row in
            mixin.channel_measurement("sms")["metrics"]} == {
        "reply-rate"}
    overview = mixin.channel_measurement()
    assert overview["channels"] == ["email", "sms", "voice"]
    assert overview["policy"] == BASELINE_POLICY


def test_index_and_policy_rows():
    mixin = SocialEngMixin()
    index = mixin.socialeng_index()
    assert index["exercises"] == ["impersonation", "phishing"]
    assert index["channels"] == ["email", "sms", "voice"]
    assert index["scenarios"] == ["executive", "helpdesk", "vendor"]
    assert index["policy"] == BASELINE_POLICY
    rows = mixin.socialeng_policy()
    assert rows == BASELINE_POLICY
    rows["lab_only"] = False           # copies, not the live constant
    assert mixin.socialeng_policy()["lab_only"] is True


def test_no_payload_content_in_outputs():
    mixin = SocialEngMixin()
    blobs = []
    blobs.append(str(mixin.plan_phishing_simulation(_consent(),
                                                    "lab-cohort-a")))
    blobs.append(str(mixin.plan_impersonation_exercise(_consent(),
                                                       "lab-cohort-a")))
    blobs.append(str(mixin.soc_watch_pairing("impersonation")))
    blobs.append(str(mixin.channel_measurement("voice")))
    joined = " ".join(blobs)
    for banned in ("href=", "<script", "data:text", "base64",
                   "os.system"):
        assert banned not in joined, banned


def test_module_never_executes():
    import agentic_ai.agents.cyber.socialeng_ops as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "os.system", "eval(",
                   "urllib", "requests", "socket"):
        assert banned not in source, banned