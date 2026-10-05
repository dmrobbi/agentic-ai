"""SocialEngMixin (KA-042): phishing/impersonation SIMULATION exercise
planners + SOC watch pairings (no execution; lab-only by policy).

Policy: consent_required: True - every simulation-planning op takes a
consent record and REFUSES (ValueError) without one; a bare flag is
not a record. The record is a dict with authorized_by, scope, expires
(an ISO date YYYY-MM-DD on the future side); expired records refuse
too. lab_only: True - the planners assume a lab exercise window only;
no real audiences, no production systems. no_payload_generation: True
- the ops output exercise STRUCTURE (audience, channel, timing,
measurement) only; never message or phishing payload texts.

Kinds: phishing (alias phish), impersonation (aliases pretext,
vishing). Channels: email (alias mail), sms (aliases text, message),
voice (aliases phone, call). Impersonation scenario classes:
helpdesk (aliases service-desk, servicedesk), vendor (alias supply),
executive (alias boss). Unknown values raise ValueError naming the
known ones.

Ops:
- socialeng_policy() - the policy rows
- socialeng_index() - the overview (kinds/channels/scenarios/policy)
- plan_phishing_simulation(consent, audience_label, channel) - the
  consent-gated 6-phase exercise arc
- plan_impersonation_exercise(consent, audience_label, scenario,
  channel) - the consent-gated arc for the impersonation classes
- soc_watch_pairing(exercise) - the SOC watch rows per exercise
- channel_measurement(channel) - the metric rows per channel

The consent fields are structurally validated and echoed verbatim in
the consent_summary - they are never interpolated into command
strings. The audience label is a compact slug: the shared scrubber
(wp_scrub_target) rejects metacharacters and whitespace, then the
host agent's validate_target gets consulted via getattr with a silent
fallback when the chassis is absent.
"""

from __future__ import annotations

import datetime
import re

from agentic_ai.agents.cyber.web_pentest import wp_scrub_target

POLICY = {"lab_only": True, "consent_required": True,
          "no_payload_generation": True}

CONSENT_KEYS = ("authorized_by", "scope", "expires")

EXERCISES = {"phishing": ("phishing", "phish"),
             "impersonation": ("impersonation", "pretext", "vishing")}

CHANNELS = {"email": ("email", "mail"),
            "sms": ("sms", "text", "message"),
            "voice": ("voice", "phone", "call")}

SCENARIOS = {"helpdesk": ("helpdesk", "service-desk", "servicedesk"),
             "vendor": ("vendor", "supply"),
             "executive": ("executive", "boss")}

PHISHING_PLAN = (
    ("1-consent", "Consent gate before anything else",
     ["The exercise runs only under a consent record on file; the op "
      "refused without one already.",
      "The record's rows anchor the audit trail for the lab window."],
     ["# record: authorized_by + scope + expires; store with the lab "
      "paperwork"]),

    ("2-audience", "Define the lab audience - names only, no content",
     ["The audience = a fixed list of lab inboxes/personas owned by "
      "the exercise lead.",
      "This planner generates NO message texts - structure only."],
     ["# audience: {audience_label}; lab-only roles + count recorded"]),

    ("3-channel-timing", "Channel plan + the timing windows",
     ["Two touches max per lab recipient, inside two consecutive lab "
      "days; no after-hours sends.",
      "Keep the volume small: the exercise measures behavior, not "
      "throughput."],
     ["# channel: <channel>; windows = lab days 09:00-11:00 + "
      "14:00-16:00"]),

    ("4-soc-watch", "The run window stays under SOC watch",
     ["The SOC watches the same lab window; the rows come from "
      "soc_watch_pairing().",
      "Anything real in the window pauses the exercise immediately."],
     ["# op: soc_watch_pairing('phishing')"]),

    ("5-measure", "Measure behavior, never touch anything real",
     ["The metric rows name metric + source only, from the lab "
      "telemetry exports.",
      "Rates = structure; the export stays on the lab machine."],
     ["# op: channel_measurement('<channel>')"]),

    ("6-debrief", "Debrief + the SOC-paired report",
     ["Per-segment results + the SOC pairings; redact every row "
      "before the report leaves the machine.",
      "The report carries the consent rows + the exercise window."],
     ["# report: consent rows + rates + SOC pairings; scrub before "
      "export"]),
)

IMPERSONATION_PLAN = (
    ("1-consent", "Consent gate before anything else",
     ["The exercise runs only under a consent record on file; the op "
      "refused without one already.",
      "The record's rows anchor the audit trail for the lab window."],
     ["# record: authorized_by + scope + expires; store with the lab "
      "paperwork"]),

    ("2-audience", "Define the lab audience - names only, no dialogs",
     ["The audience = lab personas briefed on the stop-word + the "
      "out-of-band verification path.",
      "This planner generates NO call scripts or pretext dialogues - "
      "structure only."],
     ["# audience: {audience_label}; lab-only personas + briefing "
      "recorded"]),

    ("3-scenario-class", "Impersonation scenario class - coarse only",
     ["The scenario stays a coarse class (helpdesk/vendor/executive); "
      "the planner writes no scripts.",
      "Each lab persona's compliance path is the out-of-band one the "
      "brief defined."],
     ["# scenario: <scenario> class; scripts stay out of the "
      "planner"]),

    ("4-soc-watch", "The run window stays under SOC watch",
     ["The SOC watches the same lab window; the rows come from "
      "soc_watch_pairing().",
      "A real report in the window = treat it as an incident first."],
     ["# op: soc_watch_pairing('impersonation')"]),

    ("5-measure", "Measure behavior, never touch anything real",
     ["The metric rows name metric + source only, from the lab "
      "logs.",
      "Rates = structure; the export stays on the lab machine."],
     ["# op: channel_measurement('<channel>')"]),

    ("6-debrief", "Debrief + the SOC-paired report",
     ["Per-segment results + the SOC pairings; redact every row "
      "before the report leaves the machine.",
      "The report carries the consent rows + the exercise window."],
     ["# report: consent rows + rates + SOC pairings; scrub before "
      "export"]),
)

SOC_WATCH = {
    "phishing": (
        ("watch-click-telemetry",
         "the mail-gateway click log = the row source; a mid-window "
         "spike = alert the exercise lead"),
        ("watch-report-burst",
         "the report-button queue = the row source; runs above the "
         "lab baseline = the exercise is landing"),
        ("watch-real-incident",
         "anything true-positive in the window = the exercise "
         "pauses; the SOC leads until the all-clear"),
    ),
    "impersonation": (
        ("watch-callback-log",
         "the lab call log = the row source; callbacks route to the "
         "bounced path the brief defined"),
        ("watch-badge-review",
         "the physical-review notes = the row source; every attempt "
         "is logged where it happened, never reproduced"),
        ("watch-real-incident",
         "a real report in the window = treat it as an incident "
         "first"),
    ),
}

MEASUREMENTS = {
    "email": (
        ("click-rate", "clicked vs sent",
         "the mail-gateway click telemetry export"),
        ("report-rate", "report-button use vs sent",
         "the SOC report queue"),
    ),
    "sms": (
        ("reply-rate", "replies vs sent", "the lab sms gateway log"),
    ),
    "voice": (
        ("callback-rate", "callbacks vs calls placed",
         "the lab call log"),
        ("verify-rate", "out-of-band verifications vs contacts",
         "the lab call log + the contact directory"),
    ),
}


def _canonical(table, value, what):
    """Canonical table key for a str/alias value; refuses unknowns."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("%s must be a non-empty string" % (what,))
    form = value.strip().lower()
    for canonical, aliases in table.items():
        if form in aliases:
            return canonical
    raise ValueError("unknown %s %r - known: %s"
                     % (what, value, ", ".join(sorted(table))))


def _consent_check(consent):
    """Validate the consent record; refuse without a structurally
    valid one. Returns the echoed consent_summary dict."""
    if not isinstance(consent, dict):
        raise ValueError("consent record required - pass a dict with "
                         "authorized_by, scope, expires; got %s"
                         % (type(consent).__name__,))
    missing = [key for key in CONSENT_KEYS if key not in consent]
    if missing:
        raise ValueError("consent record missing required fields: %s"
                         % ", ".join(missing))
    for key in ("authorized_by", "scope"):
        row = consent[key]
        if not isinstance(row, str) or not row.strip():
            raise ValueError("consent field %r must be a non-empty "
                             "string" % (key,))
    expires = consent["expires"]
    text = expires.strip() if isinstance(expires, str) else str(expires)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        raise ValueError("consent field 'expires' must be an ISO date "
                         "YYYY-MM-DD string")
    try:
        expiry = datetime.date.fromisoformat(text)
    except ValueError:
        raise ValueError("consent field 'expires' must be an ISO date "
                         "YYYY-MM-DD string") from None
    if expiry < datetime.date.today():
        raise ValueError("consent record expired on %s - refuse"
                         % (text,))
    return {"authorized_by": consent["authorized_by"].strip(),
            "scope": consent["scope"].strip(),
            "expires": text}


def _build_phases(plan, tokens):
    """Render the plan rows into phase dicts with the tokens inlined."""
    audience, exercise = tokens["audience_label"], tokens["exercise"]
    channel, scenario = (tokens["channel"],
                         tokens.get("scenario", ""))
    phases = []
    for pid, goal, acts, cmds in plan:
        rendered = [
            c.replace("{audience_label}", audience)
             .replace("<exercise>", exercise)
             .replace("<channel>", channel)
             .replace("<scenario>", scenario)
            for c in cmds]
        phases.append({"phase": pid, "goal": goal,
                       "activities": list(acts),
                       "sample_commands": rendered,
                       "policy": dict(POLICY)})
    return phases


class SocialEngMixin:
    """Social-engineering SIMULATION planning ops (no execution) - the
    consent gate is mandatory, the policy is lab-only, and the output
    stays exercise structure (never payloads)."""

    def socialeng_index(self) -> dict:
        """The overview: exercises, channels, scenarios + the policy."""
        return {"exercises": sorted(EXERCISES),
                "channels": sorted(CHANNELS),
                "scenarios": sorted(SCENARIOS),
                "policy": dict(POLICY)}

    def socialeng_policy(self) -> dict:
        """The lab-only policy rows (the consent gate included)."""
        return dict(POLICY)

    def _socialeng_guard(self, audience_label):
        """Scrub the audience slug, then consult the host agent's
        validate_target (silent fallback when the chassis is absent)."""
        label = wp_scrub_target(audience_label)
        if len(label) > 80:
            raise ValueError("audience_label too long (<= 80 chars)")
        gate = getattr(self, "validate_target", None)
        if callable(gate):
            ok, msg = gate(label)
            if not ok:
                raise ValueError(
                    "audience rejected by host agent gate: %s" % (msg,))
        return label

    def plan_phishing_simulation(self, consent, audience_label,
                                 channel=None):
        """The consent-gated phishing SIMULATION plan - exercise
        structure only; refuses without a consent record."""
        record = _consent_check(consent)
        label = self._socialeng_guard(audience_label)
        if channel is None:
            channel = "email"
        canonical_channel = _canonical(CHANNELS, channel, "channel")
        phases = _build_phases(
            PHISHING_PLAN,
            {"audience_label": label, "exercise": "phishing",
             "channel": canonical_channel})
        return {"exercise": "phishing", "audience_label": label,
                "channel": canonical_channel,
                "consent_summary": dict(record),
                "soc_watch": [{"watch": wid, "note": note}
                              for wid, note in SOC_WATCH["phishing"]],
                "policy": dict(POLICY), "phases": phases}

    def plan_impersonation_exercise(self, consent, audience_label,
                                    scenario=None, channel=None):
        """The consent-gated impersonation SIMULATION plan - coarse
        scenario classes only; refuses without a consent record."""
        record = _consent_check(consent)
        label = self._socialeng_guard(audience_label)
        if scenario is None:
            scenario = "helpdesk"
        if channel is None:
            channel = "voice"
        canonical_scenario = _canonical(SCENARIOS, scenario, "scenario")
        canonical_channel = _canonical(CHANNELS, channel, "channel")
        phases = _build_phases(
            IMPERSONATION_PLAN,
            {"audience_label": label, "exercise": "impersonation",
             "channel": canonical_channel,
             "scenario": canonical_scenario})
        return {"exercise": "impersonation", "audience_label": label,
                "scenario": canonical_scenario,
                "channel": canonical_channel,
                "consent_summary": dict(record),
                "soc_watch": [{"watch": wid, "note": note}
                              for wid, note in
                              SOC_WATCH["impersonation"]],
                "policy": dict(POLICY), "phases": phases}

    def soc_watch_pairing(self, exercise=None):
        """The SOC watch rows per exercise (None = the overview)."""
        if exercise is None:
            return {"exercises": sorted(EXERCISES),
                    "policy": dict(POLICY)}
        canonical = _canonical(EXERCISES, exercise, "exercise")
        return {"exercise": canonical,
                "pairings": [{"watch": wid, "note": note}
                             for wid, note in SOC_WATCH[canonical]]}

    def channel_measurement(self, channel=None):
        """The metric rows per channel (None = the overview)."""
        if channel is None:
            return {"channels": sorted(CHANNELS),
                    "policy": dict(POLICY)}
        canonical = _canonical(CHANNELS, channel, "channel")
        return {"channel": canonical,
                "metrics": [{"metric": m, "definition": d, "source": s}
                            for m, d, s in MEASUREMENTS[canonical]]}