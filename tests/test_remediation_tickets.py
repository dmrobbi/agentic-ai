"""KA-070 tests - remediation-ticket bridge: the SOC store line contract
(exact key set, 12-hex ids, UTC +00:00 stamps, running/done lifecycle,
non-blank done outcomes), the latest-line-wins state replay, the
append-only structural findings (duplicate open appends, appends after
close), the targeting precedence (host rule over control rule, hosts and
controls never mixed into one target string), the owner-exception close
discipline (verbatim directive, partial resolution refused), the
booking-slip append-only repair, the refusal matrix for hostile
verification inputs, and the planner purity source-scan. No network;
store snapshots are mocked contract shapes (the [none] environment)."""
from __future__ import annotations

import importlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentic_ai.agents.cyber.remediation_tickets import (
    DEFAULT_KIND,
    KINDS,
    LINE_KEYS,
    ORIGIN_TAG,
    STATUS_DONE,
    STATUS_RUNNING,
    close_ticket_line,
    consult_target_validator,
    iso_utc,
    new_ticket_id,
    open_ticket_line,
    plan_slip_recovery,
    plan_tickets,
    scrub_target,
    scrub_text,
    ticket_state,
    validate_line,
    validate_store,
)

UTC = timezone.utc
NOW = datetime(2026, 10, 6, 21, 0, 0, tzinfo=UTC)
LATER = NOW + timedelta(hours=1)
ISO_NOW = "2026-10-06T21:00:00+00:00"
ISO_LATER = "2026-10-06T22:00:00+00:00"


class SeqIds:
    """Deterministic 12-hex id factory: the wiring's uuid4 stand-in."""

    def __init__(self, start: int = 0) -> None:
        self._n = start

    def __call__(self) -> str:
        self._n += 1
        return "%012x" % self._n


def tid(number: int) -> str:
    return "%012x" % number


def vresult(vid="V-1", host="lab-host-1", control_id=None, **kw):
    """One lab-verification result (the bridge's failure input)."""
    row = {"verification_id": vid, "host": host}
    if control_id is not None:
        row["control_id"] = control_id
    row.update(kw)
    return row


def open_line(target, number, *, kind=DEFAULT_KIND, details=None,
              ts=ISO_NOW, _id=None):
    """A minimal OPEN store line (mocked contract shape)."""
    return {
        "id": _id or tid(number),
        "ts": ts,
        "kind": kind,
        "target": target,
        "status": STATUS_RUNNING,
        "ended": None,
        "details": details or {},
    }


def done_line(target, number, *, details=None, ts=ISO_LATER):
    base = open_line(target, number, details=details or {"outcome": "ok"})
    base["status"] = STATUS_DONE
    base["ended"] = ts
    base["ts"] = ts
    return base


# --- the injected clock: UTC +00:00 stamps --------------------------------


def test_iso_utc_formats_an_aware_datetime():
    assert iso_utc(NOW) == ISO_NOW


def test_iso_utc_echoes_a_preformatted_store_string():
    assert iso_utc(ISO_NOW) == ISO_NOW


def test_iso_utc_keeps_microsecond_precision():
    stamped = iso_utc(datetime(2026, 10, 6, 21, 0, 0, 123456, tzinfo=UTC))
    assert stamped.endswith(".123456+00:00")


@pytest.mark.parametrize("bad_now", [
    NOW.replace(tzinfo=None),                      # naive datetime
    NOW.astimezone(timezone(timedelta(hours=2))),  # non-UTC aware
    None,
    42,
    ["now"],
    "2026-10-06T21:00:00Z",                        # Z suffix is not ours
    "2026-10-06T21:00:00",                         # naive string
    "garbage+00:00",                               # suffix game
])
def test_iso_utc_refuses_non_conforming_clocks(bad_now):
    with pytest.raises(ValueError):
        iso_utc(bad_now)


# --- the shared input gates ------------------------------------------------


def test_scrub_target_accepts_hosts_and_control_ids():
    assert scrub_target("lab-host-1") == "lab-host-1"
    assert scrub_target("SV-230338r879587") == "SV-230338r879587"
    assert scrub_target("  WN10-CC-000065 ") == "WN10-CC-000065"
    assert scrub_target("10.10.10.5") == "10.10.10.5"


@pytest.mark.parametrize("hostile", [
    "", "   ", "\t\n", None, 42, [],
    "", "a b", "a\nb", "host; rm", "host|pipe", "a&b", "$VAR", "`cmd`",
    "(a)", "<script>", 'a"b', "a'b", "a\\b", "..", "...", "-" * 4,
    "x" * 129,
])
def test_scrub_target_rejects_hostile_strings(hostile):
    with pytest.raises(ValueError):
        scrub_target(hostile)


def test_scrub_text_none_passthrough_and_clean_passthrough():
    assert scrub_text(None) is None
    assert scrub_text("already clean") == "already clean"


def test_scrub_text_control_chars_become_spaces():
    assert scrub_text("\x00dirty\x1f") == "dirty"
    assert scrub_text("line1\r\nline2") == "line1  line2"
    assert scrub_text("keep\x7fme") == "keep me"
    assert scrub_text("  padded  ") == "padded"


@pytest.mark.parametrize("garbage", [42, [], {}, object()])
def test_scrub_text_refuses_non_strings(garbage):
    with pytest.raises(ValueError):
        scrub_text(garbage)


def test_new_ticket_id_is_the_store_uuid4_discipline():
    first, second = new_ticket_id(), new_ticket_id()
    for value in (first, second):
        assert len(value) == 12
        int(value, 16)  # lowercase hex
    assert first != second


# --- the validate_target consult --------------------------------------------


class DuckValidator:
    """Agent-chassis duck: exposes validate_target as an attribute."""

    def __init__(self):
        self.targets = []

    def validate_target(self, target):
        self.targets.append(target)


def test_consult_consults_a_duck_validator():
    duck = DuckValidator()
    consult_target_validator(duck, "lab-1")
    assert duck.targets == ["lab-1"]


def test_consult_consults_a_bare_callable():
    seen = []
    consult_target_validator(seen.append, "lab-2")
    assert seen == ["lab-2"]


def test_consult_absent_validator_is_the_silent_fallback():
    seen = []
    consult_target_validator(None, "lab-3")   # None: no consult, no crash
    consult_target_validator(42, "lab-4")     # garbage: silent fallback
    assert seen == []


def test_consult_lets_the_validator_refuse():
    def refuses(target):
        raise ValueError("not a lab target: %s" % target)
    with pytest.raises(ValueError) as caught:
        consult_target_validator(refuses, "prod-1")
    assert "prod-1" in str(caught.value)


# --- single-line contract ---------------------------------------------------


def test_module_open_line_passes_its_own_contract():
    line = open_ticket_line("lab-1", {"origin": ORIGIN_TAG},
                            id=tid(7), now=NOW)
    validate_line(line)  # no raise = valid


MALFORMED = [
    ("not-a-dict", "not a dict", lambda l: l),
    ("missing-id", None, lambda l: l.pop("id")),
    ("missing-ts", None, lambda l: l.pop("ts")),
    ("missing-kind", None, lambda l: l.pop("kind")),
    ("missing-target", None, lambda l: l.pop("target")),
    ("missing-status", None, lambda l: l.pop("status")),
    ("missing-ended", None, lambda l: l.pop("ended")),
    ("missing-details", None, lambda l: l.pop("details")),
    ("extra-key", None, lambda l: l.update({"extra": 1})),
    ("id-short", "12 lowercase hex", lambda l: l.update({"id": "abc"})),
    ("id-uppercase", "12 lowercase hex", lambda l: l.update({"id": "A" * 12})),
    ("id-nonhex", "12 lowercase hex", lambda l: l.update({"id": "z" * 12})),
    ("ts-none", "ts:", lambda l: l.update({"ts": None})),
    ("ts-naive-string", "ts:", lambda l: l.update({"ts": "2026-10-06"})),
    ("ts-z-suffix", "ts:", lambda l: l.update({"ts": "xTz"})),
    ("ts-garbage", "ts:", lambda l: l.update({"ts": 42})),
    ("kind-unknown", "stig_remediate|stig_scan",
     lambda l: l.update({"kind": "ticket"})),
    ("target-hostile", "target:", lambda l: l.update({"target": "a b"})),
    ("details-not-dict", "details must be a dict",
     lambda l: l.update({"details": "no"})),
]
DONE_MALFORMED = [
    ("done-ended-null", None,
     lambda l: l.update({"ended": None})),
    ("done-ended-naive", "ended:",
     lambda l: l.update({"ended": "soon"})),
    ("done-no-outcome", "outcome", lambda l: l["details"].pop("outcome")),
    ("done-blank-outcome", "outcome",
     lambda l: l["details"].update({"outcome": "   "})),
]


@pytest.mark.parametrize("label,fragment,mutate", MALFORMED,
                         ids=[m[0] for m in MALFORMED])
def test_open_line_malformed_variants_refused(label, fragment, mutate):
    if label == "not-a-dict":
        line = "not a dict"  # non-dict input hits the same ValueError
    else:
        line = open_line("lab-1", 1)
        mutate(line)
    with pytest.raises(ValueError) as caught:
        validate_line(line)
    if fragment is not None:
        assert fragment in str(caught.value)


@pytest.mark.parametrize("label,fragment,mutate", DONE_MALFORMED,
                         ids=[m[0] for m in DONE_MALFORMED])
def test_done_line_malformed_variants_refused(label, fragment, mutate):
    line = done_line("lab-1", 1)
    mutate(line)
    with pytest.raises(ValueError) as caught:
        validate_line(line)
    if fragment is not None:
        assert fragment in str(caught.value)


def test_running_line_must_carry_ended_null():
    line = open_line("lab-1", 1)
    line["ended"] = "tomorrow"
    with pytest.raises(ValueError):
        validate_line(line)


# --- append-only structural findings ----------------------------------------


def test_validate_store_clean_snapshot():
    assert validate_store([]) == []
    store = [open_line("lab-1", 1),
             done_line("lab-1", 1)]
    assert validate_store(store) == []


def test_validate_store_non_list_refused():
    with pytest.raises(ValueError):
        validate_store("tasks.jsonl")  # raw file text is not a snapshot


def test_validate_store_reports_malformed_line_with_index():
    line = open_line("lab-1", 1)
    line["id"] = "nope"
    findings = validate_store([line, line])
    assert findings and findings[0].startswith("line 1:")
    assert "ticket id" in findings[0]


def test_validate_store_flags_duplicate_open_append():
    findings = validate_store([
        open_line("lab-1", 1),
        dict(open_line("lab-1", 2), id=tid(1)),  # the booking-slip shape
    ])
    assert len(findings) == 1
    assert "duplicate open append" in findings[0]
    assert "line 1" in findings[0]


def test_validate_store_flags_append_after_close():
    for later in (open_line("lab-1", 1, ts="2026-10-06T23:30:00+00:00"),
                  done_line("lab-1", 1,
                            ts="2026-10-06T23:30:00+00:00")):
        findings = validate_store([
            open_line("lab-1", 1),
            done_line("lab-1", 1),
            dict(later, id=tid(1)),
        ])
        assert any("append after close" in f for f in findings)


def test_validate_store_two_ids_clean_even_with_target_overlap():
    store = [open_line("lab-1", 1),
             open_line("CTL-9", 2)]
    assert validate_store(store) == []


# --- state replay: latest line wins -----------------------------------------


def test_ticket_state_latest_line_wins_not_any_running_exists():
    state = ticket_state([open_line("lab-1", 1),
                          done_line("lab-1", 1)])
    assert state["open"] == {}
    assert set(state["closed"]) == {tid(1)}
    assert state["closed"][tid(1)]["status"] == STATUS_DONE


def test_ticket_state_a_done_line_backs_an_earlier_running():
    state = ticket_state([done_line("lab-1", 1),
                          open_line("lab-1", 1,
                                    ts="2026-10-07T08:00:00+00:00")])
    assert set(state["open"]) == {tid(1)}
    assert state["open"][tid(1)]["ts"] == "2026-10-07T08:00:00+00:00"


def test_ticket_state_multi_id_counts_and_target_map():
    store = [open_line("lab-1", 1),
             done_line("CTL-9", 2),
             open_line("lab-2", 3)]
    state = ticket_state(store)
    assert set(state["open"]) == {tid(1), tid(3)}
    assert set(state["closed"]) == {tid(2)}
    assert state["summary"] == {"ids": 3, "open": 2, "closed": 1}
    assert state["open_targets"] == {"lab-1": tid(1), "lab-2": tid(3)}


def test_ticket_state_is_strict_about_lines():
    line = open_line("lab-1", 1)
    line["status"] = "open"
    with pytest.raises(ValueError) as caught:
        ticket_state([open_line("lab-1", 2), line])
    assert "line 2" in str(caught.value)


# --- building an open line ---------------------------------------------------


def test_open_ticket_line_exact_shape():
    line = open_ticket_line("  lab-1 ", {"origin": ORIGIN_TAG},
                            id=tid(9), now=NOW)
    assert set(line) == set(LINE_KEYS)
    assert line == {
        "id": tid(9),
        "ts": ISO_NOW,
        "kind": DEFAULT_KIND,
        "target": "lab-1",
        "status": STATUS_RUNNING,
        "ended": None,
        "details": {"origin": ORIGIN_TAG},
    }


def test_open_ticket_line_details_are_copied():
    details = {"origin": ORIGIN_TAG}
    line = open_ticket_line("lab-1", details, id=tid(1), now=NOW)
    details["tampered"] = True
    assert "tampered" not in line["details"]


def test_open_ticket_line_consults_the_duck_validator_on_scrubbed_target():
    duck = DuckValidator()
    open_ticket_line("  lab-1 ", {}, id=tid(1), now=NOW,
                     target_validator=duck)
    assert duck.targets == ["lab-1"]


def test_open_ticket_line_consults_a_bare_callable_validator():
    seen = []
    open_ticket_line("lab-1", {}, id=tid(1), now=NOW,
                     target_validator=seen.append)
    assert seen == ["lab-1"]


def test_open_ticket_line_absent_validator_never_consults():
    duck = DuckValidator()
    open_ticket_line("lab-1", {}, id=tid(1), now=NOW, target_validator=None)
    assert duck.targets == []


def test_open_ticket_line_validator_refusal_propagates():
    def refuses(target):
        raise ValueError("outside the lab range: %s" % target)
    with pytest.raises(ValueError) as caught:
        open_ticket_line("prod-1", {}, id=tid(1), now=NOW,
                         target_validator=refuses)
    assert "prod-1" in str(caught.value)


def test_open_ticket_line_guards_the_basics():
    with pytest.raises(ValueError):
        open_ticket_line("a b", {}, id=tid(1), now=NOW)  # hostile target
    with pytest.raises(ValueError):
        open_ticket_line("lab-1", {}, id="SHORT", now=NOW)  # id discipline
    with pytest.raises(ValueError):
        open_ticket_line("lab-1", {}, id=tid(1),
                         now=NOW, kind="ticket")  # unknown kind
    with pytest.raises(ValueError):
        open_ticket_line("lab-1", {}, id=tid(1), now="yesterday")
    with pytest.raises(ValueError):
        open_ticket_line("lab-1", {}, id=tid(1), now=NOW.replace(tzinfo=None))


# --- closing: decisions, exceptions, partial resolution ----------------------


def _host_ticket():
    return open_ticket_line("lab-a", {
        "origin": ORIGIN_TAG,
        "host": "lab-a",
        "controls": [
            {"control": "CTL-1", "verification_id": "V-1",
             "evidence_path": "lab:/tmp/v1.txt"},
            {"control": "CTL-2", "verification_id": "V-2"},
        ],
        "verifications": [],
    }, id=tid(1), now=NOW)


def test_close_host_ticket_exact_shape():
    done = close_ticket_line(
        _host_ticket(),
        decisions={"CTL-1": "fixed", "CTL-2": "fixed"},
        outcome="both controls remediated and re-verified",
        now=LATER)
    assert set(done) == set(LINE_KEYS)
    assert done["id"] == tid(1)
    assert done["target"] == "lab-a"
    assert done["kind"] == DEFAULT_KIND
    assert done["status"] == STATUS_DONE
    assert done["ts"] == ISO_LATER and done["ended"] == ISO_LATER
    assert done["details"] == {
        "outcome": "both controls remediated and re-verified",
        "decisions": {"CTL-1": "fixed", "CTL-2": "fixed"},
    }
    validate_line(done)


def test_close_happens_at_a_later_injected_clock():
    opened = _host_ticket()
    done = close_ticket_line(opened, decisions={"CTL-1": "fixed",
                                                "CTL-2": "fixed"},
                             outcome="clean", now=LATER)
    assert done["ts"] == ISO_LATER
    assert opened["ts"] == ISO_NOW  # the open line is untouched


def test_close_refuses_partial_resolution():
    with pytest.raises(ValueError) as caught:
        close_ticket_line(_host_ticket(), decisions={"CTL-1": "fixed"},
                          outcome="one of two", now=LATER)
    assert "partial resolution" in str(caught.value)
    assert "CTL-2" in str(caught.value)


def test_close_refuses_decisions_for_units_not_on_the_ticket():
    with pytest.raises(ValueError) as caught:
        close_ticket_line(_host_ticket(),
                          decisions={"CTL-1": "fixed", "CTL-2": "fixed",
                                     "CTL-99": "fixed"},
                          outcome="x", now=LATER)
    assert "CTL-99" in str(caught.value)


def test_close_refuses_unknown_decision_values():
    with pytest.raises(ValueError) as caught:
        close_ticket_line(_host_ticket(),
                          decisions={"CTL-1": "waved", "CTL-2": "fixed"},
                          outcome="x", now=LATER)
    assert "waved" in str(caught.value)


def test_owner_exception_requires_the_verbatim_directive():
    with pytest.raises(ValueError) as caught:
        close_ticket_line(_host_ticket(),
                          decisions={"CTL-1": "excepted",
                                     "CTL-2": "fixed"},
                          outcome="exception accepted", now=LATER)
    assert "owner's directive" in str(caught.value)


def test_exception_close_carries_the_directive_verbatim():
    done = close_ticket_line(_host_ticket(),
                             decisions={"CTL-1": "excepted",
                                        "CTL-2": "fixed"},
                             outcome="CTL-1 accepted as an exception",
                             now=LATER,
                             owner_directive="\"keep the banner, "
                                             "documented.\"\n- owner")
    details = done["details"]
    assert details["decisions"] == {"CTL-1": "excepted", "CTL-2": "fixed"}
    assert details["owner_directive"] == \
        '"keep the banner, documented." - owner'
    assert "\n" not in details["owner_directive"]


def test_all_fixed_close_needs_no_directive_and_cleans_paths():
    done = close_ticket_line(
        _host_ticket(), decisions={"CTL-1": "fixed", "CTL-2": "fixed"},
        outcome="fixed", now=LATER, owner_directive=None,
        evidence_paths=["lab:/tmp/x.txt", "lab:/tmp/y.txt"])
    assert "owner_directive" not in done["details"]
    assert done["details"]["evidence_paths"] == ["lab:/tmp/x.txt",
                                                 "lab:/tmp/y.txt"]
    assert done["details"]["decisions"] == {"CTL-1": "fixed",
                                            "CTL-2": "fixed"}


def test_close_validates_evidence_paths_and_outcome():
    with pytest.raises(ValueError):
        close_ticket_line(_host_ticket(),
                          decisions={"CTL-1": "fixed", "CTL-2": "fixed"},
                          outcome="x", now=LATER,
                          evidence_paths=["not a path!"])
    with pytest.raises(ValueError):
        close_ticket_line(_host_ticket(),
                          decisions={"CTL-1": "fixed", "CTL-2": "fixed"},
                          outcome="x", now=LATER, evidence_paths=42)
    with pytest.raises(ValueError):
        close_ticket_line(_host_ticket(),
                          decisions={"CTL-1": "fixed", "CTL-2": "fixed"},
                          outcome="", now=LATER)


def test_close_only_open_tickets():
    done = done_line("lab-1", 1)
    with pytest.raises(ValueError) as caught:
        close_ticket_line(done, decisions={}, outcome="again",
                          now=LATER)
    assert "already done" in str(caught.value)


def test_close_control_ticket_decides_the_control():
    control_ticket = open_ticket_line("CTL-2", {
        "origin": ORIGIN_TAG, "control": "CTL-2",
        "hosts": [{"host": "lab-b", "verification_id": "V-3"}],
    }, id=tid(5), now=NOW)
    done = close_ticket_line(control_ticket, decisions={"CTL-2": "fixed"},
                             outcome="patched every enrolled host",
                             now=LATER)
    assert done["details"]["decisions"] == {"CTL-2": "fixed"}


def test_close_foreign_line_decides_its_target():
    legacy = open_line("SV-230338r879587", 11,
                       details={"scan summary": "banner mismatch"})
    done = close_ticket_line(legacy, decisions={
        "SV-230338r879587": "excepted"}, outcome="accepted", now=LATER,
        owner_directive="owner ok")
    assert done["details"]["decisions"] == {
        "SV-230338r879587": "excepted"}


def test_close_refuses_malformed_control_entries():
    broken = open_ticket_line("lab-a", {
        "origin": ORIGIN_TAG, "host": "lab-a", "controls": ["CTL-1"],
        "verifications": [],
    }, id=tid(2), now=NOW)
    with pytest.raises(ValueError) as caught:
        close_ticket_line(broken, decisions={}, outcome="x", now=LATER)
    assert "malformed control entry" in str(caught.value)


# --- the bridge core: plan_tickets ------------------------------------------


def test_plan_tickets_shape_pins():
    result = plan_tickets([], now=NOW, id_factory=SeqIds())
    assert set(result) == {"lines", "refused", "skipped", "notes", "summary"}
    assert result["summary"] == {"verifications": 0, "plannable": 0,
                                 "refused": 0, "skipped": 0, "lines": 0}
    assert result["lines"] == [] and result["refused"] == []
    assert result["skipped"] == []


def test_plan_tickets_single_control_host_ticket_precedence():
    result = plan_tickets([
        vresult("V-1", "lab-a", "CTL-1", severity="critical"),
        vresult("V-2", "lab-a", "CTL-2"),
        vresult("V-3", "lab-a", "CTL-3"),
    ], now=NOW, id_factory=SeqIds())
    assert len(result["lines"]) == 1
    line = result["lines"][0]
    assert line["target"] == "lab-a"
    assert set(line["details"]) == {"origin", "host", "controls",
                                    "verifications"}
    assert line["details"]["origin"] == ORIGIN_TAG
    assert [c["control"] for c in line["details"]["controls"]] == [
        "CTL-1", "CTL-2", "CTL-3"]  # input order
    assert line["details"]["controls"][0] == {
        "control": "CTL-1", "verification_id": "V-1",
        "severity": "critical"}
    assert line["details"]["verifications"] == []
    assert result["summary"]["lines"] == 1


def test_plan_tickets_control_rule_when_control_spans_hosts():
    result = plan_tickets([
        vresult("V-1", "lab-a", "CTL-1"),
        vresult("V-2", "lab-b", "CTL-1"),
        vresult("V-3", "lab-c", "CTL-1"),
    ], now=NOW, id_factory=SeqIds())
    assert len(result["lines"]) == 1
    line = result["lines"][0]
    assert line["target"] == "CTL-1"  # the original convention
    assert set(line["details"]) == {"origin", "control", "hosts"}
    assert [h["host"] for h in line["details"]["hosts"]] == [
        "lab-a", "lab-b", "lab-c"]


def test_plan_tickets_host_rule_precedence_splits_a_spread_control():
    result = plan_tickets([
        vresult("V-1", "lab-a", "CTL-1"),
        vresult("V-2", "lab-a", "CTL-2"),
        vresult("V-3", "lab-b", "CTL-2"),
    ], now=NOW, id_factory=SeqIds())
    assert len(result["lines"]) == 2
    host_ticket = result["lines"][0]
    control_ticket = result["lines"][1]
    assert host_ticket["target"] == "lab-a"
    assert [c["control"] for c in host_ticket["details"]["controls"]] == [
        "CTL-1", "CTL-2"]
    assert control_ticket["target"] == "CTL-2"
    assert [h["host"] for h in control_ticket["details"]["hosts"]] == [
        "lab-b"]  # lab-a's CTL-2 rides the lab-a host ticket
    assert any("host rule" in n for n in result["notes"])


def test_plan_tickets_isolated_failure_defaults_to_control_target():
    result = plan_tickets([vresult("V-1", "lab-a", "CTL-1")],
                          now=NOW, id_factory=SeqIds())
    assert len(result["lines"]) == 1
    assert result["lines"][0]["target"] == "CTL-1"
    assert not any("host rule" in n for n in result["notes"])


def test_plan_tickets_controlless_verification_is_host_targeted():
    result = plan_tickets([vresult("V-9", "lab-a", severity="low")],
                          now=NOW, id_factory=SeqIds())
    line = result["lines"][0]
    assert len(result["lines"]) == 1
    assert line["target"] == "lab-a"
    assert set(line["details"]) == {"origin", "host", "controls",
                                    "verifications"}
    assert line["details"]["verifications"][0] == {
        "verification_id": "V-9", "severity": "low"}


def test_plan_tickets_controlless_rides_a_multi_control_host_ticket():
    result = plan_tickets([
        vresult("V-1", "lab-a", "CTL-1"),
        vresult("V-2", "lab-a", "CTL-2"),
        vresult("V-3", "lab-a"),
    ], now=NOW, id_factory=SeqIds())
    assert len(result["lines"]) == 1  # one ticket per grouped host
    line = result["lines"][0]
    assert [c["control"] for c in line["details"]["controls"]] == [
        "CTL-1", "CTL-2"]
    assert [v["verification_id"]
            for v in line["details"]["verifications"]] == ["V-3"]


def test_plan_tickets_optional_fields_pack_into_units():
    result = plan_tickets([vresult(
        "V-1", "lab-a", "CTL-1", severity="HIGH",
        summary="stale issue banner", evidence_path="gus2:~/v/out.txt",
        finding_ref="AF-101", fix="grub hardening", exception="none")],
        now=NOW, id_factory=SeqIds())
    unit = result["lines"][0]["details"]["hosts"][0]
    assert unit["verification_id"] == "V-1"
    assert unit["host"] == "lab-a"
    assert unit["severity"] == "high"  # case-insensitive normalization
    assert unit["evidence_path"] == "gus2:~/v/out.txt"
    assert unit["finding_ref"] == "AF-101"


def test_plan_tickets_abSENT_fields_are_omitted_not_none():
    result = plan_tickets([vresult("V-1", "lab-a", "CTL-1")],
                          now=NOW, id_factory=SeqIds())
    unit = result["lines"][0]["details"]["hosts"][0]
    assert unit["verification_id"] == "V-1"
    assert unit["host"] == "lab-a"
    assert set(unit) == {"verification_id", "host"}


def test_plan_tickets_store_skip_target_already_open():
    store = [open_line("lab-a", 42)]
    result = plan_tickets([
        vresult("V-1", "lab-a", "CTL-1"),
        vresult("V-2", "lab-a", "CTL-2"),   # host rule -> lab-a ticket
        vresult("V-3", "lab-b", "CTL-1"),   # control rule -> CTL-1 ticket
    ], now=NOW, id_factory=SeqIds(), store_lines=store)
    assert result["skipped"] == [{
        "target": "lab-a",
        "ticket_id": tid(42),
        "reason": "already open as %s" % tid(42),
    }]
    assert len(result["lines"]) == 1
    assert result["lines"][0]["target"] == "CTL-1"
    assert result["lines"][0]["id"] == tid(1)  # skip drew no factory id


def test_plan_tickets_without_store_snapshot_notes_the_skipped_check():
    result = plan_tickets([vresult("V-1", "lab-a", "CTL-1")],
                          now=NOW, id_factory=SeqIds())
    assert any("duplicate-target check" in n for n in result["notes"])


def test_plan_tickets_with_store_snapshot_drops_the_skip_note():
    result = plan_tickets([vresult("V-1", "lab-a", "CTL-1")],
                          now=NOW, id_factory=SeqIds(), store_lines=[])
    assert not any("duplicate-target check" in n for n in result["notes"])


def test_plan_tickets_id_collision_is_the_loud_wiring_failure():
    store = [open_line("lab-x", 1)]  # id tid(1) exists (closed or open)
    with pytest.raises(ValueError) as caught:
        plan_tickets([vresult("V-1", "lab-a", "CTL-1")], now=NOW,
                     id_factory=SeqIds(), store_lines=store)
    assert "never re-append" in str(caught.value)


def test_plan_tickets_garbage_factory_ids_abort_the_plan():
    with pytest.raises(ValueError):
        plan_tickets([vresult("V-1", "lab-a", "CTL-1")], now=NOW,
                     id_factory=lambda: "not-hex-12")


def test_plan_tickets_is_deterministic():
    failures = [
        vresult("V-1", "lab-a", "CTL-1", summary="one"),
        vresult("V-2", "lab-a", "CTL-2"),
        vresult("V-3", "lab-b", "CTL-2"),
        vresult("V-4", "lab-c"),
    ]
    first = plan_tickets(failures, now=NOW, id_factory=SeqIds())
    second = plan_tickets(failures, now=NOW, id_factory=SeqIds())
    assert first == second


def test_plan_tickets_accepts_a_single_dict():
    result = plan_tickets(vresult("V-1", "lab-a", "CTL-1"),
                          now=NOW, id_factory=SeqIds())
    assert result["summary"]["verifications"] == 1


REFUSED_ROWS = [
    ("non-dict", "not-a-dict"),
    ("missing-vid", {"host": "lab-a", "control_id": "CTL-1"}),
    ("vid-hostile-chars", vresult("V;1", "lab-a", "CTL-1")),
    ("vid-too-long", {"verification_id": "V" * 65, "host": "lab-a"}),
    ("vid-empty", vresult("   ", "lab-a", "CTL-1")),
    ("host-missing", {"verification_id": "V-1"}),
    ("host-hostile", vresult("V-1", "a b", "CTL-1")),
    ("control-bad", vresult("V-1", "lab-a", "CTL;1")),
    ("control-empty", vresult("V-1", "lab-a", "")),
    ("severity-unknown", vresult("V-1", "lab-a", "CTL-1",
                                 severity="apocalyptic")),
    ("severity-type", vresult("V-1", "lab-a", "CTL-1", severity=42)),
    ("summary-type", vresult("V-1", "lab-a", "CTL-1", summary=42)),
    ("evidence-hostile", vresult("V-1", "lab-a", "CTL-1",
                                 evidence_path="has spaces")),
    ("evidence-type", vresult("V-1", "lab-a", "CTL-1",
                              evidence_path=[])),
    ("finding-ref-bad", vresult("V-1", "lab-a", "CTL-1",
                                finding_ref="AF;1")),
]


@pytest.mark.parametrize("label,row", REFUSED_ROWS,
                         ids=[r[0] for r in REFUSED_ROWS])
def test_plan_tickets_refuses_hostile_rows_without_crashing(label, row):
    if row == "not-a-dict":
        row = 42
    result = plan_tickets([
        row,
        vresult("OK-1", "lab-b", "CTL-2"),
    ], now=NOW, id_factory=SeqIds())
    assert result["summary"]["refused"] == 1
    assert result["summary"]["plannable"] == 1
    assert len(result["refused"]) == 1
    entry = result["refused"][0]
    assert set(entry) == {"verification_id", "reasons"}
    assert entry["reasons"], "a refusal carries its reasons"


def test_plan_tickets_non_dict_refusal_marks_missing_id():
    result = plan_tickets([42], now=NOW, id_factory=SeqIds())
    assert result["refused"] == [{
        "verification_id": "<missing-id>",
        "reasons": ["verification result not a dict"]}]


def test_plan_tickets_validator_refusal_lands_in_the_refused_bucket():
    def refuses(target):
        if target.startswith("prod"):
            raise ValueError("%s is outside the lab range" % target)
    result = plan_tickets([
        vresult("V-1", "prod-1", "CTL-1"),
        vresult("V-2", "lab-b", "CTL-1"),
    ], now=NOW, id_factory=SeqIds(), target_validator=refuses)
    assert result["summary"]["refused"] == 1
    assert result["refused"][0]["verification_id"] == "V-1"
    assert any("target validator" in r
               for r in result["refused"][0]["reasons"])
    assert len(result["lines"]) == 1
    assert result["lines"][0]["target"] == "CTL-1"


def test_plan_tickets_validator_consults_survivors_only():
    duck = DuckValidator()
    plan_tickets([
        vresult("V-1", "lab-a", "CTL-1", severity=42),  # refused earlier
        vresult("V-2", "lab-b", "CTL-1"),
    ], now=NOW, id_factory=SeqIds(), target_validator=duck)
    assert duck.targets == ["lab-b"]


def test_plan_tickets_duplicate_pair_first_occurrence_wins():
    result = plan_tickets([
        vresult("V-1", "lab-a", "CTL-1", summary="first"),
        vresult("V-2", "lab-a", "CTL-1", summary="second"),
    ], now=NOW, id_factory=SeqIds())
    assert result["summary"]["plannable"] == 1
    units = result["lines"][0]["details"]["hosts"]
    assert len(units) == 1 and units[0]["verification_id"] == "V-1"
    assert any("V-2" in n for n in result["notes"])


def test_plan_tickets_lines_are_valid_and_json_roundtrip_clean():
    result = plan_tickets([
        vresult("V-1", "lab-a", "CTL-1", summary="s\nwith a newline",
                evidence_path="gus2:~/v/out.txt"),
        vresult("V-2", "lab-a", "CTL-2"),
        vresult("V-3", "lab-b", "CTL-2"),
        vresult("V-4", "lab-c"),
    ], now=NOW, id_factory=SeqIds())
    for line in result["lines"]:
        validate_line(line)
        assert json.loads(json.dumps(line)) == line
        assert line["ts"] == ISO_NOW and line["ended"] is None


def test_plan_tickets_open_close_cycle_is_self_consistent():
    result = plan_tickets([
        vresult("V-1", "lab-a", "CTL-1", evidence_path="gus2:~/v/o.txt"),
        vresult("V-2", "lab-a", "CTL-2"),
    ], now=NOW, id_factory=SeqIds())
    open_ticket = result["lines"][0]
    controls = {c["control"] for c in open_ticket["details"]["controls"]}
    done = close_ticket_line(open_ticket,
                             decisions={c: "fix"
                                        and "fixed" for c in controls},
                             outcome="remediated", now=LATER)
    validate_store([open_ticket, done])  # appended after the open: clean


# --- booking-slip recovery ---------------------------------------------------


def _slip_store():
    """The real open ticket + the accidental stale re-append (the slip)."""
    return [
        open_line("lab-a", 1, details={
            "origin": ORIGIN_TAG, "host": "lab-a",
            "controls": [{"control": "CTL-1",
                          "verification_id": "V-1"}],
            "verifications": []}),
        open_line("lab-a", 2, _id=tid(2), ts=ISO_LATER, details={
            "origin": ORIGIN_TAG, "stale": "pastied payload"}),
    ]


def test_plan_slip_recovery_supersede_append_only():
    result = plan_slip_recovery(_slip_store(), slip_id=tid(2),
                                real_id=tid(1), now=LATER)
    assert set(result) == {"appends", "notes"}
    assert len(result["appends"]) == 1
    close = result["appends"][0]
    assert set(close) == set(LINE_KEYS)
    assert close["id"] == tid(2)
    assert close["status"] == STATUS_DONE
    assert close["ended"] == ISO_LATER
    assert close["target"] == "lab-a"
    assert close["kind"] == DEFAULT_KIND
    assert close["details"]["superseded_by"] == tid(1)
    assert close["details"]["outcome"].startswith(
        "superseded-duplicate:")
    assert tid(1) in close["details"]["outcome"]
    assert "lab-a" in close["details"]["outcome"]


def test_plan_slip_recovery_carries_the_intended_record():
    intended = open_ticket_line("lab-b", {"origin": ORIGIN_TAG},
                                id=tid(3), now=LATER)
    result = plan_slip_recovery(_slip_store(), slip_id=tid(2),
                                real_id=tid(1), now=LATER,
                                intended=intended)
    assert len(result["appends"]) == 2
    assert result["appends"][1] == intended


def test_plan_slip_recovery_repair_is_clean_against_the_contract():
    # the corrupted store + the planned appends validate clean
    result = plan_slip_recovery(_slip_store(), slip_id=tid(2),
                                real_id=tid(1), now=LATER)
    repaired = _slip_store() + result["appends"]
    assert validate_store(repaired) == []
    state = ticket_state(repaired)
    assert set(state["open"]) == {tid(1)}
    assert set(state["closed"]) == {tid(2)}


def test_plan_slip_recovery_refuses_the_nonsense_cases():
    store = _slip_store()
    with pytest.raises(ValueError):
        plan_slip_recovery(store, slip_id=tid(1), real_id=tid(1),
                           now=LATER)
    with pytest.raises(ValueError):
        plan_slip_recovery(store, slip_id=tid(9), real_id=tid(1),
                           now=LATER)  # unknown slip id
    with pytest.raises(ValueError):
        plan_slip_recovery(store, slip_id=tid(2), real_id=tid(9),
                           now=LATER)  # real ticket not open


def test_plan_slip_recovery_refuses_an_already_closed_slip():
    done = done_line("lab-a", 2)
    done["id"] = tid(2)
    store = [open_line("lab-a", 1), done]
    with pytest.raises(ValueError) as caught:
        plan_slip_recovery(store, slip_id=tid(2), real_id=tid(1),
                           now=LATER)
    assert "not an open ticket" in str(caught.value)


def test_plan_slip_recovery_intended_target_already_open_is_the_next_slip():
    store = _slip_store()
    intended = open_ticket_line("lab-a", {}, id=tid(3), now=LATER)
    with pytest.raises(ValueError) as caught:
        plan_slip_recovery(store, slip_id=tid(2), real_id=tid(1),
                           now=LATER, intended=intended)
    assert "next slip" in str(caught.value)


def test_plan_slip_recovery_intended_must_be_an_open_line():
    done = done_line("lab-b", 3)
    with pytest.raises(ValueError):
        plan_slip_recovery(_slip_store(), slip_id=tid(2), real_id=tid(1),
                           now=LATER, intended=done)


def test_plan_slip_recovery_strict_about_malformed_store_rows():
    line = open_line("lab-a", 1)
    line["id"] = "BAD"
    with pytest.raises(ValueError) as caught:
        plan_slip_recovery([line], slip_id=tid(1), real_id=tid(2),
                           now=LATER)
    assert "line 1" in str(caught.value)


# --- planner purity ----------------------------------------------------------


def test_module_purity_source_scan():
    module = importlib.import_module(
        "agentic_ai.agents.cyber.remediation_tickets")
    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("from agentic_ai", "import agentic_ai",
                   "subprocess", "popen", "os.system",
                   "eval(", "exec(",
                   "urllib", "socket", "requests", "http.client",
                   "utcnow", "time.time", "today(", "datetime.now",
                   "open(", "Path(", "shutil", "pathlib"):
        assert banned not in source, banned
    assert "uuid" in source  # the id helper is the only stdlib addition
