"""KA-098 tests - plan explorer: the browse-only contract over injected
plans/ops (dict and duck-typed object sources), the normalized plan and
step-row shapes per the landed planners (web phases, redteam tool
phases, runsheets, string steps, explicit id/title/risk_tags), args =
top-level scalars, deduped capped ref URLs, clean not-found dicts (with
known ids / step names, capped), narrowed show() by 0-based index,
exact/case-insensitive step name (str-ints NOT parsed), related() cross
refs (shared targets/tools, insertion-ordered plans lists, cap 25),
search() rows and cap/truncated, the stable ASCII render tree (determin-
istic, no control characters, width/height caps with markers), collision
suffixed ids, "step-<n>" fallback names, risk-tag coercion, skip-route
counts for malformed plan entries, source non-mutation, and the planner
purity source scan (no run paths). No network, no I/O beyond reading
this repo's own module source for the scan."""

from __future__ import annotations

import copy
import importlib
import re
from pathlib import Path

import pytest

from agentic_ai.agents.cyber import plan_explorer
from agentic_ai.agents.cyber.plan_explorer import (
    CAP_ROWS,
    REASON_UNKNOWN_PLAN,
    REASON_UNKNOWN_STEP,
    TREE_MAX_HEIGHT,
    TREE_MAX_WIDTH,
    PlanExplorer,
)


# --- fixtures (fresh dicts per call; landed-planner shapes) ---------------

def web_plan():
    """plan_web_pentest shape: target + phases (activities, cmds)."""
    return {
        "target": "wks-a01.lab.example",
        "phases": [
            {"phase": "1-pre-engagement", "goal": "Scope the engagement",
             "activities": ["Confirm written authorization, see "
                            "https://scope.example/policy."],
             "sample_commands": ["# scope: wks-a01.lab.example; window"]},
            {"phase": "2-recon", "goal": "Passive reconnaissance",
             "activities": ["Identify infrastructure, domains, and "
                            "exposure."],
             "sample_commands": ["whois wks-a01.lab.example",
                                 "dig wks-a01.lab.example ANY +noall "
                                 "+answer"]},
            {"phase": "3-discovery", "goal": "Active enumeration",
             "activities": ["Map ports and web surface.",
                            "Fingerprint servers with "
                            "https://nmap.org/book/ guidance."],
             "sample_commands": [
                 "nmap -sV -Pn --top-ports 1000 wks-a01.lab.example",
                 "whatweb http://wks-a01.lab.example"]},
        ],
    }


def redteam_plan():
    """plan_redteam shape: scope + tool-phase arcs with example_tools."""
    return {
        "scope": "sre-lab",
        "phases": [
            {"phase": "recon", "goal": "Initial access prep",
             "tool_count": 2,
             "example_tools": [
                 {"name": "nmap", "url": "https://nmap.org/",
                  "purpose": "network mapper"},
                 {"name": "amass",
                  "url": "https://owasp.org/www-project-amass/",
                  "purpose": ""}]},
            {"phase": "weaponization", "goal": "Stage the tooling",
             "tool_count": 0},
        ],
        "policy": {"authorized": "lab-only"},
        "coverage": {"total": 10},
    }


def sweep_plan():
    """plan_analyzer_sweep shape: tool runsheet + plain string step."""
    return {
        "target": "chain-01",
        "net": "lab-net",
        "depth": "standard",
        "policy": {"windows": "lab"},
        "suggested_sweep": ["solhint", "slither", "nmap"],
        "steps": [
            {"step": "solhint", "text": "lint static",
             "sample_commands": ["solhint . --deny=all"]},
            {"step": "nmap", "goal": "port scan",
             "commands": ["nmap -sV {net}"]},
            "plain-step-string",
        ],
    }


def manual_plan():
    """Explicit id/title/risk_tags plan with plain string steps, sharing
    web_plan's target for cross-ref rows."""
    return {
        "id": "plan-manual-1", "title": "Manual follow-ups",
        "risk_tags": ["low-impact", "low-impact", "retest"],
        "target": "wks-a01.lab.example",
        "steps": ["collect evidence", "write report"],
    }


def source_plans():
    return {
        "plan_web_pentest": web_plan(),
        "plan_redteam": redteam_plan(),
        "plan_contract_sweep": sweep_plan(),
        "plan-manual-key": manual_plan(),
    }


def source_ops():
    return {
        "plan_web_pentest": {
            "detail": "The 12-phase web engagement plan for a target.",
            "params": ["target"]},
        "web_recon_commands": {
            "purpose": "Reconnaissance command catalog for a target, "
                       "grouped by step.",
            "args": ["target", 7, None, {"bad": 1}]},
        "redteam_catalog": "Phase-keyed red-team tool catalog.",
        "validate_target": {
            "description": "Gate a target against the engagement scope."},
    }


def full_source():
    return {"plans": source_plans(), "ops": source_ops()}


def wide_source():
    """Two plans with 30 shared sweep tools plus 80 unique step tools
    and 80 step refs - the cap-behavior fixture."""
    steps = []
    for i in range(80):
        steps.append({
            "phase": "tool-%03d" % i,
            "goal": "analyzer %03d on the lab" % i,
            "sample_commands": [
                "tool-%03d --lab --%s --note https://ref.example/doc-%03d"
                % (i, "x" * 200, i)]})
    return {"plans": {
        "plan-big-1": {
            "target": "lab-big",
            "suggested_sweep": ["share-%02d" % i for i in range(30)],
            "phases": steps},
        "plan-mate": {
            "target": "mate-t",
            "suggested_sweep": ["share-%02d" % i for i in range(30)]
                               + ["z-extra"]},
    }}


def hostile_plan():
    """Control characters, mixed entries, non-tool commands."""
    return {
        "phases": [
            {"phase": "bad\nstep\tname", "goal": "goal\x00 with\x1fctrl"},
            "plain step",
            42,
            None,
            {"sample_commands": ["grep 'https://x.example/a' file",
                                 "cmd | pipe ; sep & back `x` ()"],
             "example_tools": [{"name": "evil\npipe",
                                "url": "not a url"}],
             "activities": [None, {"x": 1}, "activity text\nnew", 3.5]},
        ],
    }


def explorer(source):
    return PlanExplorer(source)


class FakePlanner:
    """Duck-typed planner source: attributes only; never called."""

    def __init__(self, plans, ops=None):
        self.plans = plans
        self.ops = ops


# --- construction ---------------------------------------------------------

def test_dict_source_construction():
    px = explorer(full_source())
    assert isinstance(px, PlanExplorer)
    counts = px.explore()["counts"]
    assert counts == {"plans": 4, "ops": 4, "steps": 10,
                      "skipped_plans": 0}


def test_object_source_construction():
    px = PlanExplorer(FakePlanner(source_plans(), source_ops()))
    assert px.explore()["counts"]["plans"] == 4
    assert px.explore()["counts"]["ops"] == 4
    # plans-only planner (ops attribute absent) is legal
    solo = PlanExplorer(FakePlanner(source_plans()))
    assert solo.explore()["counts"] == {"plans": 4, "ops": 0, "steps": 10,
                                        "skipped_plans": 0}


@pytest.mark.parametrize("bad", [None, 42, "str-source", object()])
def test_bad_source_raises(bad):
    with pytest.raises(ValueError):
        PlanExplorer(bad)


def test_containers_validated():
    with pytest.raises(ValueError):
        PlanExplorer({"plans": None})
    with pytest.raises(ValueError):
        PlanExplorer({"plans": {}, "ops": 42})
    with pytest.raises(ValueError):
        PlanExplorer({"plans": 42})


# --- contract pins ---------------------------------------------------------

def test_docstring_first_line_capability():
    first = plan_explorer.__doc__.splitlines()[0]
    low = first.lower()
    assert "browse" in low and "plans/ops" in low
    assert "without execution" in low


def test_public_surface_and_constants():
    assert CAP_ROWS == 25
    assert TREE_MAX_WIDTH == 96
    assert TREE_MAX_HEIGHT == 120
    assert sorted(n for n in dir(PlanExplorer) if not n.startswith("_")) == [
        "explore", "related", "render", "search", "show"]


# --- explore ----------------------------------------------------------------

def test_explore_shape():
    data = explorer(full_source()).explore()
    assert sorted(data) == ["counts", "ops", "plans"]
    assert [row["id"] for row in data["plans"]] == [
        "plan_web_pentest", "plan_redteam", "plan_contract_sweep",
        "plan-manual-1"]
    assert len(data["ops"]) == 4
    assert data["counts"]["steps"] == 10


def test_explore_plan_row_values():
    rows = explorer(full_source()).explore()["plans"]
    by_id = {row["id"]: row for row in rows}
    assert sorted(by_id["plan_web_pentest"]) == sorted(
        ["id", "title", "step_count", "risk_tags"])
    assert by_id["plan_web_pentest"]["title"] == "plan_web_pentest"
    assert by_id["plan_web_pentest"]["step_count"] == 3
    assert by_id["plan_web_pentest"]["risk_tags"] == []
    assert by_id["plan_contract_sweep"]["step_count"] == 3
    manual = by_id["plan-manual-1"]
    assert manual["title"] == "Manual follow-ups"
    assert manual["risk_tags"] == ["low-impact", "retest"]
    assert manual["step_count"] == 2
    # risk-tag lists coerce (numbers stringify), dedup, keep order
    px = explorer({"plans": {"taggy": {"tags": [1, "x", None,
                                                {"oops": 1}, "x"]}}})
    assert px.explore()["plans"][0]["risk_tags"] == ["1", "x"]


def test_explore_ops_rows():
    ops = explorer(full_source()).explore()["ops"]
    by_name = {op["name"]: op for op in ops}
    assert sorted(by_name) == sorted(["plan_web_pentest",
                                      "web_recon_commands",
                                      "redteam_catalog", "validate_target"])
    assert sorted(by_name["plan_web_pentest"]) == ["detail", "name",
                                                   "params"]
    assert (by_name["plan_web_pentest"]["detail"]
            == "The 12-phase web engagement plan for a target.")
    assert by_name["plan_web_pentest"]["params"] == ["target"]
    # detail-key precedence: purpose/description backfills
    assert (by_name["web_recon_commands"]["detail"]
            == "Reconnaissance command catalog for a target, grouped "
               "by step.")
    assert by_name["web_recon_commands"]["params"] == ["target"]
    assert by_name["validate_target"]["params"] == []
    assert (by_name["validate_target"]["detail"]
            == "Gate a target against the engagement scope.")
    # a bare string descriptor names the op with no detail
    assert by_name["redteam_catalog"]["detail"] == ""
    # list-entry ops: bare strings name the op, dict entries carry
    # their own name keys; params dedup (strings-only op-card names)
    px = explorer({"plans": {}, "ops": [
        "nmap sweep",
        {"name": "gate", "detail": "d1", "params": ["t", "t", 5, None]},
    ]})
    assert px.explore()["ops"] == [
        {"name": "nmap sweep", "detail": "", "params": []},
        {"name": "gate", "detail": "d1", "params": ["t"]},
    ]


def test_skipped_malformed_plans():
    px = explorer({"plans": {"a": {"phases": []}, "bad": "oops",
                             "worse": [1, 2], "b": {"steps": []}}})
    counts = px.explore()["counts"]
    assert counts["plans"] == 2
    assert counts["skipped_plans"] == 2


def test_explore_deterministic():
    px = explorer(full_source())
    assert px.explore() == px.explore()
    assert px.show("plan_web_pentest") == px.show("plan_web_pentest")
    assert px.related("plan_web_pentest") == px.related("plan_web_pentest")


# --- show -------------------------------------------------------------------

def test_show_shape_and_refs():
    detail = explorer(full_source()).show("plan_web_pentest")
    assert sorted(detail) == sorted(["found", "plan_id", "title",
                                     "step_count", "args", "risk_tags",
                                     "steps", "refs"])
    assert detail["found"] is True
    assert detail["plan_id"] == "plan_web_pentest"
    assert detail["title"] == "plan_web_pentest"
    assert detail["step_count"] == 3
    assert detail["args"] == {"target": "wks-a01.lab.example"}
    assert detail["risk_tags"] == []
    # deduped, order-stable, punctuation-stripped urls across steps
    assert detail["refs"] == ["https://scope.example/policy",
                              "http://wks-a01.lab.example",
                              "https://nmap.org/book/"]


def test_show_step_rows():
    detail = explorer(full_source()).show("plan_web_pentest")
    assert [row["name"] for row in detail["steps"]] == [
        "1-pre-engagement", "2-recon", "3-discovery"]
    recon = detail["steps"][1]
    assert sorted(recon) == ["activities", "commands", "name", "text"]
    assert recon["text"] == "Passive reconnaissance"
    assert recon["commands"] == ["whois wks-a01.lab.example",
                                 "dig wks-a01.lab.example ANY +noall "
                                 "+answer"]
    assert recon["activities"] == ["Identify infrastructure, domains, "
                                   "and exposure."]
    zero = detail["steps"][0]
    assert zero["commands"] == ["# scope: wks-a01.lab.example; window"]
    assert zero["activities"] == [
        "Confirm written authorization, see "
        "https://scope.example/policy."]


def test_show_args_types():
    px = explorer({"plans": {"b": {"flag": True, "score": 2,
                                   "note": None, "tags": ["x"],
                                   "steps": []}}})
    detail = px.show("b")
    assert detail["title"] == "b"
    assert detail["step_count"] == 0
    assert detail["steps"] == []
    # args take top-level SCALARS only (tags is a list -> risk_tags view)
    assert detail["args"] == {"flag": "True", "score": "2"}
    assert detail["risk_tags"] == ["x"]


@pytest.mark.parametrize("step,want", [
    (0, "1-pre-engagement"),
    ("2-recon", "2-recon"),
])
def test_show_narrow(step, want):
    px = explorer(full_source())
    detail = px.show("plan_web_pentest", step=step)
    assert detail["found"] is True
    assert [row["name"] for row in detail["steps"]] == [want]
    assert detail["step_count"] == 3  # plan total, not filtered
    # case-insensitive name fallback and python-style tail index
    assert (px.show("plan_web_pentest", step="2-RECON")
            ["steps"][0]["name"]) == "2-recon"
    assert (px.show("plan_web_pentest", step=-1)
            ["steps"][0]["name"]) == "3-discovery"


@pytest.mark.parametrize("step,echo", [("1", "1"), (99, "99"),
                                       (True, "True")])
def test_show_narrow_miss(step, echo):
    px = explorer(full_source())
    detail = px.show("plan_web_pentest", step=step)
    assert detail["found"] is False
    assert detail["reason"] == REASON_UNKNOWN_STEP
    assert detail["step"] == echo
    assert detail["plan_id"] == "plan_web_pentest"
    assert detail["known"] == ["1-pre-engagement", "2-recon",
                               "3-discovery"]


def test_show_plan_not_found():
    detail = explorer(full_source()).show("nope")
    assert detail == {
        "found": False, "plan_id": "nope", "step": "",
        "reason": REASON_UNKNOWN_PLAN,
        "known": ["plan_web_pentest", "plan_redteam",
                  "plan_contract_sweep", "plan-manual-1"]}


def test_show_refs_cap():
    detail = explorer(wide_source()).show("plan-big-1")
    refs = detail["refs"]
    assert len(refs) == CAP_ROWS
    assert len(set(refs)) == CAP_ROWS
    assert all(u.startswith(("http://", "https://")) for u in refs)
    assert refs[0] == "https://ref.example/doc-000"


# --- related -------------------------------------------------------------------

def test_related_web_rows():
    data = explorer(full_source()).related("plan_web_pentest")
    assert sorted(data) == ["found", "plan_id", "rows"]
    assert data["found"] is True
    assert data["rows"] == [
        {"kind": "target", "value": "wks-a01.lab.example",
         "plans": ["plan-manual-1"]},
        {"kind": "tool", "value": "nmap",
         "plans": ["plan_redteam", "plan_contract_sweep"]},
    ]


def test_related_redteam_sweep():
    px = explorer(full_source())
    assert px.related("plan_redteam")["rows"] == [
        {"kind": "tool", "value": "nmap",
         "plans": ["plan_web_pentest", "plan_contract_sweep"]}]
    assert px.related("plan_contract_sweep")["rows"] == [
        {"kind": "tool", "value": "nmap",
         "plans": ["plan_web_pentest", "plan_redteam"]}]


def test_related_not_found():
    data = explorer(full_source()).related("nope")
    assert data["found"] is False
    assert data["reason"] == REASON_UNKNOWN_PLAN
    assert data["plan_id"] == "nope"
    assert data["known"] == ["plan_web_pentest", "plan_redteam",
                             "plan_contract_sweep", "plan-manual-1"]


def test_related_cap():
    px = explorer(wide_source())
    data = px.related("plan-big-1")
    rows = data["rows"]
    assert len(rows) == CAP_ROWS
    assert all(row["kind"] == "tool" for row in rows)
    assert [row["value"] for row in rows] == ["share-%02d" % i
                                              for i in range(25)]
    assert all(row["plans"] == ["plan-mate"] for row in rows)
    assert "plan-big-1" not in rows[0]["plans"]


# --- search ----------------------------------------------------------------

def test_search_steps():
    data = explorer(full_source()).search("recon")
    assert data["term"] == "recon"
    assert data["matches"] == [
        {"source": "plan", "plan_id": "plan_web_pentest",
         "step": "2-recon", "text": "2-recon"},
        {"source": "plan", "plan_id": "plan_redteam",
         "step": "recon", "text": "recon"},
        {"source": "op", "name": "web_recon_commands",
         "text": "Reconnaissance command catalog for a target, "
                 "grouped by step."},
    ]
    assert data["counts"] == {"plans": 2, "ops": 1, "truncated": False}


def test_search_ops():
    data = explorer(full_source()).search("engagement plan")
    assert data["matches"] == [
        {"source": "op", "name": "plan_web_pentest",
         "text": "The 12-phase web engagement plan for a target."}]
    assert data["counts"] == {"plans": 0, "ops": 1, "truncated": False}
    miss = explorer(full_source()).search("absolutely-nothing")
    assert miss == {"term": "absolutely-nothing", "matches": [],
                    "counts": {"plans": 0, "ops": 0, "truncated": False}}


def test_search_casefold_command():
    px = explorer(full_source())
    data = px.search("NMAP")
    assert [row["step"] for row in data["matches"]] == [
        "3-discovery", "nmap"]
    hit = px.search("whatweb")
    assert hit["matches"] == [
        {"source": "plan", "plan_id": "plan_web_pentest",
         "step": "3-discovery",
         "text": "whatweb http://wks-a01.lab.example"}]


def test_search_cap():
    data = explorer(wide_source()).search("tool-")
    assert data["counts"]["plans"] == 80
    assert len(data["matches"]) == CAP_ROWS
    assert data["counts"]["truncated"] is True
    assert [row["step"] for row in data["matches"]] == [
        "tool-%03d" % i for i in range(25)]


@pytest.mark.parametrize("term", ["", None, 42])
def test_search_term_validation(term):
    with pytest.raises(ValueError):
        explorer(full_source()).search(term)


# --- render ------------------------------------------------------------------

def test_render_all_tree():
    px = explorer(full_source())
    text = px.render()
    lines = text.splitlines()
    assert lines[0] == "plans (4 plans, 10 steps)"
    assert "+- plan_web_pentest (steps=3)" in lines
    assert "+- plan_redteam (steps=2)" in lines
    assert "+- plan_contract_sweep (steps=3)" in lines
    assert "`- plan-manual-1 (steps=2) tags=low-impact,retest" in lines
    assert "|   +- 2-recon: Passive reconnaissance" in lines
    assert ("|   |   +- cmd: whois wks-a01.lab.example") in lines
    assert "|   `- plain-step-string" in lines
    assert "    +- collect evidence" in lines
    assert "    `- write report" in lines
    assert "args:" not in text  # args are a single-plan view detail


def test_render_single_plan():
    px = explorer(full_source())
    text = px.render("plan_web_pentest")
    lines = text.splitlines()
    assert lines[0] == "plan_web_pentest (steps=3)"
    assert "+- args: target=wks-a01.lab.example" in lines
    assert "+- 1-pre-engagement: Scope the engagement" in lines
    assert ("|   `- act: Confirm written authorization, see "
            "https://scope.example/policy.") in lines
    manual = px.render("plan-manual-1").splitlines()
    assert manual[0] == "plan-manual-1 (steps=2)"
    assert "+- tags: low-impact, retest" in manual
    assert "+- collect evidence" in manual  # no trailing colon on empty


def test_render_not_found():
    text = explorer(full_source()).render("nope")
    lines = text.splitlines()
    assert lines[0] == "not-found: plan 'nope'"
    assert lines[1] == ("known (4): plan_web_pentest, plan_redteam, "
                        "plan_contract_sweep, plan-manual-1")


def test_render_deterministic():
    px = explorer(full_source())
    assert px.render() == px.render()
    assert px.render("plan_web_pentest") == px.render("plan_web_pentest")


def test_render_caps():
    px = explorer(wide_source())
    text = px.render("plan-big-1")
    lines = text.splitlines()
    assert len(lines) <= TREE_MAX_HEIGHT
    assert all(len(line) <= TREE_MAX_WIDTH for line in lines)
    assert any(len(line) == TREE_MAX_WIDTH and line.endswith("...")
               for line in lines)
    assert re.fullmatch(r"\.\.\. \(\+\d+ lines hidden\)", lines[-1])
    every = px.render()
    assert all(len(line) <= TREE_MAX_WIDTH
               for line in every.splitlines())
    assert len(every.splitlines()) <= TREE_MAX_HEIGHT


def test_render_empty_explorer():
    px = explorer({"plans": {}})
    assert px.render() == "plans (0 plans, 0 steps)"
    assert px.explore()["counts"] == {"plans": 0, "ops": 0, "steps": 0,
                                      "skipped_plans": 0}
    assert px.show("zzz")["found"] is False


def test_render_no_control_characters():
    px = explorer({"plans": {"h": hostile_plan()}})
    text = px.render("h")
    for line in text.splitlines():
        assert all(ord(ch) >= 32 for ch in line)
        assert len(line) <= TREE_MAX_WIDTH
    assert "bad step name" in text      # newline/tab collapsed
    assert "goal with ctrl" in text     # \\x00 / \\x1f collapsed
    assert "activity text new" in text  # multi-entry activity
    detail = px.show("h")
    assert [row["name"] for row in detail["steps"]] == [
        "bad step name", "plain step", "42", "step-4", "step-5"]
    assert detail["refs"] == ["https://x.example/a"]
    # step-<n> fallbacks for unnamed entries, 1-based
    assert detail["steps"][2]["name"] == "42"
    assert detail["steps"][3]["name"] == "step-4"


def test_id_collision_suffixes():
    px = explorer({"plans": [
        {"id": "same", "phases": []},
        {"id": "same", "phases": []},
        {"plan_id": "same", "phases": []},
    ]})
    assert [row["id"] for row in px.explore()["plans"]] == [
        "same", "same-2", "same-3"]
    assert px.show("same-3")["found"] is True


# --- purity & non-mutation ------------------------------------------------------

def test_purity_source_scan():
    code = Path(plan_explorer.__file__).read_text()
    # the spec pin: the run word itself never appears
    assert "execute" not in code
    assert "subprocess" not in code
    assert "os.system" not in code
    assert "eval(" not in code
    assert "exec(" not in code
    assert "popen" not in code
    assert "open(" not in code
    assert "import os" not in code
    banned_import = re.compile(r"(?m)^\s*(?:import|from)\s+"
                               r"(?:socket|urllib|http|requests|shutil|"
                               r"subprocess|ssl|ftplib|telnetlib)\b")
    assert not banned_import.search(code)


def test_never_mutates_source():
    source = full_source()
    snapshot = copy.deepcopy(source)
    px = explorer(source)
    px.explore()
    px.show("plan_web_pentest", step="2-recon")
    px.related("plan_web_pentest")
    px.search("nmap")
    px.render()
    assert source == snapshot
    # returned structures are copies too: mutating them does not leak
    detail = px.show("plan_web_pentest")
    detail["steps"][0]["commands"].append("tampered")
    detail["args"]["target"] = "tampered"
    assert px.show("plan_web_pentest") == px.show("plan_web_pentest")
    assert px.show("plan_web_pentest")["args"] == {
        "target": "wks-a01.lab.example"}
    obj_source = FakePlanner(source_plans(), source_ops())
    obj_snapshot = copy.deepcopy({"plans": obj_source.plans,
                                  "ops": obj_source.ops})
    obj_px = PlanExplorer(obj_source)
    obj_px.explore()
    obj_px.render("plan_redteam")
    obj_px.related("plan_contract_sweep")
    assert {"plans": obj_source.plans, "ops": obj_source.ops} == (
        obj_snapshot)