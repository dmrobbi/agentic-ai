"""Plan Explorer (KA-098): browse plans/ops in a rich REPL view without execution -
all read-only over injected structures.

A pure module (docs/KA-BUILDING-CONVENTIONS.md): PlanExplorer wraps any
duck-typed source that exposes `plans` and `ops` (a {"plans": ..., "ops":
...} dict or an object with `plans`/`ops` attributes) holding the shapes
the landed planners already produce, and serves a review-only
console/REPL surface:

  explore()  plan + op index rows and totals
  show()     one plan's detail (args, steps, refs) or a clean not-found
  related()  cross-ref rows: shared targets/tools across plans (cap 25)
  render()   a stable text tree (no emojis; capped width/height)
  search()   matching steps/ops (cap 25)

Source shapes accepted (per the landed planners):
  plans  dict {id -> plan dict} or list of plan dicts. A plan dict is any
         planner payload: {"target": ..., "phases": [...]},
         {"scope": ..., "phases": [...], "suggested_sweep": [...]},
         {"target", "net", "steps": [...]} runsheets, steps that are
         plain strings, plans with explicit id/title/risk_tags. A plan's
         top-level scalar keys become its `args` view (stringified);
         containers are excluded. Malformed plan entries are SKIPPED and
         counted, never crashed on (house skip-route discipline); ids
         collide-suffix as "<id>-2", "<id>-3", ...
  ops    dict {name -> op descriptor} or list of op descriptors. An op
         descriptor is a string (bare name), a dict with
         detail/purpose/description/doc (first present wins) and
         params/args (scalar entries only), or a dict carrying its own
         name/op/id.

Step rows normalize to {"name", "text", "commands", "activities"} with
step-name fallbacks "step-<n>" (1-based) when the planner skipped
naming. show() narrows by 0-based python step index (negatives allowed)
or by exact step name, falling back to case-insensitive. Every
not-found response is a clean {"found": False, ..., "known": ...} dict
carrying the known ids/names (capped 25).

PLANNER PURITY: no process spawning, no network facilities, no local
I/O; the source-scan pins in tests/test_plan_explorer.py verify the
module text stays free of run paths. Nothing here mutates the injected
structures either.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

__all__ = [
    "PlanExplorer",
    "CAP_ROWS",
    "TREE_MAX_WIDTH",
    "TREE_MAX_HEIGHT",
    "URL_RE",
    "REASON_UNKNOWN_PLAN",
    "REASON_UNKNOWN_STEP",
]

# --- contract constants (the drift alarm; the tests pin them) -------------

CAP_ROWS = 25          # house cap: related/search rows, refs, hint lists
TREE_MAX_WIDTH = 96    # any rendered line stays at or under this
TREE_MAX_HEIGHT = 120  # any rendered tree stays at or under this many lines

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_WS_RE = re.compile(r"[\x00-\x20\x7f]+")

TARGET_KEYS = ("target", "scope", "target_label", "device_label",
               "account_label", "artifact_label", "net", "dc")
PLAN_ID_KEYS = ("id", "plan_id")
PLAN_TITLE_KEYS = ("title", "name")
STEP_KEYS = ("phases", "steps")
STEP_NAME_KEYS = ("phase", "step", "name", "tool", "stage")
STEP_TEXT_KEYS = ("goal", "purpose", "text", "summary", "detail")
STEP_CMD_KEYS = ("sample_commands", "commands")
STEP_ACT_KEYS = ("activities",)
STEP_TOOL_KEYS = ("example_tools", "tools")
PLAN_TOOL_KEYS = ("suggested_sweep", "tools")
RISK_KEYS = ("risk_tags", "tags", "risks")
OP_NAME_KEYS = ("name", "op", "id")
OP_DETAIL_KEYS = ("detail", "purpose", "description", "doc", "card")
OP_PARAM_KEYS = ("params", "args")

REASON_UNKNOWN_PLAN = "unknown plan id"
REASON_UNKNOWN_STEP = "unknown step (use a 0-based index or an exact name)"
REASON_SCALAR = "a scalar string"

SCALARS = (str, int, float, bool)


# --- shared input scrubbing (one helper per concern; house pattern) --------

def _text(value: Any) -> str:
    """Display string for any value: strings pass through, scalars
    stringify, and every control character or whitespace run collapses
    to a single space (stable single-line rendering everywhere)."""
    s = value if isinstance(value, str) else (
        "" if value is None else str(value))
    return _WS_RE.sub(" ", s).strip()


def _uniq(items: List[str]) -> List[str]:
    """Order-preserving de-duplication."""
    seen: set = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _first(mapping: Dict[str, Any], keys, scalar=False):
    """First key with a usable value; scalar=True demands a scalar."""
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        if scalar and not isinstance(value, SCALARS):
            continue
        return value
    return None


def _scalar_list(container: Dict[str, Any], keys,
                 str_only: bool = False) -> List[str]:
    """Scalar entries under the first matching key (containers and
    nulls skipped; str_only additionally keeps true strings alone)."""
    for key in keys:
        value = container.get(key)
        if isinstance(value, (list, tuple)):
            out = []
            for entry in value:
                if entry is None or isinstance(entry, (dict, list, tuple, set)):
                    continue
                if str_only and not isinstance(entry, str):
                    continue
                out.append(_text(entry))
            return out
    return []


def _tool_entries(container: Dict[str, Any], keys) -> List[str]:
    """Tool names under the given keys: scalar entries and dicts named
    name/tool both qualify."""
    names: List[str] = []
    for key in keys:
        value = container.get(key)
        if not isinstance(value, (list, tuple)):
            continue
        for tool in value:
            if isinstance(tool, dict):
                candidate = _first(tool, ("name", "tool"), scalar=True)
                name = _text(candidate)
            else:
                if tool is None or isinstance(tool, (list, tuple, set)):
                    continue
                name = _text(tool)
            if name:
                names.append(name)
    return names


def _extract_urls(strings: List[str]) -> List[str]:
    """Deduped, capped URL refs from display strings (order stable)."""
    urls: List[str] = []
    for s in strings:
        for raw in URL_RE.findall(s):
            url = raw.rstrip(".,;:")
            url = url.rstrip("')\"")
            if url:
                urls.append(url)
    return _uniq(urls)[:CAP_ROWS]


def _cmd_tool(command: str) -> str:
    """Tool token from a sample command: first word, minus path/flags;
    comments and non-tool-ish tokens yield ''."""
    cmd = command.strip()
    if not cmd or cmd.startswith("#"):
        return ""
    parts = cmd.split()
    if not parts:
        return ""
    token = parts[0].strip("'\"")
    if not token or token.startswith("-"):
        return ""
    if "/" in token or "\\" in token:
        token = token.replace("\\", "/").rsplit("/", 1)[-1]
    if token == "sudo" or not re.fullmatch(r"[a-z0-9][a-z0-9._+\-]*", token):
        return ""
    return token


def _tokens_from_step(row: Dict[str, Any]) -> List[str]:
    """Tool tokens a step row implies: its explicit tool lists' names are
    handled at plan level; here only sample commands count."""
    out: List[str] = []
    for command in row["commands"]:
        tool = _cmd_tool(command)
        if tool:
            out.append(tool)
    return out


# --- normalization ---------------------------------------------------------

def _normalize_steps(plan: Dict[str, Any]) -> Any:
    """The plan's step collection into {'name','text','commands',
    'activities'} rows (names 1-based "step-<n>" fallback), plus the
    plan's per-step tool names and deduped ref URLs."""
    raw = None
    for key in STEP_KEYS:
        value = plan.get(key)
        if isinstance(value, (list, tuple)):
            raw = value
            break
    if raw is None:
        return [], [], []
    rows: List[Dict[str, Any]] = []
    plan_tools: List[str] = []
    plan_urls: List[str] = []
    for i, entry in enumerate(raw, 1):
        name, text, commands, activities = "", "", [], []
        if isinstance(entry, dict):
            name = _text(_first(entry, STEP_NAME_KEYS, scalar=True))
            text = _text(_first(entry, STEP_TEXT_KEYS, scalar=True))
            commands = _scalar_list(entry, STEP_CMD_KEYS)
            activities = _scalar_list(entry, STEP_ACT_KEYS)
            plan_tools.extend(_tool_entries(entry, STEP_TOOL_KEYS))
        else:
            if entry is not None and not isinstance(entry, (list, tuple, set)):
                name = _text(entry)
        if not name:
            name = "step-%d" % i
        candidates = [text] + commands + activities
        urls = _extract_urls(candidates)
        rows.append({"name": name, "text": text, "commands": commands,
                     "activities": activities})
        plan_urls.extend(urls)
    return rows, _uniq(plan_tools), _uniq(plan_urls)[:CAP_ROWS]


def _normalize_plan(entry: Dict[str, Any], fallback_id: str) -> Dict[str, Any]:
    """One plan dict -> the explorer's normalized view (no mutation of
    the injected payload); the final (collision-suffixed) id arrives
    already resolved from the plans-container walker."""
    pid = fallback_id
    title = _text(_first(entry, PLAN_TITLE_KEYS, scalar=True)) or pid
    steps, tools, urls = _normalize_steps(entry)
    tools = _uniq(_tool_entries(entry, PLAN_TOOL_KEYS) + tools)
    risk_tags = _uniq(tag for tag in _scalar_list(entry, RISK_KEYS))
    args = {}
    for key, value in entry.items():
        if key in STEP_KEYS:
            continue
        if isinstance(value, SCALARS):
            args[_text(key)] = _text(value)
    return {"id": pid, "title": title, "step_count": len(steps),
            "risk_tags": risk_tags, "args": args, "steps": steps,
            "tools": tools, "urls": urls}


def _normalize_plans(raw: Any) -> Any:
    """Plans container -> normalized plan views and the skipped count;
    a non-dict/list container is a CALLER error (raised, not skipped)."""
    rows: List[Dict[str, Any]] = []
    if isinstance(raw, dict):
        items = list(raw.items())
    elif isinstance(raw, (list, tuple)):
        items = [(None, value) for value in raw]
    else:
        raise ValueError("plans must be a dict of plan dicts or a list of "
                         "plan dicts, got: %r" % (raw,))
    skipped = 0
    used: set = set()
    for i, (key, value) in enumerate(items, 1):
        if not isinstance(value, dict):
            skipped += 1
            continue
        fallback = _text(key) or "plan-%d" % i
        pid = _text(_first(value, PLAN_ID_KEYS, scalar=True)) or fallback
        if pid in used:
            n = 2
            while "%s-%d" % (pid, n) in used:
                n += 1
            pid = "%s-%d" % (pid, n)
        used.add(pid)
        rows.append(_normalize_plan(value, pid))
    return rows, skipped


def _normalize_ops(raw: Any) -> List[Dict[str, Any]]:
    """Ops container -> {"name", "detail", "params"} rows."""
    rows: List[Dict[str, Any]] = []
    if raw is None:
        return rows
    if isinstance(raw, dict):
        items = list(raw.items())
    elif isinstance(raw, (list, tuple)):
        items = [(None, value) for value in raw]
    else:
        raise ValueError("ops must be a dict or list of op descriptors, "
                         "got: %r" % (raw,))
    for i, (key, value) in enumerate(items, 1):
        name = _text(key)
        candidate = ""
        if isinstance(value, dict):
            if not name:
                name = _text(_first(value, OP_NAME_KEYS, scalar=True))
            detail = _text(_first(value, OP_DETAIL_KEYS, scalar=True))
            params = _uniq(_scalar_list(value, OP_PARAM_KEYS, str_only=True))
        else:
            if value is not None and not isinstance(value, (list, tuple, set)):
                candidate = _text(value)
            else:
                candidate = ""
            detail = ""
            params = []
        if not name:
            name = _text(candidate) or "op-%d" % i
        rows.append({"name": name, "detail": detail, "params": params})
    return rows


def _plan_tokens(view: Dict[str, Any]) -> Dict[Any, str]:
    """The plan's cross-ref tokens: target-ish args and tool names
    (comparison key -> first-seen display value)."""
    tokens: Dict[Any, str] = {}
    for key in TARGET_KEYS:
        if key in view["args"]:
            tokens.setdefault(("target", view["args"][key].casefold()),
                              view["args"][key])
    for tool in view["tools"]:
        tokens.setdefault(("tool", tool.casefold()), tool)
    for row in view["steps"]:
        for command in row["commands"]:
            tool = _cmd_tool(command)
            if tool:
                tokens.setdefault(("tool", tool), tool)
    return tokens


def _extract_source(source: Any) -> Any:
    """The duck-typed source gate: a dict or an object exposing `plans`
    (required) and `ops` (optional). No method is ever called."""
    plans = None
    ops = None
    if isinstance(source, dict):
        plans = source.get("plans")
        ops = source.get("ops")
    elif isinstance(source, (str, bytes, int, float, bool, list, tuple,
                             set)) or source is None:
        plans = None
    else:
        plans = getattr(source, "plans", None)
        ops = getattr(source, "ops", None)
    if plans is None and not isinstance(source, dict):
        raise ValueError("source must expose plans/ops (a dict with "
                         "'plans'/'ops' or an object with those "
                         "attributes), got: %r" % (source,))
    if plans is None:
        raise ValueError("source plans missing or null: %r" % (source,))
    return plans, ops


def _cap_tree(lines: List[str]) -> str:
    """Stable caps: at most TREE_MAX_HEIGHT lines, each at most
    TREE_MAX_WIDTH wide, with explicit truncation markers."""
    if len(lines) > TREE_MAX_HEIGHT:
        hidden = len(lines) - TREE_MAX_HEIGHT + 1
        marker = "... (+%d lines hidden)" % hidden
        lines = lines[:TREE_MAX_HEIGHT - 1] + [marker]
    out = []
    for line in lines:
        if len(line) > TREE_MAX_WIDTH:
            line = line[:TREE_MAX_WIDTH - 3] + "..."
        out.append(line)
    return "\n".join(out)


def _tree_lines(lines: List[str], prefix: str, rows: List[Any]) -> None:
    """Append an ASCII tree: each branch '+- ' (or '- ' for the last
    child), continuations '|   '/'    '."""
    for i, (label, subrows) in enumerate(rows):
        last = i == len(rows) - 1
        branch = "`- " if last else "+- "
        lines.append(prefix + branch + label)
        if subrows:
            _tree_lines(lines, prefix + ("    " if last else "|   "),
                        subrows)


class PlanExplorer:
    """Browse plans/ops without execution over the injected source: a
    duck-typed plans/ops holder read once into normalized views, after
    which every method is a pure lookup returning dicts or text."""

    def __init__(self, source: Any) -> None:
        plans, ops = _extract_source(source)
        self._plan_rows, self._skipped = _normalize_plans(plans)
        self._op_rows = _normalize_ops(ops)
        self._ids = [row["id"] for row in self._plan_rows]
        self._by_id = {row["id"]: row for row in self._plan_rows}
        self._token_by_id = {row["id"]: _plan_tokens(row)
                             for row in self._plan_rows}

    # -- index ------------------------------------------------------------

    def explore(self) -> Dict[str, Any]:
        """Index all injected plans and ops: plan rows (id, title, step
        count, risk tags), normalized op rows, and totals."""
        return {
            "plans": [{"id": row["id"], "title": row["title"],
                       "step_count": row["step_count"],
                       "risk_tags": list(row["risk_tags"])}
                      for row in self._plan_rows],
            "ops": [{"name": op["name"], "detail": op["detail"],
                     "params": list(op["params"])} for op in self._op_rows],
            "counts": {
                "plans": len(self._plan_rows),
                "ops": len(self._op_rows),
                "steps": sum(row["step_count"]
                             for row in self._plan_rows),
                "skipped_plans": self._skipped,
            },
        }

    # -- detail -----------------------------------------------------------

    def show(self, plan_id: Any = None, step: Any = None) -> Dict[str, Any]:
        """Detail for one plan - args, normalized step rows, ref URLs -
        optionally narrowed to a single step; misses return a clean
        {'found': False} dict with the known ids or step names."""
        pid = _text(plan_id)
        plan = self._by_id.get(pid)
        if plan is None:
            return {"found": False, "plan_id": pid, "step": _text(step),
                    "reason": REASON_UNKNOWN_PLAN,
                    "known": list(self._ids[:CAP_ROWS])}
        chosen = None
        if step is None:
            chosen = list(plan["steps"])
        elif isinstance(step, bool):
            chosen = None
        elif isinstance(step, int):
            if -len(plan["steps"]) <= step < len(plan["steps"]):
                chosen = [plan["steps"][step]]
        elif isinstance(step, str):
            wanted = _text(step)
            idx = None
            for i, row in enumerate(plan["steps"]):
                if row["name"] == wanted:
                    idx = i
                    break
            if idx is None:
                fold = wanted.casefold()
                for i, row in enumerate(plan["steps"]):
                    if row["name"].casefold() == fold:
                        idx = i
                        break
            if idx is not None:
                chosen = [plan["steps"][idx]]
        if chosen is None:
            return {"found": False, "plan_id": pid, "step": _text(step),
                    "reason": REASON_UNKNOWN_STEP,
                    "known": [row["name"] for row in plan["steps"]]
                             [:CAP_ROWS]}
        return {"found": True, "plan_id": plan["id"],
                "title": plan["title"],
                "step_count": plan["step_count"],
                "args": dict(plan["args"]),
                "risk_tags": list(plan["risk_tags"]),
                "steps": [{"name": row["name"], "text": row["text"],
                           "commands": list(row["commands"]),
                           "activities": list(row["activities"])}
                          for row in chosen],
                "refs": list(plan["urls"][:CAP_ROWS])}

    # -- cross-refs ---------------------------------------------------------

    def related(self, plan_id: Any = None) -> Dict[str, Any]:
        """Cross-reference rows for one plan: other plans sharing its
        targets/tools, each {'kind', 'value', 'plans'}, rows capped 25."""
        pid = _text(plan_id)
        if pid not in self._by_id:
            return {"found": False, "plan_id": pid,
                    "reason": REASON_UNKNOWN_PLAN,
                    "known": list(self._ids[:CAP_ROWS])}
        tokens = self._token_by_id[pid]
        rows: List[Dict[str, Any]] = []
        for (kind, key), display in tokens.items():
            others = []
            for row in self._plan_rows:
                other_id = row["id"]
                if other_id == pid:
                    continue
                if (kind, key) in self._token_by_id[other_id]:
                    others.append(other_id)
                if len(others) >= CAP_ROWS:
                    break
            if others:
                rows.append({"kind": kind, "value": display,
                             "plans": others})
        rows.sort(key=lambda r: (r["kind"], r["value"].casefold()))
        return {"found": True, "plan_id": pid, "rows": rows[:CAP_ROWS]}

    # -- search -------------------------------------------------------------

    def search(self, term: Any) -> Dict[str, Any]:
        """Case-insensitive matches across plan ids/titles, step
        text/commands/activities, and op details; rows capped 25."""
        if not isinstance(term, str):
            raise ValueError("term must be a string, got: %r" % (term,))
        needle_txt = _text(term)
        if not needle_txt:
            raise ValueError("term must be a non-blank string, got: %r"
                             % (term,))
        fold = needle_txt.casefold()
        plan_matches: List[Dict[str, Any]] = []
        op_matches: List[Dict[str, Any]] = []
        for plan in self._plan_rows:
            if fold in plan["id"].casefold() or fold in plan["title"].casefold():
                plan_matches.append({"source": "plan", "plan_id": plan["id"],
                                     "step": "", "text": plan["title"]})
            for row in plan["steps"]:
                hit = ""
                if fold in row["name"].casefold():
                    hit = row["name"]
                elif fold in row["text"].casefold():
                    hit = row["text"]
                else:
                    for candidate in row["commands"] + row["activities"]:
                        if fold in candidate.casefold():
                            hit = candidate
                            break
                if hit:
                    plan_matches.append({"source": "plan",
                                         "plan_id": plan["id"],
                                         "step": row["name"], "text": hit})
        for op in self._op_rows:
            if fold in op["name"].casefold() or fold in op["detail"].casefold():
                op_matches.append({"source": "op", "name": op["name"],
                                   "text": op["detail"]})
        total = len(plan_matches) + len(op_matches)
        return {"term": needle_txt,
                "matches": (plan_matches + op_matches)[:CAP_ROWS],
                "counts": {"plans": len(plan_matches),
                           "ops": len(op_matches),
                           "truncated": total > CAP_ROWS}}

    # -- render ---------------------------------------------------------------

    def render(self, plan_id: Any = None) -> str:
        """A stable ASCII text tree of the plans (or one plan's detail)
        for the REPL/console: no emojis, width/height capped."""
        pid = _text(plan_id)
        lines: List[str] = []
        if pid:
            plan = self._by_id.get(pid)
            if plan is None:
                lines.append("not-found: plan '%s'" % pid)
                names = ", ".join(self._ids[:CAP_ROWS]) or "(none)"
                lines.append("known (%d): %s" % (len(self._ids), names))
            else:
                self._render_plan(lines, plan)
        else:
            lines.append("plans (%d plans, %d steps)"
                         % (len(self._plan_rows),
                            sum(row["step_count"]
                                for row in self._plan_rows)))
            rows = []
            for row in self._plan_rows:
                label = "%s (steps=%d)" % (row["id"], row["step_count"])
                if row["risk_tags"]:
                    label += " tags=%s" % ",".join(row["risk_tags"])
                rows.append((label, self._step_branches(row)))
            _tree_lines(lines, "", rows or [])
        return _cap_tree(lines)

    # -- helpers --------------------------------------------------------------

    def _step_branches(self, plan: Dict[str, Any]) -> List[Any]:
        """The sub-rows (step branches) for one plan's tree node."""
        out: List[Any] = []
        for row in plan["steps"]:
            leaves = []
            for command in row["commands"]:
                leaves.append(("cmd: %s" % command, []))
            for activity in row["activities"]:
                leaves.append(("act: %s" % activity, []))
            label = ("%s: %s" % (row["name"], row["text"])
                     if row["text"] else row["name"])
            out.append((label, leaves or []))
        return out

    def _render_plan(self, lines: List[str], plan: Dict[str, Any]) -> None:
        """One plan's detail tree: header, args, tags, steps."""
        lines.append("%s (steps=%d)" % (plan["id"], plan["step_count"]))
        rows: List[Any] = []
        for key in sorted(plan["args"]):
            rows.append(("args: %s=%s" % (key, plan["args"][key]), []))
        if plan["risk_tags"]:
            rows.append(("tags: %s" % ", ".join(plan["risk_tags"]), []))
        rows.extend(self._step_branches(plan))
        _tree_lines(lines, "", rows or [])
