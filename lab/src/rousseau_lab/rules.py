"""The detection rule engine, mirroring ``rousseau-core`` exactly.

The shared ``conformance/`` suite runs against both implementations; any
change to the semantics here must be made in Rust too (and vice versa). See
docs/rules.md for the format and the processing contract.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SEVERITIES = ("info", "low", "medium", "high", "critical")
MODES = ("observe", "alert", "enforce")
OPS = ("equals", "in", "contains", "startswith", "endswith", "glob", "regex", "exists", "gt", "gte", "lt", "lte")
KNOWN_RULE_KEYS = {
    "id",
    "title",
    "severity",
    "description",
    "references",
    "owasp",
    "mitre",
    "falsepositives",
    "tags",
    "enabled",
    "mode",
    "response",
    "detection",
}
MAX_CHAINS = 64
MAX_GROUPS = 10_000
MAX_WINDOW = 100_000


class RuleError(ValueError):
    """Invalid rule."""


class _Yaml12Loader(yaml.SafeLoader):
    """SafeLoader with YAML 1.2 booleans (only true/false), matching serde_yaml."""


_Yaml12Loader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:bool"] for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
for _first in "tTfF":
    _Yaml12Loader.yaml_implicit_resolvers.setdefault(_first, []).append(
        ("tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"))
    )


def load_yaml(text: str) -> Any:
    """Parses YAML with serde_yaml-compatible scalar typing."""
    return yaml.load(text, Loader=_Yaml12Loader)  # noqa: S506 (SafeLoader subclass)


def split_documents(text: str) -> list[str]:
    """Splits a YAML stream on ``---`` lines (same as the Rust loader)."""
    docs: list[list[str]] = [[]]
    for line in text.splitlines():
        if line.rstrip() == "---":
            docs.append([])
        else:
            docs[-1].append(line)
    return ["\n".join(d) + "\n" for d in docs if "".join(d).strip()]


def parse_duration_ms(s: str) -> int | None:
    m = re.fullmatch(r"(\d+)(ms|s|m|h)", s.strip())
    if not m:
        return None
    return int(m.group(1)) * {"ms": 1, "s": 1_000, "m": 60_000, "h": 3_600_000}[m.group(2)]


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def scalar_string(v: Any) -> str | None:
    """String form of a scalar for string operators (integers without fraction)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return v
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v.is_integer() and abs(v) < 1e15:
            return str(int(v))
        return repr(v)
    return None


def resolve(root: Any, path: list[str]) -> list[Any]:
    """Candidate leaf values for a dotted path (arrays flattened, nulls dropped)."""
    current: list[Any] = [root]
    for key in path:
        nxt: list[Any] = []
        for v in current:
            _collect(v, key, nxt)
        current = nxt
        if not current:
            break
    out: list[Any] = []
    for v in current:
        _flatten(v, out)
    return out


def _collect(v: Any, key: str, out: list[Any]) -> None:
    if isinstance(v, dict):
        if key in v:
            out.append(v[key])
    elif isinstance(v, list):
        for i in v:
            _collect(i, key, out)


def _flatten(v: Any, out: list[Any]) -> None:
    if v is None:
        return
    if isinstance(v, list):
        for i in v:
            _flatten(i, out)
    else:
        out.append(v)


def _values_equal(field_v: Any, want: Any, case_sensitive: bool) -> bool:
    if _is_number(field_v) and _is_number(want):
        return float(field_v) == float(want)
    a, b = scalar_string(field_v), scalar_string(want)
    if a is None or b is None:
        return False
    return a == b if case_sensitive else a.lower() == b.lower()


def compile_glob(glob: str, case_sensitive: bool) -> re.Pattern[str]:
    parts = []
    for c in glob:
        if c == "*":
            parts.append(".*")
        elif c == "?":
            parts.append(".")
        elif c in "/\\":
            parts.append(r"[/\\]")
        else:
            parts.append(re.escape(c))
    flags = re.DOTALL | (0 if case_sensitive else re.IGNORECASE)
    try:
        return re.compile("".join(parts), flags)
    except re.error as exc:
        raise RuleError(f"bad glob {glob!r}: {exc}") from exc


@dataclass
class Condition:
    """A compiled condition node."""

    kind: str  # all, any, not, field, descendant, mcp, mcp_named
    children: list[Condition] = field(default_factory=list)
    path: list[str] = field(default_factory=list)
    op: str = ""
    operand: Any = None
    case_sensitive: bool = False
    flag: bool = False
    name: str = ""

    @staticmethod
    def parse(v: Any) -> Condition:
        if not isinstance(v, dict):
            raise RuleError(f"condition must be a mapping, got {v!r}")
        for key in ("all", "any"):
            if key in v:
                _only_key(v, key)
                items = v[key]
                if not isinstance(items, list):
                    raise RuleError(f"'{key}' takes a list")
                if not items:
                    raise RuleError(f"'{key}' list is empty")
                return Condition(key, children=[Condition.parse(i) for i in items])
        if "not" in v:
            _only_key(v, "not")
            return Condition("not", children=[Condition.parse(v["not"])])
        if "descendant_of_agent" in v:
            _only_key(v, "descendant_of_agent")
            b = v["descendant_of_agent"]
            if not isinstance(b, bool):
                raise RuleError("descendant_of_agent must be true or false")
            return Condition("descendant", flag=b)
        if "spawned_by_mcp_server" in v:
            _only_key(v, "spawned_by_mcp_server")
            s = v["spawned_by_mcp_server"]
            if isinstance(s, bool):
                return Condition("mcp", flag=s)
            if isinstance(s, str):
                return Condition("mcp_named", name=s.lower())
            raise RuleError("spawned_by_mcp_server must be a boolean or a server name")
        fld = v.get("field")
        if not isinstance(fld, str):
            raise RuleError(f"unknown condition {v!r}")
        cs = v.get("case_sensitive", False)
        if not isinstance(cs, bool):
            raise RuleError("case_sensitive must be a boolean")
        op_key = None
        for k in v:
            if k in ("field", "case_sensitive"):
                continue
            if k in OPS:
                if op_key is not None:
                    raise RuleError(f"predicate on '{fld}' has more than one operator")
                op_key = k
            else:
                raise RuleError(f"unknown key '{k}' in predicate on '{fld}'")
        if op_key is None:
            raise RuleError(f"predicate on '{fld}' has no operator")
        operand = v[op_key]
        compiled: Any
        if op_key == "equals":
            if isinstance(operand, (list, dict)):
                raise RuleError("equals takes a scalar")
            compiled = operand
        elif op_key == "in":
            if not isinstance(operand, list):
                raise RuleError("in takes a list")
            compiled = operand
        elif op_key in ("contains", "startswith", "endswith"):
            compiled = [s if cs else s.lower() for s in _strings(operand, op_key)]
        elif op_key == "glob":
            compiled = [compile_glob(g, cs) for g in _strings(operand, op_key)]
        elif op_key == "regex":
            pats = []
            for r in _strings(operand, op_key):
                try:
                    pats.append(re.compile(r, 0 if cs else re.IGNORECASE))
                except re.error as exc:
                    raise RuleError(f"bad regex {r!r}: {exc}") from exc
            compiled = pats
        elif op_key == "exists":
            if not isinstance(operand, bool):
                raise RuleError("exists takes a boolean")
            compiled = operand
        else:
            if not _is_number(operand):
                raise RuleError(f"{op_key} takes a number")
            compiled = float(operand)
        return Condition("field", path=fld.split("."), op=op_key, operand=compiled, case_sensitive=cs)

    def eval(self, event: Any) -> bool:
        k = self.kind
        if k == "all":
            return all(c.eval(event) for c in self.children)
        if k == "any":
            return any(c.eval(event) for c in self.children)
        if k == "not":
            return not self.children[0].eval(event)
        if k == "descendant":
            return bool(resolve(event, ["lineage", "agent"])) == self.flag
        if k == "mcp":
            return bool(resolve(event, ["lineage", "mcp_server"])) == self.flag
        if k == "mcp_named":
            return any(isinstance(v, str) and v.lower() == self.name for v in resolve(event, ["lineage", "mcp_server"]))
        values = resolve(event, self.path)
        if self.op == "exists":
            return bool((len(values) > 0) == self.operand)
        return any(self._eval_one(v) for v in values)

    def _eval_one(self, v: Any) -> bool:
        op, operand, cs = self.op, self.operand, self.case_sensitive
        if op == "equals":
            return _values_equal(v, operand, cs)
        if op == "in":
            return any(_values_equal(v, w, cs) for w in operand)
        if op in ("contains", "startswith", "endswith"):
            s = scalar_string(v)
            if s is None:
                return False
            s = s if cs else s.lower()
            if op == "contains":
                return any(n in s for n in operand)
            if op == "startswith":
                return any(s.startswith(n) for n in operand)
            return any(s.endswith(n) for n in operand)
        if op == "glob":
            s = scalar_string(v)
            return s is not None and any(p.fullmatch(s) for p in operand)
        if op == "regex":
            s = scalar_string(v)
            return s is not None and any(p.search(s) for p in operand)
        if not _is_number(v):
            return False
        x = float(v)
        return bool({"gt": x > operand, "gte": x >= operand, "lt": x < operand, "lte": x <= operand}[op])


def _only_key(v: dict[str, Any], key: str) -> None:
    if len(v) != 1:
        raise RuleError(f"'{key}' must be the only key in its mapping")


def _strings(v: Any, op: str) -> list[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, list) and v:
        if not all(isinstance(i, str) for i in v):
            raise RuleError(f"{op} list must hold strings")
        return list(v)
    raise RuleError(f"{op} takes a string or a non-empty list of strings")


def group_key(event: Any, fields: list[list[str]]) -> str:
    parts = []
    for f in fields:
        vals = resolve(event, f)
        s = scalar_string(vals[0]) if vals else None
        parts.append(s or "")
    return "\x1f".join(parts)


@dataclass
class Rule:
    """A compiled rule."""

    id: str
    title: str
    severity: str
    description: str
    owasp: list[str]
    mitre: list[str]
    falsepositives: list[str]
    references: list[str]
    enabled: bool
    mode: str | None
    detection_type: str
    condition: Condition | None = None
    steps: list[Condition] = field(default_factory=list)
    by: list[list[str]] = field(default_factory=list)
    within_ms: int = 0
    count: int = 0
    distinct: list[str] | None = None
    value: list[str] = field(default_factory=list)
    source: str = ""

    @staticmethod
    def from_value(v: Any) -> Rule:
        if not isinstance(v, dict):
            raise RuleError("rule must be a mapping")
        rid = v.get("id")
        if not isinstance(rid, str) or not rid.strip():
            raise RuleError("rule is missing 'id'")
        for k in v:
            if k not in KNOWN_RULE_KEYS:
                raise RuleError(f"rule {rid}: unknown key '{k}'")
        title = v.get("title")
        if not isinstance(title, str):
            raise RuleError(f"rule {rid}: missing 'title'")
        sev = v.get("severity")
        if not isinstance(sev, str) or sev.lower() not in SEVERITIES:
            raise RuleError(f"rule {rid}: missing or invalid 'severity'")

        def strings(key: str) -> list[str]:
            val = v.get(key)
            if val is None:
                return []
            if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
                raise RuleError(f"rule {rid}: '{key}' must be a list of strings")
            return list(val)

        enabled = v.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RuleError(f"rule {rid}: 'enabled' must be a boolean")
        mode = v.get("mode")
        if mode is not None and mode not in MODES:
            raise RuleError(f"rule {rid}: unknown mode {mode!r}")
        det = v.get("detection")
        if not isinstance(det, dict):
            raise RuleError(f"rule {rid}: missing 'detection'")
        rule = Rule(
            id=rid,
            title=title,
            severity=sev.lower(),
            description=str(v.get("description") or "").strip(),
            owasp=strings("owasp"),
            mitre=strings("mitre"),
            falsepositives=strings("falsepositives"),
            references=strings("references"),
            enabled=enabled,
            mode=mode,
            detection_type="event",
        )
        strings("tags")
        try:
            _parse_detection(rule, det)
        except RuleError as exc:
            raise RuleError(f"rule {rid}: {exc}") from exc
        return rule


def _paths(det: dict[str, Any]) -> list[list[str]]:
    by = det.get("by")
    if by is None:
        return []
    if isinstance(by, str):
        return [by.split(".")]
    if isinstance(by, list) and all(isinstance(x, str) for x in by):
        return [x.split(".") for x in by]
    raise RuleError("'by' must list field paths")


def _within(det: dict[str, Any]) -> int:
    w = det.get("within")
    if not isinstance(w, str):
        raise RuleError("missing 'within' (e.g. 60s)")
    ms = parse_duration_ms(w)
    if ms is None:
        raise RuleError(f"bad duration {w!r}")
    return ms


def _where(det: dict[str, Any]) -> Condition:
    if "where" not in det:
        raise RuleError("missing 'where'")
    return Condition.parse(det["where"])


def _check_keys(det: dict[str, Any], allowed: tuple[str, ...]) -> None:
    for k in det:
        if k != "type" and k not in allowed:
            raise RuleError(f"unknown detection key '{k}'")


def _parse_detection(rule: Rule, det: dict[str, Any]) -> None:
    ty = det.get("type", "event")
    rule.detection_type = ty
    if ty == "event":
        _check_keys(det, ("where",))
        rule.condition = _where(det)
    elif ty == "sequence":
        _check_keys(det, ("by", "within", "steps"))
        steps = det.get("steps")
        if not isinstance(steps, list):
            raise RuleError("sequence needs 'steps'")
        if len(steps) < 2:
            raise RuleError("sequence needs at least two steps")
        for s in steps:
            if not isinstance(s, dict):
                raise RuleError("step must be a mapping")
            for k in s:
                if k not in ("where", "name"):
                    raise RuleError(f"unknown step key '{k}'")
            rule.steps.append(_where(s))
        rule.by = _paths(det)
        rule.within_ms = _within(det)
    elif ty == "threshold":
        _check_keys(det, ("where", "by", "within", "count", "distinct"))
        count = det.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise RuleError("threshold needs 'count' >= 1")
        distinct = det.get("distinct")
        if distinct is not None and not isinstance(distinct, str):
            raise RuleError("'distinct' must be a field path")
        rule.condition = _where(det)
        rule.by = _paths(det)
        rule.within_ms = _within(det)
        rule.count = count
        rule.distinct = distinct.split(".") if distinct else None
    elif ty == "first_seen":
        _check_keys(det, ("where", "by", "value"))
        value = det.get("value")
        if not isinstance(value, str):
            raise RuleError("first_seen needs 'value'")
        rule.condition = _where(det)
        rule.by = _paths(det)
        rule.value = value.split(".")
    else:
        raise RuleError(f"unknown detection type {ty!r}")


def parse_rules(text: str, origin: str = "<inline>") -> list[Rule]:
    """Parses a YAML stream holding one or more rules."""
    out = []
    for doc in split_documents(text):
        try:
            value = load_yaml(doc)
        except yaml.YAMLError as exc:
            raise RuleError(f"YAML error in {origin}: {exc}") from exc
        if value is None:
            continue
        r = Rule.from_value(value)
        r.source = doc
        out.append(r)
    return out


def load_rules(path: Path | str) -> list[Rule]:
    """Loads a rule file, or every *.yaml / *.yml in a directory (sorted)."""
    p = Path(path)
    files = sorted(x for x in p.iterdir() if x.suffix.lower() in (".yaml", ".yml")) if p.is_dir() else [p]
    rules: list[Rule] = []
    for f in files:
        rules.extend(parse_rules(f.read_text(encoding="utf-8"), str(f)))
    seen: set[str] = set()
    for r in rules:
        if r.id in seen:
            raise RuleError(f"duplicate rule id {r.id}")
        seen.add(r.id)
    return rules


@dataclass
class Match:
    rule: str
    events: list[int]
    ts: int
    group: str | None = None


@dataclass
class _Chain:
    next: int
    start: int
    events: list[int]


class RuleEngine:
    """Evaluates rules over an ordered event stream (same contract as Rust)."""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules
        self.state: list[dict[str, Any]] = [{} for _ in rules]

    def process(self, event: dict[str, Any]) -> list[Match]:
        eid = int(event.get("id") or 0)
        ts = int(event.get("ts") or 0)
        out: list[Match] = []
        for rule, state in zip(self.rules, self.state, strict=True):
            if not rule.enabled:
                continue
            dt = rule.detection_type
            if dt == "event":
                assert rule.condition is not None
                if rule.condition.eval(event):
                    out.append(Match(rule.id, [eid], ts))
            elif dt == "sequence":
                self._sequence(rule, state, event, eid, ts, out)
            elif dt == "threshold":
                self._threshold(rule, state, event, eid, ts, out)
            elif dt == "first_seen":
                self._first_seen(rule, state, event, eid, ts, out)
        return out

    @staticmethod
    def _room(groups: dict[str, Any], key: str) -> None:
        if key not in groups and len(groups) >= MAX_GROUPS:
            groups.pop(next(iter(groups)))

    def _sequence(self, rule: Rule, groups: dict[str, Any], event: dict[str, Any], eid: int, ts: int, out: list[Match]) -> None:
        matches = [s.eval(event) for s in rule.steps]
        if not any(matches):
            return
        key = group_key(event, rule.by)
        self._room(groups, key)
        chains: list[_Chain] = [c for c in groups.get(key, []) if ts - c.start <= rule.within_ms]
        completed = None
        for c in chains:
            if matches[c.next]:
                c.events.append(eid)
                c.next += 1
                if c.next == len(rule.steps):
                    completed = list(c.events)
                    break
        if completed is not None:
            groups.pop(key, None)
            out.append(Match(rule.id, completed, ts, key))
            return
        if matches[0]:
            chains.append(_Chain(1, ts, [eid]))
            if len(chains) > MAX_CHAINS:
                chains.pop(0)
        if chains:
            groups[key] = chains
        else:
            groups.pop(key, None)

    def _threshold(self, rule: Rule, groups: dict[str, Any], event: dict[str, Any], eid: int, ts: int, out: list[Match]) -> None:
        assert rule.condition is not None
        if not rule.condition.eval(event):
            return
        dval: str | None = None
        if rule.distinct is not None:
            vals = resolve(event, rule.distinct)
            s = scalar_string(vals[0]) if vals else None
            if s is None:
                return
            dval = s.lower()
        key = group_key(event, rule.by)
        self._room(groups, key)
        window: deque[tuple[int, int, str | None]] = groups.setdefault(key, deque())
        window.append((ts, eid, dval))
        while window and ts - window[0][0] > rule.within_ms:
            window.popleft()
        while len(window) > MAX_WINDOW:
            window.popleft()
        n = len({d for _, _, d in window if d is not None}) if rule.distinct is not None else len(window)
        if n >= rule.count:
            ids = [i for _, i, _ in window]
            groups.pop(key, None)
            out.append(Match(rule.id, ids, ts, key))

    def _first_seen(self, rule: Rule, groups: dict[str, Any], event: dict[str, Any], eid: int, ts: int, out: list[Match]) -> None:
        assert rule.condition is not None
        if not rule.condition.eval(event):
            return
        vals = resolve(event, rule.value)
        s = scalar_string(vals[0]) if vals else None
        if s is None:
            return
        key = group_key(event, rule.by)
        self._room(groups, key)
        seen: set[str] = groups.setdefault(key, set())
        if s.lower() not in seen:
            seen.add(s.lower())
            out.append(Match(rule.id, [eid], ts, key))


def run_rules(rules: list[Rule], events: list[dict[str, Any]]) -> list[Match]:
    """Runs rules over events sorted by id."""
    engine = RuleEngine(rules)
    out: list[Match] = []
    for e in sorted(events, key=lambda x: int(x.get("id") or 0)):
        out.extend(engine.process(e))
    return out
