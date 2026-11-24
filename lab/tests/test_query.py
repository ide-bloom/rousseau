"""Hunt query language: parser, compiler and property tests against a
reference evaluator."""

from __future__ import annotations

import re
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rousseau_lab.query import Node, QueryError, events_frame, flatten, hunt, parse

EVENTS: list[dict[str, Any]] = [
    {"id": 1, "kind": "file.read", "process": {"name": "python.exe", "pid": 10}, "file": {"path": r"C:\Users\a\.ssh\id_rsa"}},
    {"id": 2, "kind": "net.connect", "process": {"name": "curl.exe", "pid": 11}, "net": {"remote_port": 443, "remote_scope": "public"}},
    {"id": 3, "kind": "file.write", "process": {"name": "node.exe", "pid": 12}, "file": {"path": r"C:\repo\a.js"}},
    {"id": 4, "kind": "mcp.finding", "finding": {"severity": "high", "inspector": "unicode"}},
]


def ids(q: str) -> list[int]:
    return [int(x) for x in hunt(EVENTS, q)["id"].to_list()]


def test_operators() -> None:
    assert ids("kind = 'FILE.READ'") == [1]
    assert ids("kind != 'file.read'") == [2, 3, 4]
    assert ids("file.path ~ '.SSH'") == [1]
    assert ids("file.path !~ 'ssh'") == [3]
    assert ids("file.path =~ 'a\\.js$'") == [3]
    assert ids("net.remote_port >= 443") == [2]
    assert ids("net.remote_port < 443") == []
    assert ids("process.name in ['curl.exe', 'node.exe']") == [2, 3]
    assert ids("finding exists") == []  # nested dicts become dotted columns
    assert ids("finding.inspector exists") == [4]
    assert ids("not file.path exists") == [2, 4]
    assert ids("(kind ~ 'file' and not process.name = 'node.exe') or net.remote_port = 443") == [1, 2]
    assert ids("missing.field = 'x'") == []


@pytest.mark.parametrize("bad", ["", "kind =", "kind = 'x' and", "(kind = 'x'", "kind ?? 'x'", "kind in 'x'", "= 'x'"])
def test_syntax_errors(bad: str) -> None:
    with pytest.raises(QueryError):
        parse(bad)


def test_flatten_and_frame() -> None:
    assert flatten({"a": {"b": 1, "c": [1, 2]}}) == {"a.b": 1, "a.c": "[1, 2]"}
    df = events_frame([{"x": 1}, {"x": "a"}, {"y": True}])
    assert df["x"].to_list() == ["1", "a", None]
    assert df["y"].to_list() == [None, None, "true"]


# ---------------------------------------------------------------- properties

FIELDS = ["kind", "name", "port"]
STRS = ["alpha", "Beta", "gamma", "delta", ""]


def ref_eval(node: Node, e: dict[str, Any]) -> bool:
    """Reference semantics, written independently of the polars compiler."""
    kind = node[0]
    if kind == "and":
        return ref_eval(node[1], e) and ref_eval(node[2], e)
    if kind == "or":
        return ref_eval(node[1], e) or ref_eval(node[2], e)
    if kind == "not":
        return not ref_eval(node[1], e)
    if kind == "exists":
        return e.get(node[1]) is not None
    _, f, op, v = node
    x = e.get(f)
    if x is None:
        return False
    if op in ("=", "!=", "in"):
        vals = v if op == "in" else [v]

        def eq(a: Any, b: Any) -> bool:
            if isinstance(b, (int, float)) and not isinstance(b, bool):
                try:
                    return float(a) == float(b)
                except (TypeError, ValueError):
                    return False
            return str(a).lower() == str(b).lower()

        hit = any(eq(x, w) for w in vals)
        return not hit if op == "!=" else hit
    if op in ("~", "!~"):
        hit = str(v).lower() in str(x).lower()
        return not hit if op == "!~" else hit
    if op == "=~":
        return re.search(str(v), str(x), re.IGNORECASE) is not None
    try:
        n = float(x)
    except (TypeError, ValueError):
        return False
    return bool({">": n > v, ">=": n >= v, "<": n < v, "<=": n <= v}[op])


def _literal(v: Any) -> str:
    return str(v) if isinstance(v, (int, float)) else "'" + str(v) + "'"


@st.composite
def comparisons(draw: st.DrawFn) -> tuple[str, Node]:
    f = draw(st.sampled_from(FIELDS))
    if f == "port":
        op = draw(st.sampled_from(["=", "!=", ">", ">=", "<", "<="]))
        v: Any = draw(st.integers(0, 100))
    else:
        op = draw(st.sampled_from(["=", "!=", "~", "!~"]))
        v = draw(st.sampled_from(STRS[:-1]))
    if draw(st.booleans()) and f != "port":
        vals = draw(st.lists(st.sampled_from(STRS[:-1]), min_size=1, max_size=3))
        return f"{f} in [{', '.join(_literal(x) for x in vals)}]", ("cmp", f, "in", vals)
    if draw(st.integers(0, 9)) == 0:
        return f"{f} exists", ("exists", f)
    return f"{f} {op} {_literal(v)}", ("cmp", f, op, v)


def expressions() -> st.SearchStrategy[tuple[str, Node]]:
    return st.recursive(
        comparisons(),
        lambda inner: st.one_of(
            st.tuples(inner, inner).map(lambda p: (f"({p[0][0]}) and ({p[1][0]})", ("and", p[0][1], p[1][1]))),
            st.tuples(inner, inner).map(lambda p: (f"({p[0][0]}) or ({p[1][0]})", ("or", p[0][1], p[1][1]))),
            inner.map(lambda p: (f"not ({p[0]})", ("not", p[1]))),
        ),
        max_leaves=6,
    )


events_st = st.lists(
    st.fixed_dictionaries({}, optional={"kind": st.sampled_from(STRS), "name": st.sampled_from(STRS), "port": st.integers(0, 100)}),
    min_size=1,
    max_size=12,
)


@settings(max_examples=150, deadline=None)
@given(expr=expressions(), events=events_st)
def test_compiler_matches_reference(expr: tuple[str, Node], events: list[dict[str, Any]]) -> None:
    src, ast = expr
    assert parse(src) == ast
    rows = [{"id": i, **e} for i, e in enumerate(events)]
    got = [int(x) for x in hunt(rows, src)["id"].to_list()]
    want = [r["id"] for r in rows if ref_eval(ast, r)]
    assert got == want, src
