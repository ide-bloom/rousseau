"""The ``hunt`` filter language, compiled to polars expressions.

Grammar::

    expr     := or
    or       := and ("or" and)*
    and      := unary ("and" unary)*
    unary    := "not" unary | "(" expr ")" | compare
    compare  := FIELD OP VALUE | FIELD "exists"
    OP       := "=" | "!=" | "~" | "!~" | "=~" | ">" | ">=" | "<" | "<=" | "in"
    VALUE    := 'single' | "double" | NUMBER | true | false | "[" VALUE ("," VALUE)* "]"
    FIELD    := dotted path, e.g. process.name, file.path, kind

Semantics: ``=``/``!=``/``in`` compare case-insensitively for strings;
``~`` is a case-insensitive substring match (``!~`` its negation); ``=~`` a
case-insensitive regular expression search; ``>``/``<`` compare numbers. A
missing field never satisfies a comparison (``!=`` and ``!~`` included);
use ``not`` for "anything else including missing".

Events are flattened into a DataFrame with one column per dotted path
(:func:`events_frame`).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import polars as pl

TOKEN = re.compile(
    r"""\s*(?:
        (?P<lp>\() | (?P<rp>\)) | (?P<lb>\[) | (?P<rb>\]) | (?P<comma>,) |
        (?P<op>!=|>=|<=|=~|!~|=|~|>|<) |
        (?P<str>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*") |
        (?P<num>-?\d+(?:\.\d+)?(?![\w.])) |
        (?P<word>[A-Za-z_][\w.\-]*)
    )""",
    re.VERBOSE,
)


class QueryError(ValueError):
    """Syntax error in a hunt query."""


@dataclass
class Tok:
    kind: str
    text: str
    value: Any = None


def tokenize(src: str) -> list[Tok]:
    pos, out = 0, []
    src = src.rstrip()
    while pos < len(src):
        m = TOKEN.match(src, pos)
        if not m or m.end() == pos:
            raise QueryError(f"unexpected character at {pos}: {src[pos : pos + 10]!r}")
        pos = m.end()
        kind = m.lastgroup or ""
        text = m.group(kind)
        if kind == "str":
            out.append(Tok("value", text, re.sub(r"\\(.)", r"\1", text[1:-1])))
        elif kind == "num":
            out.append(Tok("value", text, float(text) if "." in text else int(text)))
        elif kind == "word" and text.lower() in ("and", "or", "not", "in", "exists"):
            out.append(Tok(text.lower(), text))
        elif kind == "word" and text.lower() in ("true", "false"):
            out.append(Tok("value", text, text.lower() == "true"))
        else:
            out.append(Tok(kind, text))
    return out


# AST: ("and", a, b) | ("or", a, b) | ("not", a) | ("cmp", field, op, value) | ("exists", field)
Node = tuple[Any, ...]


class _Parser:
    def __init__(self, toks: list[Tok]) -> None:
        self.t, self.i = toks, 0

    def peek(self) -> Tok | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, kind: str) -> Tok:
        tok = self.peek()
        if tok is None or tok.kind != kind:
            raise QueryError(f"expected {kind}, got {tok.text if tok else 'end of query'}")
        self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.or_()
        if self.peek() is not None:
            raise QueryError(f"unexpected {self.peek().text!r}")  # type: ignore[union-attr]
        return node

    def or_(self) -> Node:
        node = self.and_()
        while (p := self.peek()) and p.kind == "or":
            self.i += 1
            node = ("or", node, self.and_())
        return node

    def and_(self) -> Node:
        node = self.unary()
        while (p := self.peek()) and p.kind == "and":
            self.i += 1
            node = ("and", node, self.unary())
        return node

    def unary(self) -> Node:
        p = self.peek()
        if p is None:
            raise QueryError("unexpected end of query")
        if p.kind == "not":
            self.i += 1
            return ("not", self.unary())
        if p.kind == "lp":
            self.i += 1
            node = self.or_()
            self.take("rp")
            return node
        fld = self.take("word").text
        nxt = self.peek()
        if nxt is not None and nxt.kind == "exists":
            self.i += 1
            return ("exists", fld)
        if nxt is not None and nxt.kind == "in":
            self.i += 1
            return ("cmp", fld, "in", self.list_())
        op = self.take("op").text
        return ("cmp", fld, op, self.take("value").value)

    def list_(self) -> list[Any]:
        self.take("lb")
        items = [self.take("value").value]
        while (p := self.peek()) and p.kind == "comma":
            self.i += 1
            items.append(self.take("value").value)
        self.take("rb")
        return items


def parse(src: str) -> Node:
    """Parses a query into an AST."""
    if not src.strip():
        raise QueryError("empty query")
    return _Parser(tokenize(src)).parse()


def _col(fld: str, columns: set[str]) -> pl.Expr:
    return pl.col(fld) if fld in columns else pl.lit(None)


def _lower_str(e: pl.Expr) -> pl.Expr:
    return e.cast(pl.Utf8).str.to_lowercase()


def to_expr(node: Node, columns: set[str]) -> pl.Expr:
    """Compiles an AST to a polars boolean expression (nulls become false)."""
    kind = node[0]
    if kind == "and":
        return to_expr(node[1], columns) & to_expr(node[2], columns)
    if kind == "or":
        return to_expr(node[1], columns) | to_expr(node[2], columns)
    if kind == "not":
        return ~to_expr(node[1], columns)
    if kind == "exists":
        return _col(node[1], columns).is_not_null()
    _, fld, op, value = node
    c = _col(fld, columns)
    expr: pl.Expr
    if op in ("=", "!=", "in"):
        values = value if op == "in" else [value]
        parts = []
        for v in values:
            if isinstance(v, bool):
                parts.append(_lower_str(c) == ("true" if v else "false"))
            elif isinstance(v, (int, float)):
                parts.append(c.cast(pl.Float64, strict=False) == float(v))
            else:
                parts.append(_lower_str(c) == str(v).lower())
        expr = parts[0]
        for p in parts[1:]:
            expr = expr | p
        if op == "!=":
            expr = c.is_not_null() & ~expr
    elif op in ("~", "!~"):
        expr = _lower_str(c).str.contains(str(value).lower(), literal=True)
        if op == "!~":
            expr = c.is_not_null() & ~expr
    elif op == "=~":
        expr = c.cast(pl.Utf8).str.contains("(?i)" + str(value))
    else:
        num = c.cast(pl.Float64, strict=False)
        v = float(value)
        expr = {">": num > v, ">=": num >= v, "<": num < v, "<=": num <= v}[op]
    return expr.fill_null(False)


def compile_query(src: str, columns: set[str]) -> pl.Expr:
    """Parses and compiles a query against a frame with ``columns``."""
    return to_expr(parse(src), columns)


def flatten(event: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flattens nested dicts into dotted keys; lists become JSON strings."""
    out: dict[str, Any] = {}
    for k, v in event.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        elif isinstance(v, list):
            out[key] = json.dumps(v, ensure_ascii=False)
        else:
            out[key] = v
    return out


def events_frame(events: list[dict[str, Any]]) -> pl.DataFrame:
    """One row per event, one column per dotted path. Columns holding only
    numbers stay numeric; everything else is text."""
    rows = [flatten(e) for e in events]
    columns: dict[str, list[Any]] = {}
    for i, r in enumerate(rows):
        for k, v in r.items():
            columns.setdefault(k, [None] * len(rows))[i] = v
    series = []
    for name, values in columns.items():
        non_null = [v for v in values if v is not None]
        if non_null and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in non_null):
            dtype: Any = pl.Int64 if all(isinstance(v, int) for v in non_null) else pl.Float64
            series.append(pl.Series(name, values, dtype=dtype))
        elif non_null and all(isinstance(v, bool) for v in non_null):
            series.append(pl.Series(name, [None if v is None else ("true" if v else "false") for v in values], dtype=pl.Utf8))
        else:
            series.append(
                pl.Series(name, [None if v is None else (v if isinstance(v, str) else json.dumps(v)) for v in values], dtype=pl.Utf8)
            )
    if not series:
        return pl.DataFrame({"id": pl.Series([], dtype=pl.Int64)})
    return pl.DataFrame(series)


def hunt(events: list[dict[str, Any]], src: str) -> pl.DataFrame:
    """Rows of ``events`` matching the query."""
    df = events_frame(events)
    return df.filter(compile_query(src, set(df.columns)))
