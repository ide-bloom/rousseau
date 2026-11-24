"""Self-contained offline HTML incident reports.

The report embeds its CSS and a few lines of JavaScript (tree folding and a
timeline filter). It loads nothing from the network and every value is
HTML-escaped (tool output is attacker-controlled).
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from importlib import resources
from pathlib import Path
from typing import Any

import jinja2

from rousseau_lab import __version__
from rousseau_lab.bundle import Bundle
from rousseau_lab.models import severity_rank
from rousseau_lab.tree import build_tree, summarize


def _fmt_ts(ms: int | None) -> str:
    if not ms:
        return "–"
    return dt.datetime.fromtimestamp(ms / 1000, tz=dt.UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def _env() -> jinja2.Environment:
    loader = jinja2.FunctionLoader(lambda name: resources.files("rousseau_lab").joinpath("templates", name).read_text(encoding="utf-8"))
    env = jinja2.Environment(loader=loader, autoescape=True, trim_blocks=True, lstrip_blocks=True)
    env.filters["ts"] = _fmt_ts
    env.globals["summarize"] = summarize
    return env


def build_context(bundle: Bundle) -> dict[str, Any]:
    """Data passed to the template (exposed for tests)."""
    raw = sorted(bundle.raw, key=lambda e: int(e.get("id") or 0))
    by_id = {e.get("id"): e for e in raw}
    incidents = sorted(bundle.manifest.incidents, key=lambda i: (-severity_rank(i.severity), i.first_ts))
    findings = [e for e in raw if e.get("kind") == "mcp.finding"]
    drift = [e for e in raw if e.get("kind") == "mcp.drift"]
    kinds = Counter(e.get("kind", "?") for e in raw)
    attribution = Counter((e.get("attribution") or {}).get("kind", "none") for e in raw if e.get("attribution"))
    m = bundle.manifest
    return {
        "version": __version__,
        "generated": _fmt_ts(int(dt.datetime.now(tz=dt.UTC).timestamp() * 1000)),
        "manifest": m,
        "session": m.session or {},
        "events": raw,
        "incidents": [{"incident": i, "evidence": [by_id[x] for x in i.evidence if x in by_id]} for i in incidents],
        "findings": findings,
        "drift": drift,
        "tree": build_tree(raw),
        "kinds": kinds.most_common(),
        "attribution": dict(attribution),
        "servers": sorted({s for e in raw if (s := (e.get("mcp") or {}).get("server"))}),
        "max_severity": max((i.severity for i in incidents), key=severity_rank, default=None),
    }


def render_report(bundle: Bundle) -> str:
    """Renders the HTML report."""
    return _env().get_template("report.html.j2").render(**build_context(bundle))


def write_report(bundle: Bundle, out: Path) -> None:
    out.write_text(render_report(bundle), encoding="utf-8")
