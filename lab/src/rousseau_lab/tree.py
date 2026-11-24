"""Causal tree: intent (tool call) → action (processes) → effects.

Mirrors ``rousseau-server``'s ``tree::build_session_tree`` so offline reports
show the same structure as the live dashboard.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from rousseau_lab.models import severity_rank


@dataclass
class TreeNode:
    kind: str  # intent | process | effect
    label: str
    ts: int
    event_id: int | None = None
    severity: str | None = None
    detail: str | None = None
    children: list[TreeNode] = field(default_factory=list)

    def max_severity(self) -> str | None:
        best = self.severity
        for c in self.children:
            s = c.max_severity()
            if s and severity_rank(s) > severity_rank(best):
                best = s
        return best


def _t(value: Any, n: int = 200) -> str:
    s = "" if value is None else str(value)
    return s if len(s) <= n else s[:n] + "…"


def summarize(e: dict[str, Any]) -> str:
    """One-line summary of a raw event."""
    k = e.get("kind", "")
    p = e.get("process") or {}
    m = e.get("mcp") or {}
    if k == "process.start":
        return f"{p.get('name', '?')} (pid {p.get('pid')}) {_t(p.get('command_line') or p.get('image'))}"
    if k == "process.stop":
        return f"{p.get('name', '?')} (pid {p.get('pid')}) exited"
    if k.startswith("file.") or k == "image.load":
        f = e.get("file") or {}
        return f"{k} {f.get('path', '')}" + (f" → {f['new_path']}" if f.get("new_path") else "")
    if k in ("net.connect", "net.accept", "net.close"):
        n = e.get("net") or {}
        extra = f" ({n.get('bytes_sent', 0)} B out, {n.get('bytes_recv', 0)} B in)" if n.get("bytes_sent") is not None else ""
        return f"{k} {n.get('protocol', '')} {n.get('remote', '')}{extra}"
    if k == "dns.query":
        return f"dns {(e.get('dns') or {}).get('query', '')}"
    if k.startswith("registry."):
        r = e.get("registry") or {}
        return f"{k} {r.get('key', '')}\\{r.get('value') or ''} = {_t(r.get('data'), 120)}"
    if k == "mcp.call":
        return f"{m.get('server')}.{m.get('tool')}({_t(json.dumps(m.get('arguments') or {}), 160)})"
    if k == "mcp.result":
        return f"result{' (error)' if m.get('is_error') else ''} in {m.get('duration_ms', 0)} ms"
    if k == "mcp.blocked":
        return f"BLOCKED: {m.get('blocked_reason', '')}"
    if k == "mcp.finding":
        f = e.get("finding") or {}
        return f"{f.get('title', '')}: {_t(f.get('detail'))}"
    if k == "mcp.drift":
        d = e.get("drift") or {}
        return f"tool {d.get('tool')} {d.get('change')}"
    if k == "transcript.tool_use":
        t = e.get("transcript") or {}
        return f"{t.get('tool')} {_t(t.get('command') or json.dumps(t.get('input') or ''))}"
    if k.startswith("mcp."):
        return f"{k} {m.get('method') or ''}"
    return str(k)


def _leaf(e: dict[str, Any]) -> TreeNode:
    return TreeNode("effect", summarize(e), int(e.get("ts", 0)), e.get("id"), e.get("severity"), e.get("kind"))


def build_tree(events: list[dict[str, Any]]) -> list[TreeNode]:
    """Builds the causal tree for one session's events (sorted by id)."""
    order: list[str] = []
    intents: dict[str, TreeNode] = {}
    procs: dict[str, dict[int, TreeNode]] = {}
    parents: dict[int, int] = {}
    proc_intent: dict[int, str] = {}

    def ensure(key: str, label: str, ts: int, detail: str) -> None:
        if key not in intents:
            intents[key] = TreeNode("intent", label, ts, detail=detail)
            order.append(key)

    for e in sorted(events, key=lambda x: int(x.get("id") or 0)):
        kind = e.get("kind", "")
        if kind in ("session.start", "session.end", "sensor.health"):
            continue
        attr = e.get("attribution") or {}
        call = attr.get("tool_call")
        if kind in ("mcp.call", "transcript.tool_use"):
            key = call or f"event-{e.get('id')}"
            ensure(key, summarize(e), int(e.get("ts", 0)), "mcp" if kind == "mcp.call" else "transcript")
            intents[key].event_id = e.get("id")
            continue
        if call:
            key = call
        else:
            srv = (e.get("mcp") or {}).get("server") or (e.get("finding") or {}).get("server") or (e.get("drift") or {}).get("server")
            key = f"server:{srv}" if srv and kind.startswith("mcp.") else "unexplained"
        if key not in intents:
            if key == "unexplained":
                ensure(key, "Unexplained activity (no tool call attributed)", int(e.get("ts", 0)), "unexplained")
            elif key.startswith("server:"):
                ensure(key, f"MCP server {key[7:]}", int(e.get("ts", 0)), "mcp")
            else:
                ensure(key, f"Tool call {key}", int(e.get("ts", 0)), "mcp")
        pid = (e.get("process") or {}).get("pid")
        if kind == "process.start" and pid is not None:
            procs.setdefault(key, {})[pid] = TreeNode("process", summarize(e), int(e.get("ts", 0)), e.get("id"), detail=attr.get("method"))
            ppid = (e.get("process") or {}).get("ppid")
            if ppid is not None:
                parents[pid] = ppid
            proc_intent[pid] = key
            continue
        target = procs.get(key, {}).get(pid) if pid is not None and proc_intent.get(pid) == key else None
        (target or intents[key]).children.append(_leaf(e))

    for key, nodes in procs.items():

        def depth(pid: int, pids: set[int] = set(nodes)) -> int:  # noqa: B006 (bound per loop)
            d, cur = 0, pid
            while cur in parents and parents[cur] in pids and d <= 64:
                cur, d = parents[cur], d + 1
            return d

        for pid in sorted(nodes, key=depth, reverse=True):
            pp = parents.get(pid)
            if pp is not None and pp != pid and pp in nodes and pid in nodes:
                nodes[pp].children.append(nodes.pop(pid))
        intents[key].children.extend(sorted(nodes.values(), key=lambda n: n.ts))
        intents[key].children.sort(key=lambda n: n.ts)
    out = [intents[k] for k in order]
    for n in out:
        n.severity = n.max_severity()
    return out
