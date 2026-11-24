"""Pydantic models of the Rousseau event schema (docs/event-schema.md).

Models accept unknown fields (``extra="allow"``) so bundles written by newer
Rousseau versions still load; rules always evaluate the raw JSON form.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SEVERITIES = ("info", "low", "medium", "high", "critical")


def severity_rank(sev: str | None) -> int:
    """0 (info) … 4 (critical); unknown or missing is 0."""
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


class _Open(BaseModel):
    model_config = ConfigDict(extra="allow")


class ProcessInfo(_Open):
    pid: int
    ppid: int | None = None
    image: str | None = None
    name: str | None = None
    command_line: str | None = None
    start_time: int | None = None
    cwd: str | None = None
    signer: str | None = None
    exit_code: int | None = None


class Lineage(_Open):
    agent: str | None = None
    root: str | None = None
    root_pid: int | None = None
    depth: int = 0
    mcp_server: str | None = None
    ancestors: list[str] = Field(default_factory=list)


class Attribution(_Open):
    kind: str = "unexplained"
    tool_call: str | None = None
    tool: str | None = None
    server: str | None = None
    method: str | None = None


class Event(_Open):
    id: int = 0
    ts: int
    kind: str
    session: str | None = None
    severity: str | None = None
    process: ProcessInfo | None = None
    lineage: Lineage | None = None
    attribution: Attribution | None = None
    file: dict[str, Any] | None = None
    net: dict[str, Any] | None = None
    dns: dict[str, Any] | None = None
    registry: dict[str, Any] | None = None
    mcp: dict[str, Any] | None = None
    finding: dict[str, Any] | None = None
    drift: dict[str, Any] | None = None
    transcript: dict[str, Any] | None = None
    sensor: dict[str, Any] | None = None
    session_info: dict[str, Any] | None = None

    def server(self) -> str | None:
        """MCP server this event concerns (MCP section, drift, finding or lineage)."""
        for section, key in ((self.mcp, "server"), (self.drift, "server"), (self.finding, "server")):
            if section and section.get(key):
                return str(section[key])
        return self.lineage.mcp_server if self.lineage else None


class Incident(_Open):
    id: int
    rule_id: str
    title: str
    severity: str
    session: str | None = None
    agent: str | None = None
    first_ts: int
    last_ts: int
    count: int = 1
    status: str = "open"
    mode: str = "observe"
    explanation: str = ""
    owasp: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    evidence: list[int] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)


class Label(_Open):
    """Ground truth written by ``synth``: these events should fire ``rule``."""

    rule: str
    events: list[int]
    description: str = ""


class Manifest(_Open):
    format: str
    schema_version: int
    rousseau_version: str = ""
    created: int = 0
    session: dict[str, Any] | None = None
    event_count: int = 0
    first_ts: int | None = None
    last_ts: int | None = None
    incidents: list[Incident] = Field(default_factory=list)
    servers: list[dict[str, Any]] = Field(default_factory=list)
    pins: list[dict[str, Any]] = Field(default_factory=list)
    producer: str = ""
    labels: list[Label] = Field(default_factory=list)
