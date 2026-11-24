"""The ``rousseau-lab`` command line."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from rousseau_lab import __version__
from rousseau_lab.bundle import Bundle, BundleError, read_bundle, write_bundle
from rousseau_lab.query import QueryError
from rousseau_lab.query import hunt as run_hunt
from rousseau_lab.report import write_report
from rousseau_lab.rules import RuleError, load_rules, run_rules
from rousseau_lab.synth import SCENARIOS, generate

app = typer.Typer(help="Offline analysis of Rousseau sessions.", no_args_is_help=True, add_completion=False)
console = Console()


def _version(value: bool) -> None:
    if value:
        console.print(f"rousseau-lab {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")] = False,
) -> None:
    """rousseau-lab: reports, rule testing, hunting and synthetic sessions."""


def _load(path: Path) -> Bundle:
    try:
        return read_bundle(path)
    except BundleError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc


@app.command()
def load(bundle: Annotated[Path, typer.Argument(help="A .rousseau bundle.")]) -> None:
    """Print summary statistics for a bundle."""
    b = _load(bundle)
    m = b.manifest
    console.print(f"[bold]{bundle}[/bold]  schema v{m.schema_version}  produced by {m.producer or 'rousseau'} {m.rousseau_version}")
    if m.session:
        console.print(f"session [cyan]{m.session.get('id')}[/cyan]  agent {m.session.get('agent')}  cwd {m.session.get('cwd')}")
    t = Table(title="Events by kind")
    t.add_column("kind")
    t.add_column("count", justify="right")
    for kind, n in Counter(e.get("kind", "?") for e in b.raw).most_common():
        t.add_row(kind, str(n))
    console.print(t)
    attr = Counter((e.get("attribution") or {}).get("kind") for e in b.raw if e.get("attribution"))
    a = Table(title="Attribution")
    a.add_column("kind")
    a.add_column("events", justify="right")
    for k, n in attr.most_common():
        a.add_row(str(k), str(n))
    console.print(a)
    procs = Counter((e.get("process") or {}).get("name") for e in b.raw if e.get("kind") == "process.start")
    if procs:
        p = Table(title="Top processes started")
        p.add_column("image")
        p.add_column("starts", justify="right")
        for name, n in procs.most_common(10):
            p.add_row(str(name), str(n))
        console.print(p)
    servers = Counter((e.get("mcp") or {}).get("server") for e in b.raw if e.get("mcp"))
    if servers:
        s = Table(title="MCP servers")
        s.add_column("server")
        s.add_column("events", justify="right")
        for name, n in servers.most_common():
            s.add_row(str(name), str(n))
        console.print(s)
    i = Table(title=f"Incidents ({len(m.incidents)})")
    for col in ("severity", "rule", "title", "count"):
        i.add_column(col)
    for inc in m.incidents:
        i.add_row(inc.severity, inc.rule_id, inc.title, str(inc.count))
    console.print(i)


@app.command()
def report(
    bundle: Annotated[Path, typer.Argument(help="A .rousseau bundle.")],
    output: Annotated[Path, typer.Option("-o", "--output", help="HTML file to write.")] = Path("report.html"),
) -> None:
    """Write a self-contained offline HTML incident report."""
    b = _load(bundle)
    write_report(b, output)
    console.print(f"wrote [bold]{output}[/bold] ({len(b.raw)} events, {len(b.manifest.incidents)} incidents)")


@app.command("test-rule")
def test_rule(
    rule: Annotated[Path, typer.Argument(help="Rule file (or directory of rules).")],
    against: Annotated[list[Path], typer.Option("--against", help="Bundles to evaluate (repeatable).")],
) -> None:
    """Run rules against recorded sessions and print hits and misses.

    Misses are reported for bundles carrying ground-truth labels (synth output).
    """
    try:
        rules = load_rules(rule)
    except (RuleError, OSError) as exc:
        console.print(f"[red]invalid rule:[/red] {exc}")
        raise typer.Exit(2) from exc
    ids = {r.id for r in rules}
    missed = 0
    for path in against:
        b = _load(path)
        matches = run_rules(rules, b.raw)
        by_id = {e.get("id"): e for e in b.raw}
        t = Table(title=f"{path}: {len(matches)} hit(s)")
        for col in ("rule", "events", "first event"):
            t.add_column(col)
        for m in matches:
            first = by_id.get(m.events[0], {})
            t.add_row(
                m.rule, ",".join(map(str, m.events[:8])) + ("…" if len(m.events) > 8 else ""), f"{first.get('kind')} {first.get('id')}"
            )
        console.print(t)
        hit_rules = {m.rule for m in matches}
        for label in b.manifest.labels:
            if label.rule not in ids:
                continue
            if label.rule in hit_rules:
                console.print(f"  [green]hit[/green]   {label.rule}: {label.description}")
            else:
                missed += 1
                console.print(f"  [red]miss[/red]  {label.rule}: {label.description} (events {label.events[:5]})")
    if missed:
        raise typer.Exit(1)


@app.command()
def hunt(
    bundles: Annotated[list[Path], typer.Argument(help="Bundles to search.")],
    query: Annotated[str, typer.Option("--query", "-q", help="Filter expression, e.g. \"kind = 'file.read' and file.path ~ '.ssh'\".")],
    columns: Annotated[str, typer.Option(help="Comma-separated columns to show.")] = "id,kind,session,process.name,summary",
    limit: Annotated[int, typer.Option(help="Maximum rows to print.")] = 100,
) -> None:
    """Search events with a small filter language (compiled to polars)."""
    from rousseau_lab.tree import summarize

    events = []
    for p in bundles:
        b = _load(p)
        for e in b.raw:
            events.append({**e, "summary": summarize(e), "bundle": p.name})
    try:
        result = run_hunt(events, query)
    except QueryError as exc:
        console.print(f"[red]query error:[/red] {exc}")
        raise typer.Exit(2) from exc
    cols = [c.strip() for c in columns.split(",") if c.strip()]
    t = Table(title=f"{result.height} match(es)")
    for c in cols:
        t.add_column(c)
    for row in result.head(limit).iter_rows(named=True):
        t.add_row(*[str(row.get(c, "")) if row.get(c) is not None else "" for c in cols])
    console.print(t)


@app.command()
def synth(
    scenario: Annotated[str, typer.Option(help=f"One of: {', '.join(SCENARIOS)}.")],
    output: Annotated[Path, typer.Option("-o", "--output", help="Bundle to write.")],
    seed: Annotated[int, typer.Option(help="Random seed (output is deterministic per seed).")] = 7,
) -> None:
    """Generate a synthetic session (no code is executed; events are fabricated)."""
    try:
        events, manifest = generate(scenario, seed)
    except ValueError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc
    write_bundle(output, events, manifest)
    console.print(f"wrote [bold]{output}[/bold]: {len(events)} events, {len(manifest['labels'])} labelled sequence(s)")


@app.command()
def scenarios() -> None:
    """List synthetic scenarios."""
    for name, desc in SCENARIOS.items():
        console.print(f"[bold]{name}[/bold]: {desc}")
