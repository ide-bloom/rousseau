"""Every CLI command, end to end, on synthetic bundles."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from rousseau_lab.bundle import BundleError, read_bundle, write_bundle
from rousseau_lab.cli import app
from rousseau_lab.report import build_context
from rousseau_lab.rules import load_rules, run_rules
from rousseau_lab.synth import SCENARIOS, generate

runner = CliRunner()


def synth(tmp_path: Path, scenario: str = "all") -> Path:
    out = tmp_path / f"{scenario}.rousseau"
    r = runner.invoke(app, ["synth", "--scenario", scenario, "-o", str(out)])
    assert r.exit_code == 0, r.output
    return out


def test_synth_is_deterministic(tmp_path: Path) -> None:
    a, _ = generate("all", seed=3)
    b, _ = generate("all", seed=3)
    assert a == b
    c, _ = generate("all", seed=4)
    assert a != c


@pytest.mark.parametrize("scenario", [s for s in SCENARIOS if s != "benign"])
def test_synth_labels_fire_builtin_rules(scenario: str, repo: Path) -> None:
    events, manifest = generate(scenario)
    rules = load_rules(repo / "rules")
    fired = {m.rule for m in run_rules(rules, events)}
    for label in manifest["labels"]:
        assert label["rule"] in fired, f"{scenario}: {label['rule']} ({label['description']}) did not fire"


def test_benign_is_quiet(repo: Path) -> None:
    events, _ = generate("benign")
    assert run_rules(load_rules(repo / "rules"), events) == []


def test_load_and_report(tmp_path: Path) -> None:
    b = synth(tmp_path, "poisoned-server")
    r = runner.invoke(app, ["load", str(b)])
    assert r.exit_code == 0, r.output
    assert "mcp.finding" in r.output and "Attribution" in r.output
    out = tmp_path / "report.html"
    r = runner.invoke(app, ["report", str(b), "-o", str(out)])
    assert r.exit_code == 0, r.output
    html = out.read_text(encoding="utf-8")
    assert "Causal tree" in html and "Hidden Unicode Tags characters" in html
    assert "<script src" not in html and "http://" not in html.replace("http://127.0.0.1", "")
    # Attacker-controlled text is escaped.
    events, manifest = generate("benign")
    events[1]["transcript"]["command"] = "<img src=x onerror=alert(1)>"
    evil = tmp_path / "evil.rousseau"
    write_bundle(evil, events, manifest)
    runner.invoke(app, ["report", str(evil), "-o", str(out)])
    assert "<img src=x" not in out.read_text(encoding="utf-8")


def test_report_context_tree(tmp_path: Path) -> None:
    ctx = build_context(read_bundle(synth(tmp_path, "credential-exfil")))
    labels = [n.label for n in ctx["tree"]]
    assert any(label.startswith("Bash") for label in labels)
    intent = next(n for n in ctx["tree"] if "credentials" in n.label)
    assert intent.children[0].kind == "process"
    assert intent.children[0].children[0].label.startswith("file.read")


def test_test_rule_hits_and_misses(tmp_path: Path, repo: Path) -> None:
    b = synth(tmp_path, "credential-exfil")
    r = runner.invoke(app, ["test-rule", str(repo / "rules" / "credential-access.yaml"), "--against", str(b)])
    assert r.exit_code == 0, r.output
    assert "hit" in r.output and "ROU-006" in r.output
    # A rule that never fires reports a miss for a labelled sequence.
    weak = tmp_path / "weak.yaml"
    weak.write_text("id: ROU-006\ntitle: t\nseverity: low\ndetection: {where: {field: kind, equals: never}}\n", encoding="utf-8")
    r = runner.invoke(app, ["test-rule", str(weak), "--against", str(b)])
    assert r.exit_code == 1
    assert "miss" in r.output
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: x\n", encoding="utf-8")
    assert runner.invoke(app, ["test-rule", str(bad), "--against", str(b)]).exit_code == 2


def test_hunt(tmp_path: Path) -> None:
    b = synth(tmp_path, "all")
    r = runner.invoke(app, ["hunt", str(b), "-q", "kind = 'file.read' and file.path ~ '.aws'", "--columns", "id,kind,file.path"])
    assert r.exit_code == 0, r.output
    assert "1 match" in r.output and "credentials" in r.output
    assert runner.invoke(app, ["hunt", str(b), "-q", "kind ="]).exit_code == 2


def test_scenarios_and_version() -> None:
    assert "poisoned-server" in runner.invoke(app, ["scenarios"]).output
    assert runner.invoke(app, ["--version"]).output.startswith("rousseau-lab")
    assert runner.invoke(app, ["synth", "--scenario", "nope", "-o", "x"]).exit_code == 2


def test_bundle_errors(tmp_path: Path) -> None:
    p = tmp_path / "x.rousseau"
    p.write_bytes(b"not zstd")
    with pytest.raises(BundleError):
        read_bundle(p)
    write_bundle(p, [], {"format": "other"})
    with pytest.raises(BundleError):
        read_bundle(p)
    write_bundle(p, [], {"schema_version": 99})
    with pytest.raises(BundleError):
        read_bundle(p)
    assert runner.invoke(app, ["load", str(p)]).exit_code == 2


def test_bundle_round_trip(tmp_path: Path) -> None:
    events, manifest = generate("persistence")
    p = tmp_path / "p.rousseau"
    write_bundle(p, events, manifest)
    b = read_bundle(p)
    assert b.raw == events
    assert b.manifest.labels[0].rule
    assert b.events[0].kind == "session.start"
