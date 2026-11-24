"""Runs the shared conformance suite against the Python rule engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from rousseau_lab.rules import Rule, RuleEngine, RuleError, load_yaml, parse_rules, split_documents

REPO = Path(__file__).resolve().parents[2]
CASES_DIR = REPO / "conformance" / "cases"


def _cases() -> list[tuple[str, dict[str, Any]]]:
    out = []
    for f in sorted(CASES_DIR.glob("*.yaml")):
        for doc in split_documents(f.read_text(encoding="utf-8")):
            case = load_yaml(doc)
            out.append((f"{f.stem}: {case['name']}", case))
    return out


CASES = _cases()


def _rule(case: dict[str, Any]) -> Rule:
    if "rule" in case:
        return Rule.from_value(case["rule"])
    ref = case["rule_ref"]
    rules = parse_rules((REPO / ref["file"]).read_text(encoding="utf-8"), ref["file"])
    return next(r for r in rules if r.id == ref["id"])


def test_suite_is_substantial() -> None:
    assert len(CASES) >= 30


@pytest.mark.parametrize(("name", "case"), CASES, ids=[c[0] for c in CASES])
def test_case(name: str, case: dict[str, Any]) -> None:
    if case.get("invalid"):
        with pytest.raises(RuleError):
            _rule(case)
        return
    engine = RuleEngine([_rule(case)])
    got = [m.events for e in case.get("events") or [] for m in engine.process(e)]
    want = [m["events"] for m in case.get("expected") or []]
    assert got == want, name


def test_builtin_rules_load(repo: Path) -> None:
    from rousseau_lab.rules import load_rules

    rules = load_rules(repo / "rules")
    assert len(rules) >= 25
    assert all(r.owasp and r.mitre for r in rules)
