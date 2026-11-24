"""Shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def repo() -> Path:
    """Repository root (for conformance cases and built-in rules)."""
    return REPO
