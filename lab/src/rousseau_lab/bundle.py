"""Reading and writing ``.rousseau`` bundles (docs/bundle-format.md).

A bundle is one zstd frame of UTF-8 JSON Lines: the manifest first, then one
event per line in id order.
"""

from __future__ import annotations

import io
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import zstandard

from rousseau_lab.models import Event, Manifest

FORMAT = "rousseau-bundle"
SCHEMA_VERSION = 1


class BundleError(Exception):
    """The file is not a readable Rousseau bundle."""


@dataclass
class Bundle:
    """A loaded bundle. ``raw`` keeps each event's JSON exactly as stored."""

    manifest: Manifest
    raw: list[dict[str, Any]]
    path: Path | None = None
    _events: list[Event] | None = field(default=None, repr=False)

    @property
    def events(self) -> list[Event]:
        if self._events is None:
            self._events = [Event.model_validate(e) for e in self.raw]
        return self._events


def read_bundle(path: Path | str) -> Bundle:
    """Reads a bundle file."""
    p = Path(path)
    try:
        data = zstandard.ZstdDecompressor().stream_reader(p.open("rb"))
        text = io.TextIOWrapper(data, encoding="utf-8")
        lines = [line for line in text if line.strip()]
    except (OSError, zstandard.ZstdError) as exc:
        raise BundleError(f"{p}: cannot decompress: {exc}") from exc
    if not lines:
        raise BundleError(f"{p}: empty bundle")
    try:
        head = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise BundleError(f"{p}: invalid manifest: {exc}") from exc
    if head.get("format") != FORMAT:
        raise BundleError(f"{p}: not a Rousseau bundle (format={head.get('format')!r})")
    if int(head.get("schema_version", 0)) > SCHEMA_VERSION:
        raise BundleError(f"{p}: schema version {head['schema_version']} is newer than supported ({SCHEMA_VERSION})")
    raw: list[dict[str, Any]] = []
    for i, line in enumerate(lines[1:], start=2):
        try:
            raw.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise BundleError(f"{p}: invalid JSON on line {i}: {exc}") from exc
    return Bundle(manifest=Manifest.model_validate(head), raw=raw, path=p)


def write_bundle(path: Path | str, events: list[dict[str, Any]], manifest: dict[str, Any] | None = None) -> Manifest:
    """Writes events (raw JSON dicts) as a bundle; fills manifest defaults."""
    m: dict[str, Any] = {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "rousseau_version": "",
        "created": int(time.time() * 1000),
        "event_count": len(events),
        "first_ts": min((e["ts"] for e in events), default=None),
        "last_ts": max((e["ts"] for e in events), default=None),
        "incidents": [],
        "servers": [],
        "pins": [],
        "producer": "rousseau-lab",
    }
    m.update(manifest or {})
    buf = io.BytesIO()
    with zstandard.ZstdCompressor(level=9).stream_writer(buf, closefd=False) as w:
        w.write((json.dumps(m, separators=(",", ":")) + "\n").encode())
        for e in events:
            w.write((json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n").encode())
    Path(path).write_bytes(buf.getvalue())
    return Manifest.model_validate(m)
