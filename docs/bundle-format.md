# `.rousseau` bundle format

A bundle is a portable copy of one session, written by `rousseau export` or `rousseau-lab synth` and read by `rousseau replay` and `rousseau-lab`.

- The file is a single **zstd** frame.
- Its content is **UTF-8 JSON Lines**.
- **Line 1** is the manifest. **Every following line** is one event ([event schema](event-schema.md)), in id order.

## Manifest

```json
{
  "format": "rousseau-bundle",
  "schema_version": 1,
  "rousseau_version": "0.1.0",
  "created": 1767225600000,
  "session": { "id": "claude-code-1200-1767225600000", "agent": "claude-code", "root_pid": 1200, "started": 1767225600000, "cwd": "C:\\src\\app" },
  "event_count": 412,
  "first_ts": 1767225600000,
  "last_ts": 1767225720000,
  "incidents": [ { "id": 1, "rule_id": "ROU-017", "severity": "critical", "evidence": [12], "…": "…" } ],
  "servers": [ { "name": "poisoned-weather", "transport": "stdio", "target": "python server.py", "first_seen": 0, "last_seen": 0 } ],
  "pins": [ { "server": "poisoned-weather", "tool": "get_forecast", "status": "pending", "current_hash": "…", "…": "…" } ],
  "producer": "rousseau export",
  "labels": [ { "rule": "ROU-016", "events": [40], "description": "rug pull" } ]
}
```

| Field | Notes |
|---|---|
| `format` | Always `rousseau-bundle`; readers reject anything else |
| `schema_version` | Readers reject versions newer than they support (currently 1) |
| `session` | Session metadata (absent for multi-session or synthetic bundles) |
| `incidents` | Incidents of the session, with evidence event ids |
| `servers`, `pins` | MCP servers seen in the session and their tool pins |
| `producer` | Free text |
| `labels` | Optional ground truth written by `rousseau-lab synth`; ignored by `rousseau replay` |

Unknown manifest fields must be ignored by readers.

## Reading a bundle by hand

```python
import io, json, zstandard

with open("session.rousseau", "rb") as f:
    lines = io.TextIOWrapper(zstandard.ZstdDecompressor().stream_reader(f), encoding="utf-8")
    manifest = json.loads(next(lines))
    events = [json.loads(l) for l in lines if l.strip()]
```

## Privacy

Bundles contain command lines, file paths, MCP arguments and results from the session (secrets found by inspectors are redacted in findings, but raw MCP payloads are kept as observed). Treat bundles as sensitive incident data.
