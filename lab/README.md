# rousseau-lab

Offline analysis for [Rousseau](https://github.com/ide-bloom/rousseau) sessions, for detection engineers and incident responders.

```bash
pip install rousseau-lab
```

| Command | What it does |
|---|---|
| `rousseau-lab load <bundle>` | Summary statistics (events by kind, attribution, processes, MCP servers, incidents) |
| `rousseau-lab report <bundle> -o report.html` | Self-contained offline HTML report: summary, incidents with evidence, causal tree, MCP findings and drift diffs, filterable timeline |
| `rousseau-lab test-rule <rule.yaml> --against <bundles...>` | Run rules against recorded sessions; prints hits, and misses for labelled (synthetic) bundles; exit code 1 on misses |
| `rousseau-lab hunt <bundles...> --query <expr>` | Search events with a small filter language compiled to polars |
| `rousseau-lab synth --scenario <name> -o out.rousseau` | Generate a synthetic session (benign work mixed with labelled attack-like sequences); nothing is executed |
| `rousseau-lab scenarios` | List synthetic scenarios |

Bundles come from `rousseau export --session <id> -o file.rousseau` (format: `docs/bundle-format.md`).

## Hunt queries

```
kind = 'file.read' and file.path ~ '.ssh'
process.name in ['curl.exe', 'powershell.exe'] and not attribution.kind = 'mcp'
net.remote_port >= 1024 and net.remote_scope = 'public'
finding.decoded exists or mcp.blocked_reason exists
process.command_line =~ '-enc(odedcommand)?\s'
```

Operators: `=` `!=` `in [...]` (case-insensitive), `~` `!~` (substring), `=~` (regex), `>` `>=` `<` `<=` (numbers), `exists`, combined with `and`, `or`, `not` and parentheses. Fields are dotted paths into the event schema (`docs/event-schema.md`). A missing field never matches a comparison.

## Rule engine

`rousseau_lab.rules` implements the same YAML semantics as the Rust engine. Both pass every case in the repository's `conformance/` directory, so a rule behaves the same live and offline.

## Development

```bash
pip install -e "lab[dev]"
cd lab && pytest && mypy && ruff check .
```
