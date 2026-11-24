# Detection rules

Rules are YAML documents (several per file, separated by `---`). Built-in rules live in [`rules/`](../rules) and are compiled into `rousseau.exe`; add your own with `rule_dirs` in `rousseau.toml`. Validate with `rousseau rules validate PATH…`; test offline with `rousseau-lab test-rule`.

The Rust engine (`rousseau-core`) and the Python engine (`rousseau-lab`) implement exactly the semantics below; the [conformance suite](../conformance/README.md) enforces it.

## Rule fields

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Unique id (`ROU-NNN` for built-ins; pick your own prefix) |
| `title` | yes | One line |
| `severity` | yes | `info`, `low`, `medium`, `high`, `critical` |
| `description` | recommended | Why this matters; shown as the incident explanation |
| `references` | no | URLs |
| `owasp` | recommended | OWASP Top 10 for Agentic Applications (2026) ids: `ASI01` Agent Goal Hijack, `ASI02` Tool Misuse & Exploitation, `ASI03` Identity & Privilege Abuse, `ASI04` Agentic Supply Chain Vulnerabilities, `ASI05` Unexpected Code Execution, `ASI06` Memory & Context Poisoning, `ASI07` Insecure Inter-Agent Communication, `ASI08` Cascading Failures, `ASI09` Human-Agent Trust Exploitation, `ASI10` Rogue Agents |
| `mitre` | recommended | MITRE ATT&CK technique ids, e.g. `T1552.004` |
| `falsepositives` | recommended | Known benign triggers |
| `tags` | no | Free-form strings |
| `enabled` | no | Default `true` |
| `mode` | no | Per-rule override of the global response mode: `observe`, `alert`, `enforce` |
| `response.suspend_tree` | no | In enforce mode (and with `response.allow_suspend = true`), suspend the agent's process tree |
| `detection` | yes | See below |

Unknown keys are errors (typos should not silently disable a rule).

## Conditions

A condition is one of:

```yaml
{all: [cond, …]}      # every condition true (non-empty list)
{any: [cond, …]}      # at least one true (non-empty list)
{not: cond}
{descendant_of_agent: true|false}        # process is an agent root or any descendant (lineage.agent set)
{spawned_by_mcp_server: true|false}      # inside / outside any MCP server's process subtree
{spawned_by_mcp_server: "server-name"}   # inside that server's subtree (case-insensitive)
{field: PATH, OP: VALUE, case_sensitive: false}
```

`descendant_of_agent` is inclusive: the agent process itself counts.

### Field predicates

`field` is a dotted path into the [event JSON](event-schema.md), e.g. `process.name`, `file.path`, `lineage.mcp_server`. Exactly one operator per predicate:

| Operator | Value | True when |
|---|---|---|
| `equals` | scalar | equal (numbers numerically when both sides are numbers; otherwise as strings) |
| `in` | list of scalars | equal to any |
| `contains` / `startswith` / `endswith` | string or list | substring / prefix / suffix (any of the list) |
| `glob` | string or list | the whole value matches: `*` any run of characters including separators, `?` one character, `/` or `\` matches either separator; other characters literal |
| `regex` | string or list | unanchored search; use syntax common to Rust `regex` and Python `re` (no look-around, no backreferences) |
| `exists` | `true`/`false` | the field is present and not null / absent or null |
| `gt` `gte` `lt` `lte` | number | numeric comparison (non-numbers never match) |

Rules of evaluation:

- Arrays along a path are flattened, so a path can yield several candidate values; a predicate is true if **any** candidate satisfies it. `null` counts as missing.
- A missing field satisfies nothing except `exists: false`.
- String comparisons are case-insensitive unless `case_sensitive: true`.
- For string operators, integers render without a fraction (`443`), booleans as `true`/`false`; objects and arrays never match.

## Detection types

### `event`: one match per matching event

```yaml
detection:
  type: event          # default
  where: <condition>
```

### `sequence`: steps in order, per group, within a window

```yaml
detection:
  type: sequence
  by: [lineage.root]   # group key fields (missing → empty string)
  within: 60s          # ms, s, m or h; measured from the first step's event (inclusive)
  steps:
    - name: optional label
      where: <condition>
    - where: <condition>
```

Per group the engine keeps partial chains in creation order. For each event: (1) chains whose first event is more than `within` older are dropped; (2) every chain whose next step matches advances; the first chain to complete emits a match with its event ids and **clears all chains of the group**, and the completing event then does not start a new chain; (3) otherwise, if the event matches step 1, a new chain starts. At most 64 chains are kept per group (oldest dropped).

### `threshold`: count (or distinct values) per group within a window

```yaml
detection:
  type: threshold
  where: <condition>
  by: [session]
  within: 10s
  count: 100
  distinct: file.path   # optional: count distinct values (case-insensitive); events lacking it are ignored
```

Entries more than `within` older than the current event are evicted; when the count reaches `count` a match with every event id in the window is emitted and the window is cleared.

### `first_seen`: first occurrence of a value per group

```yaml
detection:
  type: first_seen
  where: <condition>
  by: [lineage.mcp_server]
  value: net.remote     # values compared case-insensitively; events lacking it are ignored
```

State lives in memory from sensor start, so after a restart the first sighting of each value fires again.

## Incidents and responses

Matches of the same rule in the same session (and group) within 10 minutes of the last match merge into one incident (count and evidence grow; at most 500 evidence ids). The response mode is the rule's `mode` or the global mode:

- `observe`: recorded only.
- `alert`: alerts to the configured channels (severity at or above `alerts.min_severity`).
- `enforce`: alerts; the MCP proxy blocks calls to drifted/unapproved tools and calls whose arguments trigger findings at or above `response.block_findings_at`; rules with `response.suspend_tree` suspend the agent tree when `response.allow_suspend = true`. Critical system processes (and Rousseau itself) are never suspended; `rousseau resume PID…` resumes.

## Built-in rules

| Id | Severity | Title |
|---|---|---|
| ROU-001 | high | Agent tree reads SSH private keys |
| ROU-002 | high | Agent tree reads cloud CLI credentials |
| ROU-003 | critical | Agent tree reads browser credential or cookie stores |
| ROU-004 | critical | Agent tree reads password manager vaults |
| ROU-005 | high | Agent tree reads another tool's access tokens |
| ROU-006 | critical | Credential read followed by outbound connection (sequence) |
| ROU-007 | high | Upload to paste site, webhook relay or tunnel |
| ROU-008 | high | Agent tree writes a Run or RunOnce autostart value |
| ROU-009 | high | Agent tree writes to a Startup folder |
| ROU-010 | high | Agent tree creates a scheduled task |
| ROU-011 | high | Agent tree creates or modifies a Windows service |
| ROU-012 | critical | Agent tree sets up a WMI event subscription |
| ROU-013 | critical | Agent edits its own permission or approval settings (self-escalation) |
| ROU-014 | high | Agent edits another agent's or an MCP client's configuration |
| ROU-015 | medium | MCP server connects to a destination it never contacted before (first_seen) |
| ROU-016 | high | MCP tool definition drifted after approval |
| ROU-017 | critical | Hidden Unicode in MCP tool metadata or results |
| ROU-018 | high | Encoded PowerShell launched from an agent tree |
| ROU-019 | critical | Agent tree tampers with Microsoft Defender |
| ROU-020 | high | git push to a URL instead of a configured remote |
| ROU-021 | high | Mass file deletion by an agent tree (threshold) |
| ROU-022 | critical | Encryption-like write burst (threshold) |
| ROU-023 | critical | Files renamed to ransomware-style extensions (threshold) |
| ROU-024 | high | Executable dropped in TEMP then executed (sequence) |
| ROU-025 | high | DNS query with tunneling characteristics |
| ROU-026 | high | Instruction-like content in MCP tool metadata or results |
| ROU-027 | high | Secret in MCP tool arguments or results |
| ROU-028 | medium | Exfiltration-shaped URL in MCP traffic |
| ROU-029 | high | Dangerous argument pattern in an MCP tool call |
| ROU-030 | high | MCP tool shadowing across servers |
| ROU-031 | medium | MCP tool call blocked by Rousseau |
| ROU-032 | critical | MCP server reads a secret-named file and then connects out (sequence) |
| ROU-033 | medium | MCP server process reads a secret-named file |
| ROU-034 | high | Living-off-the-land binary used for download or proxy execution |
| ROU-035 | high | Possible prompt injection flagged by the on-device classifier |

ROU-020 approximates "a remote not configured in the repository" by flagging pushes to an explicit URL instead of a named remote; Rousseau does not read repository configuration.
