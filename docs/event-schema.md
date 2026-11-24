# Event schema

Every observation is one JSON object. Optional sections are omitted when empty, so rules can test presence with `exists`. Timestamps are Unix milliseconds (UTC). The Rust definition is `rousseau_core::event::Event`; the Python mirror is `rousseau_lab.models.Event` (unknown fields are accepted for forward compatibility).

## Top level

| Field | Type | Notes |
|---|---|---|
| `id` | int | Storage-assigned, increasing |
| `ts` | int | Unix ms |
| `kind` | string | See kinds below |
| `session` | string | `"<agent>-<root pid>-<root start ms>"` |
| `severity` | string | Set on findings, drift and blocked calls |
| `process` | object | Acting process |
| `lineage` | object | Position in the agent tree |
| `attribution` | object | Link to the causing tool call |
| `file`, `net`, `dns`, `registry`, `mcp`, `finding`, `drift`, `transcript`, `sensor`, `session_info` | object | Kind-specific sections |

## Kinds

| Kind | Source | Section |
|---|---|---|
| `process.start`, `process.stop` | ETW Kernel-Process (and a snapshot at start) | `process` |
| `image.load` | ETW Kernel-Process | `file` |
| `file.create` (new file), `file.read`, `file.write` (first read/write per open handle), `file.delete`, `file.rename` | ETW Kernel-File | `file` |
| `net.connect`, `net.accept`, `net.close` (with byte totals) | ETW Kernel-Network (UDP: first datagram per destination) | `net` |
| `dns.query` | ETW DNS-Client | `dns` |
| `registry.set`, `registry.delete` | ETW Kernel-Registry, security-relevant keys only | `registry` |
| `mcp.server_start`, `mcp.server_exit`, `mcp.initialize`, `mcp.tools`, `mcp.call`, `mcp.result`, `mcp.message` (other methods and notifications), `mcp.blocked`, `mcp.drift`, `mcp.finding` | MCP proxy | `mcp` (+ `finding` / `drift`) |
| `transcript.tool_use` | Transcript adapters | `transcript` |
| `session.start`, `session.end` | Pipeline | `session_info` |
| `sensor.health` | Sensors | `sensor` |

OS events (`file.*`, `net.*`, `dns.*`, `registry.*`, `image.load`) are recorded only for processes inside agent trees.

## Sections

**`process`**: `pid`, `ppid`, `image` (drive-letter path), `name` (lower-case file name), `command_line`, `start_time`, `cwd` and `signer` (agent candidates only), `exit_code` (stop).

**`lineage`**: `agent` (label from the signature table), `root` (`"<pid>:<start>"`), `root_pid`, `depth` (0 = the agent itself), `mcp_server` (when inside a wrapped server's subtree), `ancestors` (lower-case image names, nearest first, up to 8).

**`attribution`**: `kind` (`mcp`, `transcript`, `unexplained`), `tool_call` (an MCP call id `"<server>#<n>"` or `"tx:<adapter>:<tool_use_id>"`), `tool`, `server`, `method` (`exact`, `window`, `ambiguous`, `similarity`, `inherited`, `path`). See [correlation.md](correlation.md).

**`file`**: `path`, `new_path` (rename), `ext` (lower-case, no dot), `size` (when known).

**`net`**: `protocol` (`tcp`/`udp`), `direction`, `remote_addr`, `remote_port`, `remote` (`"addr:port"`), `remote_scope` (`loopback`, `private`, `link_local`, `multicast`, `public`), `local_addr`, `local_port`, `bytes_sent`, `bytes_recv` (on `net.close`).

**`dns`**: `query` (lower-case, no trailing dot), `query_type`, `longest_label`, `subdomain_entropy` (Shannon bits/char of labels left of the last two).

**`registry`**: `key` (normalized: `HKLM\…`, `HKCU\…`; any user hive becomes `HKCU`), `value`, `data` (strings decoded, DWORD/QWORD as decimal, other types hex-prefixed), `data_type`.

**`mcp`**: `server`, `transport` (`stdio`/`http`), `direction`, `method`, `rpc_id`, `call_id`, `tool`, `arguments`, `result`, `error`, `is_error`, `duration_ms`, `params`, `server_pid`, `proxy_pid`, `command`, `upstream`, `session_id` (HTTP `Mcp-Session-Id`), `blocked_reason`. Payloads larger than 64 KiB are replaced by `{"_rousseau_truncated": true, "bytes": N, "prefix": "…"}`.

**`finding`**: `inspector` (`unicode`, `instructions`, `shadowing`, `secrets`, `urls`, `args`, `classifier`), `code` (e.g. `unicode.tags`), `severity`, `title`, `detail`, `location`, `decoded` (hidden text, decoded payloads), `server`, `tool`. Secrets are reported redacted (first four characters and the length).

**`drift`**: `server`, `tool`, `change` (`added`, `removed`, `changed`), `previous_hash`, `current_hash`, `diff`.

**`transcript`**: `adapter`, `agent_session`, `tool`, `tool_use_id`, `command`, `input` (metadata only: command, file path, pattern, URL, description, working directory), `cwd`.

**`sensor`**: `sensor`, `status` (`ok`, `degraded`, `down`), `message`, `events_lost`, `events_dropped`.

**`session_info`**: `id`, `agent`, `root_pid`, `started`, `ended`, `cwd`, `project` (nearest ancestor with `.git`), `image`, `command_line`.
