# Architecture

## Components

| Crate / folder | Role |
|---|---|
| `crates/rousseau-core` | Event model, process tree, correlation, rule engine, incidents, SQLite storage, bundles, configuration, the pipeline |
| `crates/rousseau-etw` | ETW session and parsers (`ferrisetw`), Windows process utilities (snapshots, command lines, PEB working directory, Authenticode signer, suspension), verified provider constants |
| `crates/rousseau-mcp` | stdio and Streamable HTTP proxies, JSON-RPC framing, canonical hashing and tool pinning, inspectors, client-config adapters (`protect`/`unprotect`), optional classifier (`ml` feature) |
| `crates/rousseau-adapters` | Agent signature table (`agents.toml`) and read-only transcript adapters (Claude Code, Codex) |
| `crates/rousseau-server` | axum HTTP API, WebSocket live stream, embedded dashboard (`web/`), session causal tree, alert channels (Discord, Slack, HMAC webhook) |
| `crates/rousseau-cli` | `rousseau.exe`: commands, sensor host, Windows service, named pipe, Event Log and toast notifiers, data-directory ACLs |
| `web/` | Dashboard: vanilla ES modules, no build step, embedded at compile time |
| `lab/` | `rousseau-lab` Python package |
| `rules/` | Built-in rules (embedded in the binary) |
| `conformance/` | Shared rule-engine test cases |

## Processes and privileges

```
LocalSystem service (rousseau.exe service)        ← installed by `rousseau install`
  ├─ ETW session "Rousseau-Sensor" (needs admin)
  ├─ transcript adapters (read the installing user's profile, opt-in)
  ├─ pipeline → SQLite (%ProgramData%\Rousseau\rousseau.db)
  ├─ alerts: Event Log, webhooks
  └─ named pipe \\.\pipe\rousseau  (SYSTEM, Administrators, installing user; network logons denied; remote clients rejected)

User session
  ├─ rousseau wrap / wrap-http   (launched by MCP clients) → pipe: MCP events; DB: tool pins
  └─ rousseau ui                 → pipe: live stream, reload, health; DB: queries; toasts
```

`rousseau run` hosts the service components plus the dashboard in one foreground process (elevated for ETW).

- The service binary is copied to `%ProgramFiles%\Rousseau` so LocalSystem never executes a user-writable file.
- `%ProgramData%\Rousseau` gets a protected DACL: SYSTEM and Administrators full control, the installing user modify (needed for proxies to read pins and the UI to read events).
- Proxies ask the host for its policy over the pipe (response mode, finding threshold, strict pinning, data directory), so a proxy launched by an agent enforces the same mode as the sensor. Without a host they fall back to `rousseau.toml`; without a database they keep pins in memory and still relay traffic. A proxy never breaks the agent's MCP server because Rousseau is unavailable.
- When no host is listening, proxies write their events directly to the database (recorded without correlation or rule evaluation).

## Data flow

1. Sensors (ETW callbacks, transcript watchers, the pipe server for proxy events) push events into a bounded channel.
2. The pipeline task drains batches: process-tree updates and session tracking, enrichment (lineage, session, attribution), storage (one transaction per batch), rule evaluation, incident grouping.
3. After commit: alerts and suspension through the responder, live messages to the dashboard and pipe subscribers.
4. Every 5 s maintenance runs (tree and correlator garbage collection, hourly retention pruning); live sensor health refreshes every 5 s (shown by `rousseau doctor` and the dashboard), and every minute a `sensor.health` event is stored (Event Log id 3000 when degraded).

## Dashboard security

- Binds `127.0.0.1` on a random port (or `--port`).
- A 256-bit per-launch token travels in the URL fragment (`#token=…`), which browsers never send to servers or in `Referer`. The page keeps it in `sessionStorage` and sends it as `X-Rousseau-Token` (WebSocket: as the subprotocol `rousseau.<token>`, because browsers cannot set headers on WebSockets). Comparison is constant-time.
- The `Host` header must be `127.0.0.1:<port>` or `localhost:<port>` (blocks DNS rebinding); mutating requests and WebSocket upgrades with a foreign `Origin` are refused.
- `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' ws://127.0.0.1:<port>…`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. No remote assets.
- All untrusted strings (tool descriptions, arguments, results) are inserted with `textContent`, never as HTML.
- Webhook URLs and secrets are never sent to the browser.

## Event Log

Source `Rousseau` in the Application log (message file: .NET Framework `EventLogMessages.dll`, so the text displays verbatim).

| Id | Meaning |
|---|---|
| 1000 / 1001 | Sensor started / stopped |
| 2000–2004 | Incident with severity info, low, medium, high, critical |
| 3000 | Sensor health degraded or down |

## Storage

SQLite in WAL mode with a 5 s busy timeout. Tables: `events` (JSON body plus indexed columns), `sessions`, `incidents`, `tool_pins`, `servers`, `findings`, `rule_overrides`, `meta`. Retention (`retention_days`, default 14) deletes old events, findings, incidents and ended sessions hourly. Exports use the [bundle format](bundle-format.md).

## Optional classifier (`ml` feature)

`cargo build --features ml` adds ProtectAI's `deberta-v3-base-prompt-injection-v2` (Apache-2.0), run through ONNX Runtime loaded dynamically (`ORT_DYLIB_PATH`; a CPU or DirectML build of `onnxruntime.dll` lets it use CPU, GPU or NPU). With `classifier = true`, proxies download the model and tokenizer on first use from Hugging Face revision `90c9989b1a342275dd0d1a95aad283c04e075671` into `%ProgramData%\Rousseau\models`, verify them against pinned SHA-256 digests (`model.onnx` `f0ea7f23…228c`, `tokenizer.json` `752fe5f0…ff2f`) and refuse to load on mismatch. Tool descriptions and results scoring at or above 0.9 raise `classifier` findings (rule ROU-035). The heuristic inspectors run regardless.
