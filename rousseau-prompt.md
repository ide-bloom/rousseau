# Rousseau — Full Build Prompt

Build **Rousseau**, an open-source endpoint detection and response (EDR) tool for AI coding agents on Windows, as a complete, production-quality GitHub repository in a single run. Do not stop at a scaffold, an outline, or a partial implementation. Every feature in this document must be implemented, compile or run cleanly, be covered by tests, and be documented accurately. When a Windows, ETW or MCP protocol detail is uncertain, check the official documentation (Microsoft Learn, the MCP specification at modelcontextprotocol.io, the crate and package docs) before writing the code. Target current Windows 11 (24H2, 25H2, 26H1) and the current MCP specification revision. Use the latest stable versions of every dependency at build time.

The repository lives at `github.com/ide-bloom/rousseau`. It is the flagship of three sister projects (Epicurus, Hush, Rousseau) that together form the **Palisade** toolkit for developer security in the AI-agent era. Link the other two in the README (`github.com/ide-bloom/epicurus`, `github.com/ide-bloom/hush`).

---

## 0. Build environment

- Build this on Windows 11 (x64) with the Rust MSVC toolchain (rustup plus Visual Studio Build Tools with the "Desktop development with C++" workload), Python 3.12+ and Git. Run from an elevated terminal so the ETW sensors can actually be exercised.
- Add `target/`, `.venv/`, `__pycache__/`, `dist/` and `*.egg-info/` to `.gitignore` before the first build. Never commit build output or virtual environments.
- If you are running in a non-Windows or storage-limited environment instead: set `CARGO_TARGET_DIR` to a temporary directory outside the repository (for example `/tmp/rousseau-target`) and create the Python virtual environment outside it too. Run `rustup target add x86_64-pc-windows-msvc` and keep the Rust code compiling with `cargo check --target x86_64-pc-windows-msvc` and `cargo clippy --target x86_64-pc-windows-msvc`. Run all platform-independent Rust tests, the full Python test suite and the conformance suite, skip the Windows-only integration tests, and rely on the GitHub Actions Windows workflow for the real build and test run. In your final summary, list exactly which checks could not be run.

---

## 1. What Rousseau is and why it exists

AI coding agents (Claude Code, OpenAI Codex, Cursor, Windsurf, Gemini CLI, GitHub Copilot agent mode, Aider, OpenCode and others) run on developer machines with the user's full permissions. They read files, run shell commands, and call tools exposed by MCP servers. That makes them a new attack surface:

- More than 30 CVEs were filed against MCP servers, clients and tooling in January and February 2026 alone.
- Tool poisoning, rug pulls (a server changing its tool definitions after approval), tool shadowing, and hidden-Unicode prompt injection are all documented in the OWASP MCP Top 10 and the OWASP Top 10 for Agentic Applications (2026).

Several open-source proxies already inspect MCP JSON-RPC traffic, but they share a blind spot: **an agent's built-in tools, such as its shell, file edits and web fetch, never go through MCP**, and a JSON-RPC proxy cannot see what a tool call actually did on the machine.

Rousseau closes that gap by combining two layers of visibility:

1. **OS-level ground truth.** ETW telemetry on every process, file, network and registry action taken by an agent's entire process tree.
2. **Intent.** The MCP traffic between agents and their servers, plus (opt-in) the agent's own local session transcript, so each OS action can be traced back to the tool call that caused it.

It puts everything on one timeline (tool call → process started → files read → network connection), applies detection rules built for agents, and can block a tool call or contain a process tree.

Rousseau is strictly defensive and fully local. Nothing leaves the machine unless the user configures an alert channel.

---

## 2. Stack and repository layout

**Rust sensor and dashboard** (the shipped `rousseau.exe`):
- Rust stable, edition 2024, MSVC toolchain, targets x64 and arm64, CRT linked statically.
- Crates: `windows`, `ferrisetw`, `windows-service`, `tokio`, `axum` (HTTP + WebSocket), `rust-embed`, `serde`, `serde_json`, `serde_yaml`, `rusqlite` (bundled), `clap`, `reqwest` (rustls), `sha2`, `regex`, `unicode-normalization`, `tracing`, `anyhow`, `thiserror`. Enforce with `cargo-deny`.

**Dashboard front end:** no Node build step. Write vanilla ES modules, vendor any small libraries with their licenses (for example uPlot for charts), and embed everything into the binary at compile time.

**Python companion, `rousseau-lab`:** tooling for detection engineers and incident responders to analyze recorded sessions offline.
- Python 3.12+, `src/` layout, `pyproject.toml` (hatchling), packages `typer`, `pydantic` v2, `pyyaml`, `polars`, `jinja2`, `rich`.
- `pytest` + `hypothesis` for tests, `ruff` and `mypy --strict` for linting and types.
- Published to PyPI.

**Layout:**

```
crates/
  rousseau-core/     event model, process-tree tracker, correlation engine, rule engine, storage
  rousseau-etw/      ETW sessions and parsers
  rousseau-mcp/      stdio + HTTP MCP proxy, tool pinning, inspectors, client-config adapters
  rousseau-adapters/ agent discovery + read-only transcript adapters
  rousseau-server/   axum API, WebSocket stream, embedded dashboard
  rousseau-cli/      rousseau.exe
rules/                built-in YAML rules
web/                  dashboard source (embedded)
lab/                  rousseau-lab Python package
conformance/          shared rule-engine test cases used by both Rust and Python
examples/             demo MCP servers and scenarios (Section 9)
```

---

## 3. Agent discovery and the process tree

**Agent signatures.** Keep known agents in an embedded `agents.toml` data table: executable names, command-line patterns, path patterns and signer. Cover:
- Claude Code (native binary or Node package), Claude Desktop
- OpenAI Codex CLI and app
- Cursor, Windsurf, VS Code with Copilot agent mode
- Gemini CLI, Aider, OpenCode, Goose

Verify current executable names at build time. Users can add their own entries.

**Process tree.** Consume `Microsoft-Windows-Kernel-Process` to maintain a live process table keyed by pid plus start time. When an agent process starts, or is already running at launch (enumerate existing processes), mark it as a root. Every descendant inherits the agent label. MCP server processes are labeled with their server name: from the proxy when wrapped (Section 4), or by matching command lines from discovered client configs. Record only events from tracked trees, which keeps overhead low.

**Sessions.** Group activity into agent sessions: one session per root agent process lifetime, with a working directory and the project it belongs to.

---

## 4. MCP layer

**stdio proxy.** `rousseau wrap --name <server> -- <command> [args]` spawns the real server, relays stdin and stdout byte-exactly, and parses the newline-delimited JSON-RPC in both directions without adding latency. stderr passes through untouched.

**HTTP proxy.** `rousseau wrap-http --name <server> --upstream <url>` runs a local reverse proxy for Streamable HTTP MCP servers, including SSE streams, with correct header and session-ID handling.

**What gets recorded:** `initialize` (client and server info, capabilities), `tools/list`, `tools/call` (arguments, results, errors, timing), resources, prompts, sampling and elicitation requests, and list-changed notifications.

**Tool pinning (rug-pull defense).** On first sight of a server, compute a canonical-JSON SHA-256 of each tool definition (name, description, inputSchema, annotations) and pin it, trust-on-first-use, or require approval in strict mode. When a definition drifts:
- show a diff in the dashboard
- in enforce mode, block calls to the changed tool by returning a proper JSON-RPC error explaining why, until the user re-approves
- added or removed tools are drift too

**Inspectors** run on tool descriptions, schemas, arguments and results:
- Hidden Unicode: the Tags block U+E0000–U+E007F, zero-width characters, bidi controls, variation-selector smuggling. Report the decoded hidden text.
- Instruction-like content in descriptions or results, for example "ignore previous instructions", `<IMPORTANT>` blocks, "do not tell the user", or directions to read credential paths.
- Tool shadowing: the same or a confusable tool name across servers (use Unicode confusable skeletons).
- Secrets in arguments or results (prefix, format, checksum and entropy rules). Never commit literal token-shaped strings to the repo; build test fixtures from fragments at runtime.
- Exfiltration-shaped URLs: webhook relays, paste sites, tunneling domains, raw IPs, Discord webhooks.
- Dangerous argument patterns for shell- or git-like tools: `-c` injection, `--upload-pack`, `core.sshCommand`, encoded PowerShell.

**Client config adapters.** Discover MCP configs for Claude Desktop, Claude Code (user and project), Cursor, VS Code, Windsurf, Codex and Gemini CLI, kept in a data table and verified at build time.
- `rousseau protect` rewrites each server entry so it launches through `rousseau wrap`.
- It preserves formatting and unrelated keys, makes a timestamped backup, and supports `--dry-run` (shows a diff) and `rousseau unprotect` to restore.

---

## 5. Transcript adapters (opt-in, read-only)

Agents' built-in tools don't go through MCP, so Rousseau can, with explicit opt-in, read the agent's own local session logs to recover intent. Known locations include Claude Code's project session JSONL files under the user profile and Codex's session rollout files. Verify the current locations and formats at build time.

- Parse defensively: formats change, so unknown fields are ignored and any parse failure turns that adapter off with a warning instead of crashing.
- Extract tool-use events (tool name, command or arguments, timestamps) and correlate them with spawned processes by time window plus command-line similarity.
- Never modify or copy these files wholesale. Store only the extracted tool-use metadata.

---

## 6. Telemetry and correlation

**ETW providers:**
- `Microsoft-Windows-Kernel-Process`: process start/stop, image loads
- `Microsoft-Windows-Kernel-File`: create, read, write, delete, rename
- `Microsoft-Windows-Kernel-Network`: TCP/UDP connect and accept, plus byte counts
- `Microsoft-Windows-DNS-Client`: queries per PID
- `Microsoft-Windows-Kernel-Registry`: value sets, filtered to persistence and security-relevant keys

Verify every provider GUID, keyword and event ID against the manifests (for example with `logman query providers`); never guess. Normalize device paths to drive-letter paths, handle lost events and stale sessions, and surface sensor health in the UI and in `rousseau doctor`.

**Correlation engine.** Attribute every OS event to the agent session and the specific tool call that caused it:
- An MCP tool call's in-flight window plus that server's process subtree attributes events to the call.
- A transcript tool-use plus the spawned shell process and its descendants attributes events to that tool use.
- Everything else is attributed to the session as unexplained activity, which is itself a useful signal.

The result is a causal timeline: **intent** (prompt-derived tool call) → **action** (processes) → **effects** (files, network, registry).

---

## 7. Detection rules

**Format.** Rules are YAML, Sigma-inspired, and documented in `docs/rules.md`. Each rule has: id, title, severity, description, references, an OWASP Agentic Top 10 (2026) mapping (verify the exact IDs and names on genai.owasp.org), MITRE ATT&CK technique IDs, and false-positive notes. Supported conditions:
- field matchers (equals, contains, glob, regex, in-list)
- lineage predicates (`descendant_of_agent`, `spawned_by_mcp_server`)
- sequence and threshold correlation within a time window, for example "a credential read followed by an outbound connection from the same tree within 60 seconds"

**Ship at least 25 built-in rules**, including:
- An agent tree reads credential stores: SSH keys, cloud CLI credentials, browser `Login Data`/`Cookies`, password-manager files, or another agent's token files.
- An agent tree reads a credential and then makes an outbound network connection (sequence rule).
- Uploads to a paste site, webhook relay or tunnel via `curl`, `Invoke-WebRequest` or `bitsadmin`.
- Writes to persistence locations: Run/RunOnce keys, the Startup folder, scheduled task creation, services, WMI subscriptions.
- **Self-escalation:** the agent edits its own permission or approval settings, such as turning on auto-approve or bypass modes.
- The agent edits another agent's config or an MCP client config.
- An MCP server process connects to a destination that server has never contacted before.
- A tool definition drifts after approval.
- Hidden Unicode in a tool description or tool result.
- Encoded PowerShell launched from an agent tree.
- Attempts to change Defender settings or add exclusions.
- `git push` to a remote not configured in the repo.
- Mass file deletion or encryption-like write bursts in the project directory.
- A download followed by execution of a fresh binary from `%TEMP%`.
- DNS queries with tunneling characteristics (high-entropy, very long subdomains).

**Response modes** are set globally and can be overridden per rule:
- `observe` (the default on first run)
- `alert`
- `enforce`: block MCP tool calls; optionally suspend the offending process tree, opt-in, and never for critical system processes

**Optional on-device classifier.** Behind the `ml` cargo feature, add a local prompt-injection classifier on top of the heuristic inspectors. Use an ONNX model run through ONNX Runtime or Windows ML on CPU, GPU or NPU. The model is downloaded on first use, pinned by SHA-256, with its license noted in the docs. The heuristic path must work fully without it.

---

## 8. Dashboard, alerts and storage

**Dashboard.** Served by axum on `127.0.0.1` on a random port, protected by a per-launch token in the URL. Strict CSP, no remote assets. Launch it with `rousseau ui`.
- **Live timeline:** WebSocket stream, filterable by session, agent, server or severity.
- **Session view:** a causal tree from tool calls to processes to effects. Expand any node for details: command line, file paths, destinations, byte counts.
- **MCP inventory:** every server, its tools, pin status, drift diffs with approve/deny, and inspector findings.
- **Alerts:** grouped incidents with the rule's explanation and the evidence chain.
- **Rules:** a list with enable/disable and mode controls, plus a reload button.
- **Settings:** response mode, transcript adapters (opt-in), retention.

Design it as a polished, dense, professional security console: dark by default, light theme available, keyboard navigable.

**Alert channels:** Windows toast, Windows Event Log (event IDs documented), Discord, Slack and a generic HMAC-signed webhook.

**Storage.** SQLite in WAL mode under `%ProgramData%\Rousseau` with ACLs restricted to admins plus the installing user, and configurable retention.
- `rousseau export --session <id>` writes a portable `.rousseau` bundle: zstd-compressed JSONL of events plus a manifest with a schema version.
- `rousseau replay <bundle>` loads a bundle back into the dashboard.

**Service and privileges.** ETW kernel providers need admin rights. `rousseau install` registers a LocalSystem service that runs the sensors. The UI and the proxy run as the user and talk to the service over a named pipe with a restrictive DACL. `rousseau run` provides a foreground mode for quick use from an elevated terminal.

---

## 9. Demo and test scenarios

Write `examples/poisoned-mcp-server/` as a small, clearly documented Python MCP server built for demonstrations:
- Its tool description contains a hidden Unicode instruction.
- After N calls it rug-pulls its own tool definition.
- Its "payload" only reads a file named `demo-secret.txt` inside the examples folder and sends it to a listener on `localhost`, which the example also provides.

It must never touch real user files or any non-local network.

`examples/scenarios/` holds scripted, reproducible runs that drive this server and a fake agent process tree, producing deterministic sessions used both for the README demo and for integration tests.

---

## 10. `rousseau-lab` (Python)

CLI `rousseau-lab`, built with typer:
- `load <bundle>`: summary statistics as rich tables
- `report <bundle> -o report.html`: a self-contained offline HTML incident report with timeline, causal tree, findings and evidence, rendered with jinja2 and inline JS/CSS
- `test-rule <rule.yaml> --against <bundles...>`: run a rule against recorded sessions and print hits and misses, for rule development
- `hunt <bundles...> --query <expr>`: a small filter language over events, compiled to polars expressions
- `synth --scenario <name> -o out.rousseau`: generate synthetic sessions (benign developer work mixed with labeled attack-like sequences) for testing rules, without running anything malicious

**Conformance.** The Python rule engine implements the same YAML semantics as the Rust engine. Both must pass every case in `conformance/`: YAML files that each contain a rule, an input event sequence, and the expected matches. This guarantees a rule behaves the same live and offline.

---

## 11. Repository contents

- `README.md`, with these sections:
  - One-line pitch and badges (CI for Rust and Python, release, PyPI, license)
  - Demo GIF placeholder at `docs/media/demo.gif`, with recording instructions using the poisoned-server scenario
  - Why Rousseau exists: 2026 MCP CVEs, OWASP agentic risks, and why MCP-only proxies are blind to built-in tools
  - How it works: Mermaid diagrams of the data flow and the correlation model
  - Quick start (`rousseau install` → `rousseau protect` → `rousseau ui`)
  - CLI reference, rule-writing guide, `rousseau-lab` guide
  - Threat model and limitations: admin-level malware can blind ETW, transcript formats can change, an agent can use tools Rousseau doesn't know about
  - Comparison table against MCP-only proxies (factual, no disparagement)
  - FAQ, roadmap, sister projects, contributing, security, license
- `docs/`: `architecture.md`, `correlation.md`, `rules.md`, `event-schema.md`, `bundle-format.md`, `threat-model.md`
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue and PR templates, `.editorconfig`, `rustfmt.toml`, `deny.toml`, `ruff.toml`
- Apache-2.0 license

---

## 12. Tests

**Rust:**
- Unit tests: JSON-RPC framing, including partial and multi-message reads; canonical-JSON hashing; drift detection; each inspector (with Unicode Tags decoding round-trips); confusable detection; config rewrite golden files per client plus restore; process-tree inheritance and PID reuse; correlation windows; every rule operator; bundle export/import.
- Conformance suite.
- Integration tests behind `--features integration` that run on GitHub's Windows runners (admin): start sensors, run the scenario, and assert the expected incidents with correct attribution.

**Python:** pytest for every CLI command, the conformance suite, hypothesis property tests for the query compiler, `mypy --strict` and `ruff` clean.

---

## 13. CI/CD

GitHub Actions on `windows-latest`, with actions pinned by commit SHA:
- **Rust job:** fmt, clippy with `-D warnings`, tests, cargo-deny, release builds for x64 and arm64.
- **Python job:** a matrix for 3.12 and 3.13 running ruff, mypy, pytest and a build.
- **Conformance job:** runs both engines against `conformance/`.
- **Tags matching `v*`:** zip the binaries with README and LICENSE, generate `SHA256SUMS`, run `actions/attest-build-provenance`, create a GitHub Release with notes from the CHANGELOG, and publish `rousseau-lab` to PyPI through trusted publishing.
- Dependabot for cargo, pip and GitHub Actions.

---

## 14. Code standards

- **Rust:** no `unwrap`/`expect` outside tests unless the case is truly infallible, with a comment saying why; typed errors; minimal `unsafe`, each block with a `// SAFETY:` comment; bounded channels with backpressure, so a slow UI can never stall the sensors.
- **Python:** full type hints, no bare `except`.
- **Both:** doc comments on public items, comments that explain why rather than what, and readable code a security reviewer can audit.
- **Performance budget:** under 3% CPU and under 150 MB RAM during normal agent use, measured, with the methodology documented.

---

## 15. Definition of done

- `cargo build --release` produces `rousseau.exe` for both targets, and `pip install ./lab` works.
- All Rust, Python and conformance tests pass, and all linters are clean.
- On a Windows 11 machine with an AI agent configured:
  - `rousseau protect` wraps its MCP servers.
  - Running the poisoned-server scenario shows, live in the dashboard: the hidden-Unicode finding, the rug-pull drift (blocked in enforce mode), the demo-secret read, and the localhost exfiltration attempt, all on one causal timeline.
  - `rousseau-lab report` turns the exported session into an HTML report.
- `rousseau unprotect` restores every config byte for byte.
- The README describes only what actually exists.

Finish with a full pass over every file: remove TODOs, dead code and placeholder text, and fix any mismatch between the documentation and the real behavior.
