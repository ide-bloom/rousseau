# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-23

First release.

### Added

- ETW sensor for agent process trees: Kernel-Process, Kernel-File, Kernel-Network, DNS-Client and Kernel-Registry (security-relevant keys), with device-path normalization, lost-event reporting and stale-session cleanup.
- Agent discovery from an embedded signature table (Claude Code, Claude Desktop, Codex CLI and app, Cursor, Windsurf, VS Code with Copilot, Gemini CLI, Aider, OpenCode, Goose) plus user signature files; PID-reuse-safe process tree; per-agent sessions with working directory and project.
- MCP stdio proxy (`rousseau wrap`) and Streamable HTTP reverse proxy (`rousseau wrap-http`, SSE included), recording initialize, tools, calls, resources, prompts, sampling, elicitation and list-changed notifications.
- Tool pinning by canonical-JSON SHA-256 (trust on first use or strict) with drift diffs, approve/deny, and blocking of drifted tools in enforce mode.
- Inspectors: hidden Unicode (Tags, zero-width, bidi, variation-selector smuggling, with decoding), instruction-like content, confusable tool names across servers, secrets (prefix, format, GitHub checksum, entropy), exfiltration-shaped URLs, dangerous arguments.
- `rousseau protect` / `unprotect` for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Codex and Gemini CLI configs: format-preserving rewrites, timestamped backups, dry-run diffs and byte-for-byte restore.
- Opt-in, read-only transcript adapters for Claude Code and Codex.
- Correlation engine attributing OS activity to MCP calls, transcript tool uses, or unexplained activity.
- Rule engine (event, sequence, threshold, first_seen) with 35 built-in rules mapped to the OWASP Agentic Top 10 (2026) and MITRE ATT&CK; incidents; observe/alert/enforce response modes; opt-in process-tree suspension.
- Local dashboard (live timeline, sessions with causal trees, MCP inventory, alerts, rules, settings) with token authentication and a strict CSP.
- Alert channels: Windows toast, Windows Event Log, Discord, Slack and an HMAC-signed webhook.
- SQLite storage with retention, `.rousseau` bundle export and replay, LocalSystem service with a restricted named pipe.
- Optional on-device prompt-injection classifier (`ml` feature, ONNX Runtime, pinned model).
- `rousseau-lab` Python package: `load`, `report`, `test-rule`, `hunt`, `synth`.
- Shared rule-engine conformance suite, demo poisoned MCP server and scripted scenarios.

[Unreleased]: https://github.com/ide-bloom/rousseau/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ide-bloom/rousseau/releases/tag/v0.1.0
