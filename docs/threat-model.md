# Threat model

## What Rousseau defends against

| Threat | Examples | How Rousseau responds |
|---|---|---|
| Prompt-injected agent misusing its tools | Hidden instructions in a README or web page make the agent read `~/.ssh` and `curl` it out | ETW sees the read and the connection; rules ROU-001…006, ROU-007, ROU-025; attribution shows which tool call did it |
| Poisoned MCP tools | Hidden Unicode instructions, `<IMPORTANT>` blocks, "do not tell the user" in descriptions or results | Inspectors (ROU-017, ROU-026, ROU-035) |
| Rug pulls | A server changes a tool definition after approval | Pinning and drift (ROU-016); enforce mode blocks calls until re-approval (ROU-031) |
| Tool shadowing | A second server registers `sеnd_email` (Cyrillic е) | Confusable-skeleton comparison across servers (ROU-030) |
| Malicious MCP server payloads | Server code reads secrets and phones home | Server subtree labelling plus ETW: ROU-033, ROU-032, ROU-015 |
| Argument injection into tools | `--upload-pack=…`, `-c core.sshCommand=…`, encoded PowerShell in tool arguments | ROU-029; blocked in enforce mode at high severity |
| Agent self-escalation | The agent turns on auto-approve / bypass modes, or edits other agents' MCP configs | ROU-013, ROU-014 |
| Persistence and evasion | Run keys, Startup folder, scheduled tasks, services, WMI, Defender exclusions | ROU-008…012, ROU-019 |
| Destructive runs | Mass deletion, encryption-like write bursts | ROU-021…023 (optional suspension) |

## Trust boundaries and assumptions

- **The kernel and administrators are trusted.** Rousseau consumes ETW from a LocalSystem service. Anything with admin or SYSTEM rights can stop the session, disable providers, unload the service or edit the database. Rousseau detects a missing ETW session and lost events and reports them (dashboard health, `rousseau doctor`, Event Log 3000), but it is not tamper-proof: it is not a Protected Process Light and does not use the ETW Threat-Intelligence provider.
- **The installing user is semi-trusted.** The user's processes, including the agent, can talk to the named pipe (MCP events only; OS telemetry cannot be injected), read the database, and write tool pins and settings through the data-directory ACL. A compromised agent running as the user could therefore approve its own drifted tool or switch the mode to observe. Such changes are visible in the database and dashboard, but are not prevented. Running agents under a separate, less-privileged account removes this gap.
- **The dashboard is local.** It binds loopback only and requires the per-launch token; other local users without the token cannot use it.
- **MCP servers and tool output are untrusted.** Everything from them is treated as data: escaped in the UI and reports, bounded in size, and never executed.
- **Transcripts are untrusted input.** Adapters parse defensively, store only tool-use metadata, and switch off when the format is not understood.

## Known gaps

- **Admin-level malware can blind ETW** (see above).
- **Transcript formats can change** without notice. Adapters disable themselves and the built-in tool's intent becomes unexplained activity; OS effects are still recorded.
- **Unknown tools and agents.** An agent can use tools Rousseau has no adapter for, or be launched in a way the signature table does not match. Add signatures in `agent_files`; unknown tool activity still appears as unexplained.
- **Built-in tools cannot be blocked in advance.** Only MCP calls pass through the proxy; built-in tool effects can only be suspended after detection (opt-in).
- **Timing ambiguity.** Concurrent calls to one MCP server are attributed to the most recent call and marked `ambiguous`.
- **Encrypted payloads.** Network content is not inspected (only destinations and byte counts); HTTPS exfiltration to an allowed-looking host is visible only through behaviour (credential read then connect, first-seen destinations).
- **Remote MCP servers** are inspected only when routed through `rousseau wrap-http`; `protect` does not rewrite URL entries.
- **Registry coverage** is limited to security-relevant keys to keep volume low.
- **Kernel-Network ports and addresses** are decoded as network byte order per the provider's documented layout; verify on new Windows releases with the integration tests.

## Hardening recommendations

- Install the service (`rousseau install`) rather than relying on `rousseau run`.
- Use enforce mode with strict pinning for high-value machines; review pending tools before approving.
- Forward alerts off the machine (webhook to a SIEM) so tampering after an incident cannot erase the alert.
- Keep `allow_suspend` off until you have tuned false positives for your workflow.
