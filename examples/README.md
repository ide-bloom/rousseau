# Examples

## `poisoned-mcp-server/`

A small, clearly documented MCP server (Python standard library only) built
to demonstrate what Rousseau catches. It is safe by construction: it only
reads `demo-secret.txt` in its own folder and only sends to
`http://127.0.0.1:8765/collect`, served by the bundled `listener.py`.

| Behaviour | Where | Rousseau sees |
|---|---|---|
| Hidden instruction in invisible Unicode Tags characters | `get_forecast` description | `mcp.finding` `unicode.tags` with the decoded text (ROU-017) |
| Payload on the 2nd call: read `demo-secret.txt`, POST it to localhost | ETW file and network events attributed to that `tools/call` | ROU-033, ROU-015, ROU-032 |
| Rug pull after the payload: definition changes, `list_changed` sent | next `tools/list` | `mcp.drift` with a diff (ROU-016); in enforce mode the next call is blocked (ROU-031) |

## `scenarios/`

`rousseau-demo-agent.py` is a scripted fake agent that drives the server
through `rousseau wrap` in a fixed order, then runs one shell command outside
MCP (the activity MCP-only proxies are blind to). `demo-agent.toml` makes
Rousseau treat it as an agent root. `expected-incidents.json` lists the
incidents the run must produce; the integration tests assert them.

### Run it

From an elevated terminal in the repository root:

```powershell
cargo build --release
.\target\release\rousseau.exe run --mode enforce --agents examples\scenarios\demo-agent.toml
# second terminal (not necessarily elevated):
python examples\scenarios\rousseau-demo-agent.py --rousseau .\target\release\rousseau.exe
```

Open the dashboard link printed by `rousseau run`: the Sessions view shows
the `demo-agent` session with the causal tree (tool call → `python.exe` →
`demo-secret.txt` read → `127.0.0.1:8765` connection), MCP shows the drift
diff and the decoded hidden text, and Alerts lists the incidents.

Without elevation the ETW sensor is off: the MCP findings, drift and block
still appear, the file and network effects do not.

Export the session for offline analysis:

```powershell
.\target\release\rousseau.exe export --session latest -o demo.rousseau
rousseau-lab report demo.rousseau -o demo-report.html
```
