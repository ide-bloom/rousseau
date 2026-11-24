# Correlation model

The pipeline attributes every OS event in an agent tree to the **intent** that caused it, producing the causal timeline *intent → action → effects*. Implementation: `rousseau_core::correlate` and `rousseau_core::pipeline`.

## Process tree

Processes are keyed by `(pid, start time)`. At startup a snapshot seeds the tree (oldest first), then ETW process events keep it current. A process becomes an **agent root** when it matches the signature table and is not already inside an agent tree; nested agent processes (for example `node.exe` children of `claude.exe`) stay descendants of the outer session. A "parent" that started after its child is treated as a reused PID and ignored. Exited processes stay resolvable for two minutes so late events still attribute.

`rousseau wrap` announces its child's PID (`mcp.server_start`); that process and all its descendants carry `lineage.mcp_server`. If the server process has not been seen yet, the label is applied when it starts.

When ETW is off (no elevation), the proxy reports its parent process; that parent becomes a session root (labelled with its agent id, or `mcp-client`) so MCP activity is still grouped by session.

## Attribution, in priority order

1. **Inherited.** A process started for a tool call passes its attribution to all descendants (`method: inherited`).
2. **MCP call window.** A `tools/call` opens a window for its server, closed by the response plus a grace period. Activity in that server's subtree at time *t* is attributed to the most recent call whose window contains *t*: `method: window`, or `ambiguous` when several calls to the same server overlap. Processes spawned during a call keep that attribution permanently.
3. **Transcript tool use.** A shell tool use (Claude Code `Bash`, Codex `shell`/`exec_command`) matches a process started by the same agent (outside MCP subtrees) when:
   - it started between 3 s before and 15 s after the tool use timestamp, and
   - at least 60% of the command's tokens appear in its command line (tokens are lower-cased, shell punctuation removed, executable paths reduced to file names).

   The best-scoring candidate wins (`method: similarity`). Matching runs in both directions because transcripts are read about a second late: a late tool use re-attributes the process and its subtree in storage. File tools (`Read`, `Write`, `Edit`, …) attribute file events from the agent process itself on the same path within the same window (`method: path`).
4. **Unexplained.** Anything else in an agent tree is `attribution.kind = unexplained`. Unexplained network connections or credential reads are often the most interesting events of a session.

The agent root's own process start has no attribution: it *is* the session.

## Tunables

| Setting | Default |
|---|---|
| MCP grace after a response | 2 s |
| Abandoned call (no response) | 10 min |
| Transcript window | −3 s … +15 s |
| Minimum command similarity | 0.6 |

## Known limitations

- Two concurrent calls to the same server cannot be separated by timing alone; such events are marked `ambiguous`.
- A long-running process started by one tool call and reused by later calls keeps the first attribution.
- Transcript matching needs the adapter enabled (opt-in) and a supported agent; other agents' built-in tools show up as unexplained activity.
