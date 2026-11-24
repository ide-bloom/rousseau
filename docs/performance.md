# Performance budget and methodology

**Budget:** under 3% CPU (of total machine capacity) and under 150 MB RAM (working set) for the sensor host during normal agent use.

## Design choices that keep it there

- **Early filtering.** ETW callbacks look up the acting PID in the shared tracked-PID set and return immediately for processes outside agent trees; only process start/stop events from untracked processes reach the pipeline (they are needed for PID-reuse safety). Command lines, working directories and signatures are only queried for candidate agent executables and children of tracked processes.
- **One event per handle.** File reads and writes are reported once per open file object, not per I/O.
- **Bounded everything.** Sensor → pipeline uses a 65,536-event bounded channel with `try_send`; on overflow events are dropped and counted (sensor health shows the count) instead of stalling ETW. The live stream to the dashboard is a broadcast channel whose slow subscribers lag rather than block. File-object, connection, registry-key and rule state maps are capped.
- **Batching.** The pipeline drains up to 1,024 events per SQLite transaction (WAL mode, `synchronous=NORMAL`).
- **Proxy hot path.** The stdio proxy relays server output as soon as each line is complete and observes it on a separate task; only responses to `tools/list` are inspected before relaying (needed so a rug-pulled tool is pinned before the client can call it). Client requests are classified before relaying (needed for blocking); parsing one line takes microseconds.

## How to measure

Use a release build in an elevated terminal, with a real agent session.

```powershell
cargo build --release
.\target\release\rousseau.exe run --headless            # terminal 1 (elevated)
.\scripts\measure-perf.ps1 -Seconds 600                  # terminal 2
# meanwhile, use your agent normally (builds, tests, git, MCP tools)
```

`scripts/measure-perf.ps1` samples the `rousseau` process every 250 ms and reports:

- **CPU %**: process CPU time ÷ wall time ÷ logical processors × 100, averaged over the window.
- **Peak working set** and **private bytes**.
- **ETW events lost** from `rousseau doctor`'s session query.

Report the machine (CPU model, logical processors), agent and workload alongside the numbers. Compare against an idle baseline (`-Seconds 60` with no agent running).

## Measurements

| Build | Configuration | Workload | CPU | Peak working set |
|---|---|---|---|---|
| debug | non-elevated (ETW off: proxy, pipeline, rules, storage, pipe) | idle, 10 s | 0.00% | 32.5 MB |
| debug | non-elevated (ETW off) | three back-to-back poisoned-server demo runs, 12 s | 0.01% | 38.9 MB |

Measured on 12 logical processors, Windows 11, with `scripts/measure-perf.ps1`'s method. **ETW-enabled measurements were not taken in the development environment** (no elevation available). Run the procedure above on your machine, and please contribute numbers with the details listed.
