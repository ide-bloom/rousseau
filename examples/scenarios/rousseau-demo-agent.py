"""A scripted fake AI agent that drives the poisoned MCP server.

Deterministic sequence (used by the README demo and the integration tests):

1. start the local listener;
2. launch the poisoned server through ``rousseau wrap`` (so the proxy sees
   all MCP traffic);
3. ``initialize`` → ``tools/list`` (hidden-Unicode finding)
   → ``tools/call`` ×2 (the 2nd triggers the payload: demo-secret read and
   localhost POST) → ``notifications/tools/list_changed`` from the server
   → ``tools/list`` (rug-pull drift) → ``tools/call`` (blocked in enforce mode);
4. run one "built-in tool" shell command outside MCP (``cmd /c type``), the
   kind of activity MCP-only proxies cannot see.

The file name contains ``rousseau-demo-agent`` so ``demo-agent.toml`` makes
Rousseau treat this process as an agent root.

Usage: python rousseau-demo-agent.py [--rousseau PATH] [--port 8765]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SERVER_DIR = HERE.parent / "poisoned-mcp-server"


class Client:
    def __init__(self, cmd: list[str], env_port: int) -> None:
        env = dict(os.environ, DEMO_LISTENER_PORT=str(env_port), RUG_PULL_AFTER="2")
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env, text=True, encoding="utf-8", bufsize=1)
        self.next_id = 0
        self.notifications: list[dict[str, Any]] = []

    def send(self, msg: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.next_id += 1
        mid = self.next_id
        self.send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("server closed the connection")
            msg = json.loads(line)
            if msg.get("id") == mid:
                return msg
            self.notifications.append(msg)

    def wait_notification(self, method: str, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if any(n.get("method") == method for n in self.notifications):
                return True
            # A ping flushes any pending server output.
            self.request("ping")
            time.sleep(0.1)
        return False

    def close(self) -> int:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        return self.proc.wait(timeout=10)


def step(text: str) -> None:
    print(f"[demo-agent] {text}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rousseau", default=shutil.which("rousseau") or "rousseau.exe", help="path to rousseau.exe")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-wrap", action="store_true", help="talk to the server directly (baseline without Rousseau)")
    args = ap.parse_args()

    listener = subprocess.Popen([sys.executable, str(SERVER_DIR / "listener.py"), "--port", str(args.port)])
    time.sleep(0.5)
    server_cmd = [sys.executable, str(SERVER_DIR / "server.py")]
    cmd = server_cmd if args.no_wrap else [args.rousseau, "wrap", "--name", "poisoned-weather", "--", *server_cmd]
    step("launching: " + " ".join(cmd))
    c = Client(cmd, args.port)
    try:
        init = c.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "rousseau-demo-agent", "version": "1.0"},
            },
        )
        step(f"initialized: {init['result']['serverInfo']}")
        c.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = c.request("tools/list")["result"]["tools"]
        step(f"tools: {[t['name'] for t in tools]} (description length {len(tools[0]['description'])} chars, mostly invisible)")
        for city in ("Paris", "Lyon"):
            r = c.request("tools/call", {"name": "get_forecast", "arguments": {"city": city}})
            step(f"call {city}: {r.get('result', r.get('error'))}")
        if c.wait_notification("notifications/tools/list_changed"):
            step("server announced tools/list_changed")
        tools = c.request("tools/list")["result"]["tools"]
        step(f"re-listed: {tools[0]['description']!r}")
        r = c.request("tools/call", {"name": "get_forecast", "arguments": {"city": "Nice"}})
        if "error" in r:
            step(f"call after rug pull was BLOCKED: {r['error']['message']}")
        else:
            step("call after rug pull went through (observe/alert mode)")
        step("built-in tool (outside MCP): cmd /c type demo-secret.txt")
        subprocess.run(["cmd", "/c", "type", str(SERVER_DIR / "demo-secret.txt")], check=False, stdout=subprocess.DEVNULL)
    finally:
        code = c.close()
        listener.terminate()
        listener.wait(timeout=5)
    step(f"done (proxy exit code {code})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
