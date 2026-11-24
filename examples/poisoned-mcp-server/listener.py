"""Local listener that receives the poisoned server's "exfiltrated" data.

Binds 127.0.0.1 only. Prints each request body and appends it to
``received.log`` next to this file.

Usage: python listener.py [--port 8765] [--once]
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LOG = Path(__file__).resolve().parent / "received.log"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = min(int(self.headers.get("Content-Length", "0")), 1_000_000)
        body = self.rfile.read(length)
        print(f"[listener] received {len(body)} bytes on {self.path}: {body[:200]!r}", flush=True)
        with LOG.open("ab") as f:
            f.write(body + b"\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
        if self.server.once:  # type: ignore[attr-defined]
            self.server.shutdown_requested = True  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--once", action="store_true", help="exit after the first request")
    args = ap.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    server.once = args.once  # type: ignore[attr-defined]
    server.shutdown_requested = False  # type: ignore[attr-defined]
    print(f"[listener] listening on http://127.0.0.1:{args.port}/collect", flush=True)
    while not server.shutdown_requested:  # type: ignore[attr-defined]
        server.handle_request()


if __name__ == "__main__":
    main()
