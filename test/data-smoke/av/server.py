#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""HTTP origin for the scanning-gate smoke.

Usage: server.py NAME PORT [PORT ...]

Paths (a query string is logged and otherwise ignored, so the smoke can
fetch one object under a distinct URL per case):
  GET /            one line "server=NAME port=PORT client=IP", as the
                   forwarding echo listener answers, for control probes
  GET /clean.txt   a clean text body: that line followed by filler
  GET /eicar.txt   the 68-byte EICAR test file (see eicar.py)
  POST /upload     reads the request body and answers
                   "server=NAME port=PORT client=IP method=POST size=N md5=HEX"

Every request is appended to /tmp/av-requests.jsonl as one JSON object
with the client address the listener observed, the method, path, accepting
port, body size and body MD5, so the smoke can read which address reached
the origin and whether a refused upload ever arrived.
"""
import hashlib
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from eicar import eicar_bytes

LOG_PATH = "/tmp/av-requests.jsonl"
CLEAN_FILLER_LINES = 40
_log_lock = threading.Lock()


def record(entry: dict) -> None:
    line = json.dumps(entry, sort_keys=True)
    with _log_lock:
        with open(LOG_PATH, "a", encoding="ascii") as f:
            f.write(line + "\n")
    print(line, file=sys.stderr, flush=True)


def handler_for(name: str, eicar: bytes) -> type:
    class Handler(BaseHTTPRequestHandler):
        def echo_line(self, extra: str = "") -> str:
            return f"server={name} port={self.server.server_port} client={self.client_address[0]}{extra}\n"

        def log_message(self, fmt: str, *args) -> None:  # quiet; record() logs
            return

        def reply(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def note(self, body: bytes) -> None:
            record({
                "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "client": self.client_address[0],
                "method": self.command,
                "path": self.path,
                "port": self.server.server_port,
                "size": len(body),
                "md5": hashlib.md5(body).hexdigest(),
            })

        def do_GET(self) -> None:
            self.note(b"")
            # The query is logged but does not select the object, so a
            # client can fetch one object under distinct URLs.
            path = self.path.split("?", 1)[0]
            if path == "/":
                self.reply(200, self.echo_line().encode("ascii"), "text/plain")
            elif path == "/clean.txt":
                filler = "".join(f"clean line {i:03d} from {name}\n" for i in range(CLEAN_FILLER_LINES))
                self.reply(200, (self.echo_line() + filler).encode("ascii"), "text/plain")
            elif path == "/eicar.txt":
                self.reply(200, eicar, "application/octet-stream")
            else:
                self.reply(404, b"not found\n", "text/plain")

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b""
            self.note(body)
            if self.path.split("?", 1)[0] != "/upload":
                self.reply(404, b"not found\n", "text/plain")
                return
            digest = hashlib.md5(body).hexdigest()
            self.reply(200, self.echo_line(f" method=POST size={len(body)} md5={digest}").encode("ascii"), "text/plain")

    return Handler


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit("usage: server.py NAME PORT [PORT ...]")
    handler = handler_for(sys.argv[1], eicar_bytes())
    servers = [ThreadingHTTPServer(("0.0.0.0", int(port)), handler) for port in sys.argv[2:]]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
