#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""HTTP listener for the forwarding smoke.

Usage: echo.py NAME PORT [PORT ...]

Every GET is answered with one line naming the listener, the port that
accepted the connection and the client address the listener observed, for
example "server=wan_server port=8080 client=172.30.0.2". The harness reads
the client address to prove source translation.
"""
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def handler_for(name: str) -> type:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = f"server={name} port={self.server.server_port} client={self.client_address[0]}\n".encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit("usage: echo.py NAME PORT [PORT ...]")
    handler = handler_for(sys.argv[1])
    servers = [ThreadingHTTPServer(("0.0.0.0", int(port)), handler) for port in sys.argv[2:]]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
