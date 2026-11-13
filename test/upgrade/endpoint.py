# SPDX-License-Identifier: Apache-2.0
"""Live listeners on both the admitted and denied ports; record receiver evidence."""
import http.server
import json
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open('/tmp/requests.jsonl', 'a', encoding='utf-8') as out:
            out.write(json.dumps({'port': self.server.server_port, 'path': self.path}) + '\n')
        body = b'upgrade-origin\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    for port in (18081, 18082):
        server = http.server.ThreadingHTTPServer(('0.0.0.0', port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()
