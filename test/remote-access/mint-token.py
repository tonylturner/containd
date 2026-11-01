# SPDX-License-Identifier: Apache-2.0
"""Mint a session-less lab JWT for this isolated fixture's configured secret."""
import base64
import hashlib
import hmac
import json
import time


def encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


header = encode(b'{"alg":"HS256","typ":"JWT"}')
claims = encode(json.dumps({
    "sub": "remote-access-smoke",
    "role": "admin",
    "exp": int(time.time()) + 3600,
}).encode())
payload = header + b"." + claims
signature = hmac.new(
    b"remote-access-smoke-local-only", payload, hashlib.sha256
).digest()
print((payload + b"." + encode(signature)).decode())
