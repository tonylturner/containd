#!/usr/bin/env python3
"""Capture received TCP reset attempts at either smoke endpoint, without a GUI."""
import socket
import struct
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
sock.settimeout(0.2)
print("READY", flush=True)
end = time.monotonic() + 12
packets = 0
resets = 0
while time.monotonic() < end:
    try:
        data = sock.recv(65535)
    except socket.timeout:
        continue
    ihl = (data[0] & 15) * 4
    if len(data) < ihl + 20:
        continue
    source, destination = struct.unpack_from("!HH", data, ihl)
    if source not in (1502, 12404) and destination not in (1502, 12404):
        continue
    packets += 1
    if data[ihl + 13] & 4:
        resets += 1
print(f"PACKETS {packets} RESETS {resets}", flush=True)
if packets == 0 or resets != 0:
    raise SystemExit(1)
