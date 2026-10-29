# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic Ethernet/IPv4/TCP content-identification captures.

Run from the repository root: python3 test/identify/generate.py
No network traffic or third-party dependencies are required.
"""
from pathlib import Path
import socket
import struct

DEST = Path(__file__).resolve().parents[2] / "pkg/dp/pcap/testdata"


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(port, reverse, seq, ack, flags, data=b""):
    src, dst = (socket.inet_aton(x) for x in ("10.0.0.1", "10.0.0.2"))
    sport, dport = 49152, port
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(data))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + data)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(data), 0, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return bytes.fromhex("0000000000020000000000010800") + ip + tcp + data


def capture(name, port, request, response, midstream=False):
    frames = [] if midstream else [
        packet(port, False, 99, 0, 2),
        packet(port, True, 499, 100, 0x12),
        packet(port, False, 100, 500, 0x10),
    ]
    frames += [packet(port, False, 100, 500, 0x18, request),
               packet(port, True, 500, 100 + len(request), 0x18, response)]
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        data += struct.pack("<IIII", 1736935200, i * 10000, len(frame), len(frame)) + frame
    assert len(frames) > 0 and len(data) > 24
    (DEST / f"{name}.pcap").write_bytes(data)


request = bytes.fromhex("000100000006010300000002")
response = bytes.fromhex("000100000007010304000a000b")
for name, port in [("modbus-1502", 1502), ("modbus-20000", 20000), ("modbus-502", 502)]:
    capture(name, port, request, response)
capture("midstream", 1502, request, response, midstream=True)
capture("iec104-12404", 12404, bytes.fromhex("680407000000"), bytes.fromhex("68040b000000"))
