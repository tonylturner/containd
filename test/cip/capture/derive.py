#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Filter UDP evidence and derive one explicitly synthetic UDP/44818 negative.

No protocol serialization from this script is claimed as endpoint traffic.
"""
import pathlib
import struct


def records(data):
    assert data[:4] == b"\xd4\xc3\xb2\xa1"
    pos = 24
    while pos < len(data):
        header = data[pos:pos + 16]
        sec, usec, size, wire_size = struct.unpack("<IIII", header)
        assert size == wire_size
        yield sec, usec, data[pos + 16:pos + 16 + size]
        pos += 16 + size


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def write(path, header, packets):
    with path.open("wb") as out:
        out.write(header)
        for sec, usec, raw in packets:
            out.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            out.write(raw)


root = pathlib.Path(__file__).resolve().parents[1] / "testdata"
source = (root / "explicit-io.pcap").read_bytes()
packets = list(records(source))
write(root / "udp-enip-io.pcap", source[:24], [p for p in packets if p[2][23] == 17])
# Capture record 8 is the first valid UCMM read request. Preserve Ethernet/IP
# endpoints and its encapsulation, drop the last payload byte (CIP EPATH byte,
# original transport-payload offset 47), replace TCP with UDP to destination 44818.
sec, usec, raw = packets[7]
ip_size = (raw[14] & 15) * 4
tcp = 14 + ip_size
payload_start = tcp + ((raw[tcp + 12] >> 4) * 4)
payload = raw[payload_start:]
assert payload[0:2] == b"\x6f\x00" and len(payload) == 48
payload = payload[:-1]
udp = bytearray(struct.pack("!HHHH", 49152, 44818, 8 + len(payload), 0) + payload)
pseudo = raw[26:34] + struct.pack("!BBH", 0, 17, len(udp))
struct.pack_into("!H", udp, 6, checksum(pseudo + udp) or 65535)
ip = bytearray(raw[14:tcp])
ip[9] = 17
struct.pack_into("!H", ip, 2, len(ip) + len(udp))
struct.pack_into("!H", ip, 10, 0)
struct.pack_into("!H", ip, 10, checksum(ip))
write(root / "udp-short-mutation.pcap", source[:24], [(sec, usec, raw[:14] + ip + udp)])
