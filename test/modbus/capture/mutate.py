#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Derive explicitly labelled negative pcaps; never generate positive traffic."""
import hashlib
import json
import pathlib
import struct
import sys


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def main(directory):
    directory = pathlib.Path(directory)
    parent = directory / "operations.pcap"
    original = parent.read_bytes()
    assert original[:4] == b"\xd4\xc3\xb2\xa1", "expected little-endian classic pcap"
    records = []
    offset = 24
    while offset < len(original):
        sec, usec, size, wire = struct.unpack_from("<IIII", original, offset)
        assert size == wire
        packet = original[offset + 16:offset + 16 + size]
        records.append((sec, usec, packet, offset + 16))
        offset += 16 + size
        ihl = (packet[14] & 15) * 4
        tcp = 14 + ihl
        start = tcp + (packet[tcp + 12] >> 4) * 4
        if len(packet) > start:
            break
    assert len(records) == 4 and records[-1][2][start + 7] == 1
    result = {}
    for name in ("pid-nonzero", "bad-length", "truncation", "bad-layout"):
        sec, usec, raw, absolute = records[-1]
        packet = bytearray(raw)
        payload = packet[start:]
        before = payload.hex()
        if name == "pid-nonzero":
            payload[2:4] = b"\0\x01"
            changed = [2, 3]
        elif name == "bad-length":
            payload[4:6] = b"\0\x01"  # unframeable MBAP length
            changed = [4, 5]
        elif name == "truncation":
            payload = payload[:-2]  # original MBAP length, incomplete at EOF
            changed = [10, 11]
        else:
            payload[4:6] = b"\0\x05"  # frameable but incomplete FC1 quantity
            payload = payload[:-1]
            changed = [4, 5, 11]
        packet = packet[:start] + payload
        struct.pack_into("!H", packet, 16, len(packet) - 14)
        packet[24:26] = b"\0\0"
        struct.pack_into("!H", packet, 24, checksum(bytes(packet[14:tcp])))
        packet[tcp + 16:tcp + 18] = b"\0\0"
        pseudo = packet[26:34] + b"\0\x06" + struct.pack("!H", len(packet) - tcp)
        struct.pack_into("!H", packet, tcp + 16, checksum(bytes(pseudo + packet[tcp:])))
        output = bytearray(original[:24])
        for s, u, p, _ in records[:-1]:
            output += struct.pack("<IIII", s, u, len(p), len(p)) + p
        output += struct.pack("<IIII", sec, usec, len(packet), len(packet)) + packet
        (directory / f"{name}.pcap").write_bytes(output)
        result[name] = {
            "parent": parent.name, "parent_sha256": hashlib.sha256(original).hexdigest(),
            "frame": 4, "tcp_payload_offsets": changed,
            "parent_file_offsets": [absolute + start + n for n in changed],
            "before_payload": before, "after_payload": payload.hex(),
            "recipe": "retain opening handshake and first request only; edit payload; recompute IPv4/TCP lengths/checksums",
        }
    (directory / "mutations.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
