#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Filter native I/O unchanged, then derive a labelled short-CPF mutation."""
import hashlib
import json
from pathlib import Path
import struct
import sys


def records(data):
    if data[:4] != b'\xd4\xc3\xb2\xa1' or len(data) < 24:
        raise ValueError('requires little endian microsecond classic pcap')
    pos = 24
    while pos < len(data):
        if pos + 16 > len(data):
            raise ValueError('short pcap record')
        sec, usec, size, wire = struct.unpack_from('<IIII', data, pos)
        end = pos + 16 + size
        if size != wire or end > len(data):
            raise ValueError('truncated capture')
        yield sec, usec, data[pos + 16:end]
        pos = end


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def write(path, header, packets):
    with path.open('wb') as out:
        out.write(header)
        for sec, usec, raw in packets:
            out.write(struct.pack('<IIII', sec, usec, len(raw), len(raw)))
            out.write(raw)


def short_udp(raw):
    ip_size = (raw[14] & 15) * 4
    udp_start = 14 + ip_size
    payload_start = udp_start + 8
    original = raw[payload_start:]
    if raw[23] != 17 or original[:6] != bytes.fromhex('020002800800'):
        raise ValueError('requires captured native two-item class 1 CPF')
    offset = len(original) - 1
    packet = bytearray(raw[:-1])
    struct.pack_into('!H', packet, 16, len(packet) - 14)
    struct.pack_into('!H', packet, 24, 0)
    struct.pack_into('!H', packet, 24, checksum(bytes(packet[14:udp_start])))
    length = len(packet) - udp_start
    struct.pack_into('!H', packet, udp_start + 4, length)
    struct.pack_into('!H', packet, udp_start + 6, 0)
    pseudo = packet[26:34] + struct.pack('!BBH', 0, 17, length)
    struct.pack_into('!H', packet, udp_start + 6, checksum(bytes(pseudo + packet[udp_start:])) or 65535)
    return bytes(packet), offset


def derive(parent, out):
    data = parent.read_bytes()
    selected = [(i, p) for i, p in enumerate(records(data), 1) if p[2][23] == 17]
    if not selected:
        raise ValueError('no native I/O packets')
    native = out / 'native-io.pcap'
    write(native, data[:24], [p for _, p in selected])
    (out / 'native-io.lineage.json').write_text(json.dumps({
        'parent': parent.name, 'parent_sha256': hashlib.sha256(data).hexdigest(),
        'parent_frames': [i for i, _ in selected], 'operation': 'filter UDP records; packet bytes unchanged',
    }, indent=2) + '\n')
    sec, usec, raw = selected[0][1]
    mutated, offset = short_udp(raw)
    write(out / 'udp-short-mutation.pcap', data[:24], [(sec, usec, mutated)])
    (out / 'udp-short-mutation.mutation.json').write_text(json.dumps({
        'parent': native.name, 'parent_sha256': hashlib.sha256(native.read_bytes()).hexdigest(),
        'parent_frame': 1, 'transport_payload_offset': offset, 'removed_hex': raw[-1:].hex(),
        'operation': 'remove final UDP payload byte; retain CPF declared item length; recompute IPv4/UDP lengths and checksums',
    }, indent=2) + '\n')


if __name__ == '__main__':
    derive(Path(sys.argv[1]), Path(sys.argv[2]))
