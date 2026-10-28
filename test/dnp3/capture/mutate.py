#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Flip one data CRC in a named good classic Ethernet pcap; retain provenance."""
import hashlib
import json
from pathlib import Path
import struct
import sys


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    n = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while n >> 16:
        n = (n & 65535) + (n >> 16)
    return (~n) & 65535


def crc16(data):
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xa6bc if crc & 1 else 0)
    return (~crc) & 65535


def mutate(source, target, mode="data-crc"):
    original = Path(source).read_bytes()
    wire = bytearray(original)
    if wire[:4] != b"\xd4\xc3\xb2\xa1" or struct.unpack_from("<I", wire, 20)[0] != 1:
        raise RuntimeError("classic little-endian Ethernet pcap required")
    pos, record = 24, 0
    while pos < len(wire):
        record += 1
        length = struct.unpack_from("<I", wire, pos + 8)[0]
        packet = pos + 16
        ip = packet + 14
        if wire[packet + 12:packet + 14] != b"\x08\x00" or wire[ip + 9] != 6:
            pos = packet + length
            continue
        tcp = ip + (wire[ip] & 15) * 4
        data = tcp + (wire[tcp + 12] >> 4) * 4
        rest = wire[data:packet + length]
        if rest[:2] == b"\x05\x64" and len(rest) >= 15 and rest[10] & 0xc0 == 0xc0 and rest[12] == 1:
            size = rest[2] - 5
            frame_length = 10 + size + 2 * ((size + 15) // 16)
            if size < 3 or frame_length > len(rest):
                raise RuntimeError("mutation target is not a complete good link frame")
            metadata = {"mode": mode}
            if mode == "data-crc":
                offset = data + frame_length - 1
                wire[offset] ^= 1
                metadata.update(xor=1, recipe="xor data CRC byte by 1, recompute changed packet TCP checksum")
            elif mode == "header-crc":
                offset = data + 8
                wire[offset] ^= 1
                # End at this captured packet. This is an explicit truncation
                # of capture records, not an invented network EOF/FIN.
                wire = wire[:packet + length]
                metadata.update(xor=1, recipe="retain records through target packet; xor header CRC byte by 1; repair TCP checksum",
                                unframed_payload_bytes=len(rest))
            elif mode == "qualifier":
                offset = data + 15  # first qualifier: transport + app ctl/fc + group/variation
                if wire[offset] != 6:
                    raise RuntimeError("named parent first read must use all-objects qualifier")
                wire[offset] = 12  # reserved range, no guessed value layout
                crc_offsets = []
                block, remaining = data + 10, size
                while remaining:
                    count = min(16, remaining)
                    crc_offset = block + count
                    struct.pack_into("<H", wire, crc_offset, crc16(wire[block:crc_offset]))
                    crc_offsets.append(crc_offset)
                    block, remaining = crc_offset + 2, remaining - count
                metadata.update(old_value=6, new_value=12, dnp_crc_byte_offsets=crc_offsets,
                                recipe="set first read qualifier 0x06 to reserved 0x0c; repair data CRCs and TCP checksum")
            else:
                raise RuntimeError("unknown mutation mode")
            # Repair only the changed TCP checksum. Original offload bytes in
            # other packets remain unmodified and explicitly documented.
            tcp_length = struct.unpack_from("!H", wire, ip + 2)[0] - (tcp - ip)
            wire[tcp + 16:tcp + 18] = b"\0\0"
            pseudo = bytes(wire[ip + 12:ip + 20]) + b"\0\x06" + struct.pack("!H", tcp_length)
            value = checksum(pseudo + bytes(wire[tcp:tcp + tcp_length]))
            struct.pack_into("!H", wire, tcp + 16, value)
            Path(target).write_bytes(wire)
            Path(target).with_suffix(".mutation.json").write_text(json.dumps({
                "parent": Path(source).name, "parent_sha256": hashlib.sha256(original).hexdigest(),
                "frame": record, "pcap_byte_offset": offset,
                "tcp_checksum_byte_offset": tcp + 16, **metadata
            }, indent=2) + "\n")
            return
        pos = packet + length
    raise RuntimeError("no complete opendnp3 read found for CRC mutation")


if __name__ == "__main__":
    mutate(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "data-crc")
