#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate captured pcaps and write their inventory and checksums."""

import hashlib
import json
import pathlib
import struct
import sys

BASE_IMAGE = (
    "debian@sha256:"
    "99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3"
)
CAPTURES = {
    "dns": (
        "DNS A, AAAA, TXT queries and an NXDOMAIN response",
        ["bind9.txt"],
    ),
    "tls": (
        "TLS 1.2 and TLS 1.3 handshakes with SNI and ALPN offers",
        ["openssl.txt"],
    ),
    "http": (
        "HTTP/1.1 GET and POST requests with Host, User-Agent and Content-Type",
        ["apache2.txt", "curl.txt"],
    ),
    "ssh": (
        "SSH version exchange, key exchange and password-authenticated session",
        ["openssh-client.txt", "sshpass.txt"],
    ),
    "ntp": (
        "NTP client request and server response",
        ["chrony.txt", "ntpsec-ntpdate.txt"],
    ),
    "snmp": (
        "SNMPv2c GET of three system objects and a short sysName walk",
        ["snmp.txt", "snmpd.txt"],
    ),
    "rdp": (
        "RDP X.224 connection negotiation and TLS security selection",
        ["freerdp2-x11.txt", "xrdp.txt"],
    ),
    "smb": (
        "SMB2/3 negotiation, session setup, tree connect and file read",
        ["samba.txt", "smbclient.txt"],
    ),
}


def read_packets(path):
    data = path.read_bytes()
    if len(data) < 24 or data[:4] != b"\xd4\xc3\xb2\xa1":
        raise ValueError(f"{path.name}: expected little-endian classic pcap")
    offset = 24
    frames = 0
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError(f"{path.name}: truncated record header")
        captured = struct.unpack_from("<I", data, offset + 8)[0]
        original = struct.unpack_from("<I", data, offset + 12)[0]
        if captured != original or offset + 16 + captured > len(data):
            raise ValueError(f"{path.name}: truncated or snaplen-truncated frame")
        offset += 16 + captured
        frames += 1
    if not frames:
        raise ValueError(f"{path.name}: no packets captured")
    return frames, len(data)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: finalize.py OUTPUT-DIR IMAGE-ID < package-inventory")
    directory = pathlib.Path(sys.argv[1])
    image_id = sys.argv[2]
    packages = sys.stdin.read().splitlines()
    captures = []
    total_bytes = 0
    for protocol, (shows, license_files) in CAPTURES.items():
        name = f"{protocol}.pcap"
        frames, size = read_packets(directory / name)
        if size > 200 * 1024:
            raise ValueError(f"{name} exceeds 200 KiB ({size} bytes)")
        total_bytes += size
        captures.append(
            {
                "protocol": protocol,
                "pcap": name,
                "frames": frames,
                "bytes": size,
                "shows": shows,
                "licenses": license_files,
            }
        )
    if total_bytes >= 1024 * 1024:
        raise ValueError(f"capture set exceeds 1 MiB ({total_bytes} bytes)")

    manifest = {
        "version": 1,
        "provenance": {
            "source": "test/it/capture/capture.sh and entrypoint.sh",
            "generator": "unmodified Debian clients and servers; tcpdump",
            "generator_image_id": image_id,
            "base_image": BASE_IMAGE,
            "package_inventory": packages,
            "topology": "Private Docker bridge 198.51.100.0/24; no published ports",
            "capture_side": "tcpdump in the server container network namespace on eth0",
            "license": (
                "Source-package notices in test/it/capture/LICENSES; "
                "tcpdump notice is tcpdump.txt"
            ),
        },
        "captures": captures,
    }
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    lines = []
    for protocol, _ in CAPTURES.items():
        digest = hashlib.sha256((directory / f"{protocol}.pcap").read_bytes()).hexdigest()
        lines.append(f"{digest}  {protocol}.pcap")
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"frames={sum(item['frames'] for item in captures)} bytes={total_bytes}")


if __name__ == "__main__":
    main()
