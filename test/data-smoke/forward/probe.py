#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""TCP probe for the forwarding smoke.

Usage: probe.py IP PORT TIMEOUT_SECONDS

Prints exactly one outcome line and exits 0 when the network gave an answer:
  open <response line>  connected; the line is the first line of the
                        listener's reply to GET / (empty if none)
  timeout               no answer to the connection attempt (dropped)
  refused               the destination answered with a reset
  unreachable           the client has no route, or ICMP reported none
Any other failure (bad arguments, name resolution, local socket errors)
exits 2 with the reason on stderr, so a broken probe never reads as a drop.
"""
import errno
import ipaddress
import socket
import sys

UNREACHABLE = {errno.EHOSTUNREACH, errno.ENETUNREACH}


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: probe.py IP PORT TIMEOUT_SECONDS", file=sys.stderr)
        return 2
    try:
        # An IP literal keeps name resolution out of the result.
        ip = str(ipaddress.ip_address(sys.argv[1]))
        port = int(sys.argv[2])
        timeout = float(sys.argv[3])
    except ValueError as exc:
        print(f"probe error: {exc}", file=sys.stderr)
        return 2
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except socket.timeout:
        print("timeout")
        return 0
    except ConnectionRefusedError:
        print("refused")
        return 0
    except OSError as exc:
        if exc.errno in UNREACHABLE:
            print("unreachable")
            return 0
        print(f"probe error: {exc}", file=sys.stderr)
        return 2
    with sock:
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("ascii"))
        reply = b""
        try:
            while chunk := sock.recv(4096):
                reply += chunk
        except socket.timeout:
            pass
    lines = reply.decode("ascii", "replace").split("\r\n\r\n", 1)
    body = lines[1].splitlines()[0] if len(lines) == 2 and lines[1] else ""
    print(f"open {body}".rstrip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
