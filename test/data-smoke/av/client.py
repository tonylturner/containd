#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""HTTP client for the scanning-gate smoke.

Usage: client.py get IP PORT PATH TIMEOUT_SECONDS
       client.py post IP PORT PATH TIMEOUT_SECONDS eicar|clean

Makes one HTTP/1.1 request with "Connection: close", reads the reply to
end of stream and prints exactly one outcome line, exiting 0 when the
network gave an answer:
  status=CODE bytes=N complete=yes|no eicar=yes|no line=<first body line>
                        a response arrived; complete says whether the body
                        matched its Content-Length; eicar says whether the
                        body carries the EICAR test file, whose line is
                        printed as "(eicar)" so no log carries the string
  timeout               no answer to the connection attempt (dropped)
  refused               the destination answered with a reset
  reset                 the connection was reset after it opened
  closed                the connection closed before a response head
  unreachable           the client has no route, or ICMP reported none
Any other failure exits 2 with the reason on stderr, so a broken probe
never reads as a refusal.
"""
import errno
import ipaddress
import socket
import sys

from eicar import eicar_bytes

UNREACHABLE = {errno.EHOSTUNREACH, errno.ENETUNREACH}
RESET = {errno.ECONNRESET, errno.EPIPE}


def usage() -> int:
    print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
    return 2


def main() -> int:
    argv = sys.argv[1:]
    if len(argv) < 5 or argv[0] not in ("get", "post"):
        return usage()
    try:
        ip = str(ipaddress.ip_address(argv[1]))
        port = int(argv[2])
        path = argv[3]
        timeout = float(argv[4])
    except ValueError as exc:
        print(f"client error: {exc}", file=sys.stderr)
        return 2
    eicar = eicar_bytes()
    body = b""
    if argv[0] == "post":
        if len(argv) != 6 or argv[5] not in ("eicar", "clean"):
            return usage()
        body = eicar if argv[5] == "eicar" else b"clean upload from the scanning-gate smoke\n" * 8
        head = (
            f"POST {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n"
            f"Content-Type: application/octet-stream\r\nContent-Length: {len(body)}\r\n\r\n"
        )
    elif len(argv) != 5:
        return usage()
    else:
        head = f"GET {path} HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n"
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
        print(f"client error: {exc}", file=sys.stderr)
        return 2
    reply = b""
    with sock:
        try:
            sock.sendall(head.encode("ascii") + body)
            while chunk := sock.recv(65536):
                reply += chunk
        except socket.timeout:
            pass
        except OSError as exc:
            if exc.errno not in RESET:
                print(f"client error: {exc}", file=sys.stderr)
                return 2
            if not reply:
                print("reset")
                return 0
    if b"\r\n\r\n" not in reply:
        print("closed")
        return 0
    head_part, payload = reply.split(b"\r\n\r\n", 1)
    lines = head_part.decode("ascii", "replace").split("\r\n")
    status = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "?"
    length = None
    for header in lines[1:]:
        key, _, value = header.partition(":")
        if key.strip().lower() == "content-length":
            length = int(value.strip())
    complete = "yes" if length is None or len(payload) == length else "no"
    has_eicar = "yes" if eicar in payload else "no"
    # The EICAR string never goes into a log line: a body that carries it is
    # reported as "(eicar)" so no smoke log file contains the test string.
    first = "(eicar)" if has_eicar == "yes" else payload.split(b"\n", 1)[0].decode("ascii", "replace")
    print(f"status={status} bytes={len(payload)} complete={complete} eicar={has_eicar} line={first}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
