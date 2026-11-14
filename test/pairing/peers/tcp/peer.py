#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic real TCP peers, not an independent conformance oracle.

Unlike lib60870's sample receiver, this IEC fixture reads a stream, including
one-byte APCI header writes. DNP framing/CRC uses the existing smoke fixture.
Every case has its own client port, making receiver pcaps independently useful.
"""
import json
import pathlib
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, "/fixtures/data-smoke/dnp3")
import dnp3

RESULTS = pathlib.Path("/results")
PORTS = {"modbus": 502, "dnp3": 20000, "iec104": 2404}


def log(**fields):
    print(json.dumps({"time": time.time(), **fields}), flush=True)


def iec(cause):
    return bytes.fromhex("680e000000002e01") + bytes([cause, 0, 1, 0, 101, 0, 0, 2])


def wires(protocol, kind="normal"):
    if protocol == "modbus":
        return bytes.fromhex("000100000006010300000002"), bytes.fromhex("00010000000701030400010002")
    if protocol == "iec104":
        response = bytes.fromhex("680e0000000001010300010065000001") if kind == "autonomous" else iec(7)
        return iec(6), response
    q = dnp3.master_request(0, 1, dnp3.READ_CLASS0)
    if kind == "large":
        # Exactly 2048 application bytes: 406 g30v1 + two g1v2 objects.
        body = bytes([30, 1, 1]) + struct.pack("<HH", 0, 405) + (b"\x01\x01\x00\x00\x00" * 406)
        body += bytes([1, 2, 0, 0, 1, 1, 1])
        app = b"\xc0\x81\x00\x00" + body
        assert len(app) == 2048
        frames = []
        for i, off in enumerate(range(0, len(app), 249)):
            transport = i | (0x40 if off == 0 else 0) | (0x80 if off + 249 >= len(app) else 0)
            frames.append(dnp3.link_frame(0x44, 1, 10, bytes([transport]) + app[off:off + 249]))
        return q, b"".join(frames)
    control, fc = (0xD0, 130) if kind == "autonomous" else ((0xE0, 129) if kind == "confirm" else (0xC0, 129))
    return q, dnp3.outstation_message(0, control, fc, dnp3.ANALOG)


def read_unit(c, protocol):
    if protocol == "modbus":
        head = dnp3.recv_exact(c, 6)
        return head + dnp3.recv_exact(c, int.from_bytes(head[4:6], "big"))
    if protocol == "iec104":
        head = dnp3.recv_exact(c, 2)
        assert head[0] == 0x68
        return head + dnp3.recv_exact(c, head[1])
    _, user = dnp3.read_frame(c)
    return user


def serve_connection(c, addr, protocol):
    case = json.loads((RESULTS / "case.json").read_text())
    c.settimeout(3)
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if case.get("delayed_ack"):
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 0)
    _, response = wires(protocol, case.get("kind", "normal"))
    try:
        if case["fate"] == "missing":
            time.sleep(0.15)
        else:
            request = read_unit(c, protocol)
            log(event="request", protocol=protocol, peer=addr, wire=request.hex())
        if case.get("kind") == "confirmed-link":
            # A non-final confirmed-user-data link is unsupported in enforce.
            response = dnp3.link_frame(0x53, 1, 10, b"\x40\xc0\x81\x00\x00")
        c.sendall(response)
        log(event="response-write", peer=addr, wire=response.hex())
        if case.get("boundary") == "response":
            c.recv(1)
            raise AssertionError("outside-envelope session ended without a reset")
        if case.get("kind") == "confirm":
            _, confirm = dnp3.read_frame(c)
            assert confirm[2] == 0, confirm.hex()
            log(event="confirm", peer=addr, wire=confirm.hex())
        time.sleep(0.1)
    except (OSError, ConnectionError) as exc:
        event = "server-reset" if case.get("boundary") and isinstance(exc, ConnectionResetError) else "server-error"
        log(event=event, peer=addr, error=str(exc))
    finally:
        c.close()


def listen(protocol):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORTS[protocol]))
    s.listen(32)
    log(event="listen", protocol=protocol)
    while True:
        c, addr = s.accept()
        threading.Thread(target=serve_connection, args=(c, addr, protocol), daemon=True).start()


def client(case):
    protocol = case["protocol"]
    q, r = wires(protocol, case.get("kind", "normal"))
    if case.get("upstream"):
        # The upstream sample requires select-before-operate at IOA 5000.
        q = bytes.fromhex("680e000000002d010600010088130081")
        r = bytes.fromhex("680e000000002d010700010088130081")
    if case.get("kind") == "session":
        q, r = bytes.fromhex("680407000000"), bytes.fromhex("68040b000000")
    s = socket.socket()
    if case.get("window"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, 1)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, int(case.get("nodelay", True)))
    if case.get("delayed_ack"):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 0)
    s.settimeout(3)
    s.bind(("0.0.0.0", case["port"]))
    s.connect((case["host"], PORTS[protocol]))
    log(event="connected", port=case["port"], rcvbuf=s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
        clamp=s.getsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP),
        nodelay=s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY),
        request_wire=q.hex(), response_wire=r.hex())
    if case.get("upstream"):
        s.sendall(bytes.fromhex("680407000000"))
        assert read_unit(s, protocol) == bytes.fromhex("68040b000000"), "STARTDT confirmation"
        r = r[:4] + b"\x02\x00" + r[6:]
    log(event="expected", request_wire=q.hex(), response_wire=r.hex())
    held = None
    if case.get("independent"):
        held = socket.socket()
        held.settimeout(2)
        held.bind(("0.0.0.0", case["port"] + 1000))
        held.connect((case["host"], PORTS[protocol]))
        held.sendall(q[:1])
    start = time.monotonic()
    got = b""
    reset_seen = False
    try:
        if case["fate"] != "missing":
            step = case.get("step", len(q))
            for off in range(0, len(q), step):
                s.sendall(q[off:off + step])
                if off + step < len(q):
                    time.sleep(case.get("delay", 0.005))
        if case.get("slow"):
            time.sleep(0.3)
        while len(got) < len(r):
            b = s.recv(len(r) - len(got))
            if not b:
                break
            got += b
        if case.get("kind") == "confirm" and got:
            s.sendall(dnp3.master_request(0, 0, b""))
        log(event="received", wire=got.hex(), elapsed=time.monotonic() - start)
    except OSError as exc:
        reset_seen = isinstance(exc, ConnectionResetError)
        log(event="client-error", error=str(exc), elapsed=time.monotonic() - start, wire=got.hex())
    finally:
        s.close()
        if held:
            try:
                assert not held.recv(4096), "partial independent flow delivered data"
            except ConnectionResetError:
                pass
            finally:
                held.close()
    if case["expect"] == "pass":
        assert got == r, f"positive response {len(got)}/{len(r)} bytes"
    else:
        assert not got, f"denied response delivered {got.hex()}"
    if case.get("boundary"):
        assert reset_seen, "outside-envelope client did not receive a connection reset"


if __name__ == "__main__":
    if sys.argv[1] == "server":
        threads = [threading.Thread(target=listen, args=(p,)) for p in PORTS]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    else:
        client(json.loads(sys.argv[2]))
