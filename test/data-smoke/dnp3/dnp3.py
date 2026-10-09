#!/usr/bin/env python3
"""Minimal DNP3-over-TCP master and outstation for the US smoke harness.

Not a DNP3 stack: it builds and parses single-frame, single-fragment
messages (IEEE 1815 link frames with CRCs, one transport segment, one
application fragment), which is all scripts/smoke-dpi.sh needs.

usage:
  dnp3.py server                       outstation on 0.0.0.0:20000
  dnp3.py read      HOST [--source IP]  FC 1 class 0 read; expects the FC 129
                                        response and then an FC 130
                                        unsolicited response
  dnp3.py operate   HOST [--source IP]  FC 5 direct operate (CROB g12v1)
  dnp3.py operate-nr HOST [--source IP] FC 6 direct operate, no ack

Exit codes (clients): 0 success; 1 failure; 2 usage error; 3 connected and
sent, but the expected response never came.

The outstation appends every decoded request to /tmp/dnp3-requests.jsonl
and writes /tmp/dnp3-state.json ({"operations": N, "requests": N}) after
each request; an FC 3/4/5/6 control request increments "operations". The
smoke harness reads them to prove a denied control never reached it.
"""
import json
import os
import socket
import struct
import sys
import time

PORT = 20000
MASTER_ADDR = 1
OUTSTATION_ADDR = 10
REQUEST_LOG = os.environ.get("DNP3_REQUEST_LOG", "/tmp/dnp3-requests.jsonl")
STATE_FILE = os.environ.get("DNP3_STATE_FILE", "/tmp/dnp3-state.json")
TIMEOUT = 4.0

FC_READ = 0x01
FC_DIRECT_OPERATE = 0x05
FC_DIRECT_OPERATE_NR = 0x06
FC_RESPONSE = 0x81
FC_UNSOLICITED = 0x82
CONTROL_FCS = (0x03, 0x04, 0x05, 0x06)


def _crc_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
        table.append(crc)
    return table


CRC_TABLE = _crc_table()


def crc16(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = (crc >> 8) ^ CRC_TABLE[(crc ^ b) & 0xFF]
    return (~crc) & 0xFFFF


def link_frame(control: int, dst: int, src: int, user: bytes) -> bytes:
    header = bytes([0x05, 0x64, 5 + len(user), control]) + struct.pack("<HH", dst, src)
    out = bytearray(header + struct.pack("<H", crc16(header)))
    for i in range(0, len(user), 16):
        block = user[i : i + 16]
        out += block + struct.pack("<H", crc16(block))
    return bytes(out)


def recv_exact(conn: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
    return bytes(data)


def read_frame(conn: socket.socket) -> tuple[int, bytes]:
    """Read one link frame; return (control, CRC-stripped user data)."""
    header = recv_exact(conn, 10)
    if header[0:2] != b"\x05\x64":
        raise ValueError("bad start octets")
    if struct.unpack("<H", header[8:10])[0] != crc16(header[:8]):
        raise ValueError("bad header CRC")
    user_len = header[2] - 5
    user = bytearray()
    remaining = user_len
    while remaining > 0:
        size = min(16, remaining)
        block = recv_exact(conn, size + 2)
        user += block[:size]
        remaining -= size
    return header[3], bytes(user)


def app_message(seq: int, app_control: int, fc: int, body: bytes) -> bytes:
    transport = 0xC0 | (seq & 0x3F)  # FIR | FIN
    return bytes([transport, app_control | (seq & 0x0F), fc]) + body


# Master (DIR=1, PRM=1, unconfirmed user data) and outstation (DIR=0, PRM=1).
MASTER_CTRL = 0xC4
OUTSTATION_CTRL = 0x44

READ_CLASS0 = bytes([60, 1, 0x06])  # g60v1, all objects
CROB = bytes([12, 1, 0x28, 0x01, 0x00, 0x00, 0x00]) + bytes([0x03, 0x01]) + struct.pack("<II", 100, 100) + b"\x00"
ANALOG = bytes([30, 1, 0x00, 0x00, 0x00, 0x01]) + struct.pack("<i", 4242)


def master_request(seq: int, fc: int, body: bytes) -> bytes:
    return link_frame(MASTER_CTRL, OUTSTATION_ADDR, MASTER_ADDR, app_message(seq, 0xC0, fc, body))


def outstation_message(seq: int, app_control: int, fc: int, body: bytes) -> bytes:
    return link_frame(OUTSTATION_CTRL, MASTER_ADDR, OUTSTATION_ADDR, app_message(seq, app_control, fc, b"\x00\x00" + body))


# ---- outstation -------------------------------------------------------------

STATE = {"operations": 0, "requests": 0}


def write_state() -> None:
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="ascii") as f:
        json.dump(STATE, f)
    os.replace(tmp, STATE_FILE)


def serve() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", PORT))
        srv.listen(16)
        write_state()
        print(f"dnp3 outstation listening on 0.0.0.0:{PORT}", flush=True)
        while True:
            conn, addr = srv.accept()
            with conn:
                conn.settimeout(5.0)
                sent_unsolicited = False
                while True:
                    try:
                        _, user = read_frame(conn)
                    except (ConnectionError, OSError, ValueError, socket.timeout):
                        break
                    if len(user) < 3:
                        continue
                    seq, fc = user[1] & 0x0F, user[2]
                    STATE["requests"] += 1
                    if fc in CONTROL_FCS:
                        STATE["operations"] += 1
                    with open(REQUEST_LOG, "a", encoding="ascii") as log:
                        log.write(json.dumps({"time": time.time(), "peer": addr[0], "function_code": fc}) + "\n")
                    write_state()
                    if fc == FC_READ:
                        conn.sendall(outstation_message(seq, 0xC0, FC_RESPONSE, ANALOG))
                        if not sent_unsolicited:
                            time.sleep(0.2)
                            conn.sendall(outstation_message(0, 0xD0, FC_UNSOLICITED, ANALOG))
                            sent_unsolicited = True
                    elif fc == FC_DIRECT_OPERATE:
                        conn.sendall(outstation_message(seq, 0xC0, FC_RESPONSE, user[3:]))


# ---- master -----------------------------------------------------------------


def connect(host: str, source: str) -> socket.socket:
    src = (source, 0) if source else None
    conn = socket.create_connection((host, PORT), timeout=TIMEOUT, source_address=src)
    conn.settimeout(TIMEOUT)
    return conn


def await_fc(conn: socket.socket, want: int) -> bool:
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        try:
            _, user = read_frame(conn)
        except (socket.timeout, ConnectionError, OSError):
            return False
        if len(user) >= 3 and user[2] == want:
            return True
    return False


def client(mode: str, host: str, source: str) -> int:
    conn = connect(host, source)
    with conn:
        if mode == "read":
            conn.sendall(master_request(1, FC_READ, READ_CLASS0))
            if not await_fc(conn, FC_RESPONSE):
                print("READ_FAILED no response", file=sys.stderr)
                return 3
            print("READ_OK", flush=True)
            if not await_fc(conn, FC_UNSOLICITED):
                print("UNSOLICITED_FAILED none received", file=sys.stderr)
                return 3
            print("UNSOLICITED_OK", flush=True)
            return 0
        if mode == "operate":
            conn.sendall(master_request(2, FC_DIRECT_OPERATE, CROB))
            if not await_fc(conn, FC_RESPONSE):
                print("OPERATE_FAILED no response", file=sys.stderr)
                return 3
            print("OPERATE_OK", flush=True)
            return 0
        if mode == "operate-nr":
            conn.sendall(master_request(3, FC_DIRECT_OPERATE_NR, CROB))
            time.sleep(1.0)
            print("OPERATE_NR_SENT", flush=True)
            return 0
    return 2


def main() -> int:
    args = sys.argv[1:]
    if args == ["server"]:
        serve()
        return 0
    if len(args) not in (2, 4) or args[0] not in ("read", "operate", "operate-nr"):
        print(__doc__, file=sys.stderr)
        return 2
    source = ""
    if len(args) == 4:
        if args[2] != "--source":
            print(__doc__, file=sys.stderr)
            return 2
        source = args[3]
    try:
        return client(args[0], args[1], source)
    except Exception as exc:  # noqa: BLE001
        print(f"{args[0].upper()}_FAILED {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
