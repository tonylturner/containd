#!/usr/bin/env python3
"""Deterministic Modbus/TCP client for the smoke harness.

usage: client.py <mode> <host> <port> [--source IP] [--value N]

modes:
  read            FC 3 read of registers 0-1
  write           FC 6 write of register 1
  readwrite       a read, then a write, on one TCP connection
  read-split      one read whose MBAP header and PDU go out as two TCP
                  segments 300 ms apart
  read-coalesced  two reads (transactions 1 and 2) in one TCP segment
  diag            FC 8 diagnostics (sub-function 0, return query data)
  pid-nonzero     two FC 3 reads (transactions 1 and 2) on one connection
                  whose MBAP protocol identifier is 1 instead of 0: content
                  the firewall cannot vouch for inside a valid frame
  bad-length      one MBAP header whose length field is 1, below the valid
                  2..254, so the frame boundary is lost; nothing follows it,
                  so a server that gives up on it closes without unread data

pid-nonzero prints PID_NONZERO_PORT and bad-length prints BAD_LENGTH_PORT
(the client's TCP port) before any reply, so the harness can find the
connection's events.

Exit codes: 0 success; 1 failure (connect, read, or any other error); 2 usage
error; 3 the connection was established (and, for readwrite, the read
succeeded) but the write, diagnostics, nonzero-PID or bad-length request got
no response; stderr then names the cause (a reset, a close or a timeout).
"""
import socket
import struct
import sys
import time

TIMEOUT_SECONDS = 4.0
MODES = (
    "persistent",
    "read",
    "write",
    "readwrite",
    "read-split",
    "read-coalesced",
    "diag",
    "pid-nonzero",
    "bad-length",
)
WRITE_ADDRESS = 1
DEFAULT_WRITE_VALUE = 0x1234
NONZERO_PROTOCOL_ID = 1
BAD_MBAP_LENGTH = 1


class WriteStageError(Exception):
    pass


def recv_exact(conn: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
    return bytes(data)


def build_request(mode: str, transaction_id: int, value: int, protocol_id: int = 0) -> bytes:
    unit_id = 1
    if mode == "read":
        pdu = struct.pack(">BHH", 3, 0, 2)
    elif mode == "write":
        pdu = struct.pack(">BHH", 6, WRITE_ADDRESS, value)
    elif mode == "diag":
        pdu = struct.pack(">BHH", 8, 0, 0x1234)
    else:
        raise ValueError(f"unsupported mode: {mode}")
    header = struct.pack(">HHHB", transaction_id, protocol_id, len(pdu) + 1, unit_id)
    return header + pdu


def exchange(conn: socket.socket, mode: str, transaction_id: int, value: int) -> str:
    conn.sendall(build_request(mode, transaction_id, value))
    return read_response(conn, mode, transaction_id)


def read_response(conn: socket.socket, mode: str, transaction_id: int) -> str:
    mbap = recv_exact(conn, 7)
    response_id, protocol_id, length = struct.unpack(">HHH", mbap[:6])
    if protocol_id != 0 or length < 2 or response_id != transaction_id:
        raise RuntimeError("invalid modbus response header")
    pdu = recv_exact(conn, length - 1)
    function_code = pdu[0]
    if mode == "diag":
        return f"DIAG_REPLY fc={function_code}"
    if function_code & 0x80:
        raise RuntimeError(f"modbus exception response: fc={function_code} code={pdu[1] if len(pdu) > 1 else 'unknown'}")
    if mode == "read":
        if function_code != 3 or len(pdu) < 2:
            raise RuntimeError("unexpected modbus read response")
        byte_count = pdu[1]
        if byte_count != 4 or len(pdu) != 6:
            raise RuntimeError(f"unexpected read byte count: {byte_count}")
        values = struct.unpack(">HH", pdu[2:6])
        return f"READ_OK {values[0]} {values[1]}"
    if function_code != 6 or len(pdu) != 5:
        raise RuntimeError("unexpected modbus write response")
    address, written = struct.unpack(">HH", pdu[1:5])
    return f"WRITE_OK {address} {written}"


def run(mode: str, host: str, port: int, source: str, value: int) -> int:
    source_address = (source, 0) if source else None
    with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS, source_address=source_address) as conn:
        conn.settimeout(TIMEOUT_SECONDS)
        if mode == "persistent":
            print(f"PERSISTENT_PORT {conn.getsockname()[1]}", flush=True)
            for transaction_id, stage in ((10, "read"), (11, "write"), (12, "read")):
                try:
                    print(exchange(conn, stage, transaction_id, value), flush=True)
                except Exception as exc:  # noqa: BLE001
                    print(f"{stage.upper()}_FAILED {exc}", flush=True)
                    if transaction_id == 10:
                        return 1
                    break
            return 0
        if mode == "read":
            print(exchange(conn, "read", 1, value), flush=True)
            return 0
        if mode == "read-split":
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            request = build_request("read", 1, value)
            conn.sendall(request[:7])
            time.sleep(0.3)
            conn.sendall(request[7:])
            print(read_response(conn, "read", 1), flush=True)
            return 0
        if mode == "read-coalesced":
            conn.sendall(build_request("read", 1, value) + build_request("read", 2, value))
            print(read_response(conn, "read", 1), flush=True)
            print(read_response(conn, "read", 2), flush=True)
            return 0
        if mode == "pid-nonzero":
            print(f"PID_NONZERO_PORT {conn.getsockname()[1]}", flush=True)
            for transaction_id in (1, 2):
                try:
                    conn.sendall(build_request("read", transaction_id, value, NONZERO_PROTOCOL_ID))
                    print(read_response(conn, "read", transaction_id), flush=True)
                except Exception as exc:  # noqa: BLE001
                    raise WriteStageError(str(exc)) from exc
            return 0
        if mode == "bad-length":
            print(f"BAD_LENGTH_PORT {conn.getsockname()[1]}", flush=True)
            try:
                conn.sendall(struct.pack(">HHHB", 1, 0, BAD_MBAP_LENGTH, 1))
                print(read_response(conn, "read", 1), flush=True)
            except Exception as exc:  # noqa: BLE001
                raise WriteStageError(str(exc)) from exc
            return 0
        transaction_id = 1
        if mode == "readwrite":
            print(exchange(conn, "read", transaction_id, value), flush=True)
            transaction_id = 2
        stage = "diag" if mode == "diag" else "write"
        try:
            print(exchange(conn, stage, transaction_id, value), flush=True)
        except Exception as exc:  # noqa: BLE001
            raise WriteStageError(str(exc)) from exc
    return 0


def parse_args(argv: list[str]) -> tuple[str, str, int, str, int]:
    if len(argv) < 4 or argv[1] not in MODES:
        raise ValueError(f"usage: client.py <{'|'.join(MODES)}> <host> <port> [--source IP] [--value N]")
    mode, host, port = argv[1], argv[2], int(argv[3])
    source, value = "", DEFAULT_WRITE_VALUE
    rest = argv[4:]
    while rest:
        if len(rest) < 2 or rest[0] not in ("--source", "--value"):
            raise ValueError(f"unexpected arguments: {' '.join(rest)}")
        if rest[0] == "--source":
            source = rest[1]
        else:
            value = int(rest[1], 0)
            if not 0 <= value <= 0xFFFF:
                raise ValueError("--value must be 0..65535")
        rest = rest[2:]
    return mode, host, port, source, value


def main() -> int:
    try:
        mode, host, port, source, value = parse_args(sys.argv)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    try:
        return run(mode, host, port, source, value)
    except WriteStageError as exc:
        print(f"{mode.upper()}_FAILED stage=request {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001
        print(f"{mode.upper()}_FAILED {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
