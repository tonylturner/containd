#!/usr/bin/env python3
import socket
import struct
import sys


def recv_exact(conn: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
    return bytes(data)


def build_request(mode: str, transaction_id: int = 1) -> bytes:
    unit_id = 1
    if mode == "read":
        pdu = struct.pack(">BHH", 3, 0, 2)
    elif mode == "write":
        pdu = struct.pack(">BHH", 6, 1, 0x1234)
    else:
        raise ValueError(f"unsupported mode: {mode}")
    header = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id)
    return header + pdu


def transact(conn: socket.socket, mode: str, transaction_id: int) -> str:
    conn.sendall(build_request(mode, transaction_id))
    mbap = recv_exact(conn, 7)
    _, protocol_id, length = struct.unpack(">HHH", mbap[:6])
    if protocol_id != 0 or length < 2:
        raise RuntimeError("invalid modbus response header")
    pdu = recv_exact(conn, length - 1)
    return check_response(mode, pdu)


def run(mode: str, host: str, port: int) -> int:
    with socket.create_connection((host, port), timeout=4.0) as conn:
        conn.settimeout(4.0)
        print(transact(conn, mode, 1))
    return 0


def run_persistent(host: str, port: int) -> int:
    """Send read, write, read on ONE TCP connection.

    Prints the client port, then one line per step. Enforcement may block
    the connection after the write, so only the first read must succeed.
    """
    with socket.create_connection((host, port), timeout=4.0) as conn:
        conn.settimeout(4.0)
        print(f"PERSISTENT_PORT {conn.getsockname()[1]}", flush=True)
        for transaction_id, mode in ((10, "read"), (11, "write"), (12, "read")):
            try:
                print(transact(conn, mode, transaction_id), flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"{mode.upper()}_FAILED {exc}", flush=True)
                if transaction_id == 10:
                    return 1
                break
    return 0


def check_response(mode: str, pdu: bytes) -> str:
    function_code = pdu[0]
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
    address, value = struct.unpack(">HH", pdu[1:5])
    return f"WRITE_OK {address} {value}"


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: client.py <read|write|persistent> <host> <port>", file=sys.stderr)
        return 2
    mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    try:
        if mode == "persistent":
            return run_persistent(host, port)
        return run(mode, host, port)
    except Exception as exc:  # noqa: BLE001
        print(f"{mode.upper()}_FAILED {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
