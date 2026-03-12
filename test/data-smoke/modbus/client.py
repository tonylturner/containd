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


def build_request(mode: str) -> bytes:
    unit_id = 1
    if mode == "read":
        pdu = struct.pack(">BHH", 3, 0, 2)
    elif mode == "write":
        pdu = struct.pack(">BHH", 6, 1, 0x1234)
    else:
        raise ValueError(f"unsupported mode: {mode}")
    header = struct.pack(">HHHB", 1, 0, len(pdu) + 1, unit_id)
    return header + pdu


def run(mode: str, host: str, port: int) -> int:
    request = build_request(mode)
    with socket.create_connection((host, port), timeout=4.0) as conn:
        conn.settimeout(4.0)
        conn.sendall(request)
        mbap = recv_exact(conn, 7)
        _, protocol_id, length = struct.unpack(">HHH", mbap[:6])
        if protocol_id != 0 or length < 2:
            raise RuntimeError("invalid modbus response header")
        pdu = recv_exact(conn, length - 1)
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
        print(f"READ_OK {values[0]} {values[1]}")
        return 0
    if function_code != 6 or len(pdu) != 5:
        raise RuntimeError("unexpected modbus write response")
    address, value = struct.unpack(">HH", pdu[1:5])
    print(f"WRITE_OK {address} {value}")
    return 0


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: client.py <read|write> <host> <port>", file=sys.stderr)
        return 2
    mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    try:
        return run(mode, host, port)
    except Exception as exc:  # noqa: BLE001
        print(f"{mode.upper()}_FAILED {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
