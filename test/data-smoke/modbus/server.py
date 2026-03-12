#!/usr/bin/env python3
import os
import socket
import struct


HOST = os.environ.get("MODBUS_HOST", "0.0.0.0")
PORT = int(os.environ.get("MODBUS_PORT", "502"))
REGISTER_COUNT = int(os.environ.get("MODBUS_REGISTER_COUNT", "128"))
REGISTERS = [i for i in range(REGISTER_COUNT)]


def recv_exact(conn: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
    return bytes(data)


def exception_pdu(function_code: int, code: int) -> bytes:
    return bytes([function_code | 0x80, code])


def handle_request(unit_id: int, pdu: bytes) -> bytes:
    if len(pdu) < 1:
        return exception_pdu(0, 3)
    function_code = pdu[0]

    if function_code == 3:
        if len(pdu) != 5:
            return exception_pdu(function_code, 3)
        address, quantity = struct.unpack(">HH", pdu[1:5])
        if quantity == 0 or quantity > 125:
            return exception_pdu(function_code, 3)
        if address + quantity > len(REGISTERS):
            return exception_pdu(function_code, 2)
        payload = bytearray([function_code, quantity * 2])
        for value in REGISTERS[address : address + quantity]:
            payload.extend(struct.pack(">H", value))
        return bytes(payload)

    if function_code == 6:
        if len(pdu) != 5:
            return exception_pdu(function_code, 3)
        address, value = struct.unpack(">HH", pdu[1:5])
        if address >= len(REGISTERS):
            return exception_pdu(function_code, 2)
        REGISTERS[address] = value
        return pdu[:5]

    return exception_pdu(function_code, 1)


def serve() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(16)
        print(f"modbus server listening on {HOST}:{PORT}", flush=True)
        while True:
            conn, addr = server.accept()
            print(f"accepted connection from {addr[0]}:{addr[1]}", flush=True)
            with conn:
                conn.settimeout(5.0)
                while True:
                    try:
                        mbap = recv_exact(conn, 7)
                    except (ConnectionError, OSError, socket.timeout):
                        break
                    transaction_id, protocol_id, length = struct.unpack(">HHH", mbap[:6])
                    if protocol_id != 0 or length < 2:
                        break
                    unit_id = mbap[6]
                    try:
                        pdu = recv_exact(conn, length - 1)
                    except (ConnectionError, OSError, socket.timeout):
                        break
                    response_pdu = handle_request(unit_id, pdu)
                    response_mbap = struct.pack(">HHHB", transaction_id, 0, len(response_pdu) + 1, unit_id)
                    conn.sendall(response_mbap + response_pdu)


if __name__ == "__main__":
    serve()
