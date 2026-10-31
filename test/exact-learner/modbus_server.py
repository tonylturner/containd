#!/usr/bin/env python3
"""Receiver-side Modbus/TCP state recorder for exact learner smoke tests."""

import json
import os
import socket
import struct
import time


HOST = "0.0.0.0"
PORT = 502
REGISTERS = list(range(128))
COILS = [False] * 128
WRITES = 0
COIL_WRITES = 0
REQUEST_LOG = "/tmp/modbus-requests.jsonl"
STATE_FILE = "/tmp/modbus-state.json"


def save_state() -> None:
    temporary = STATE_FILE + ".tmp"
    with open(temporary, "w", encoding="ascii") as state:
        json.dump({"writes": WRITES, "coilWrites": COIL_WRITES, "registers": REGISTERS, "coils": COILS}, state)
    os.replace(temporary, STATE_FILE)


def receive_exact(conn: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
    return bytes(data)


def record_request(peer: str, unit: int, protocol: int, pdu: bytes) -> None:
    entry = {
        "time": time.time(),
        "peer": peer,
        "unit_id": unit,
        "protocol_id": protocol,
        "function_code": pdu[0] if pdu else None,
    }
    if len(pdu) == 5:
        address, value = struct.unpack(">HH", pdu[1:])
        entry["address"] = address
        entry["value" if pdu[0] in (5, 6) else "quantity"] = value
    with open(REQUEST_LOG, "a", encoding="ascii") as log:
        log.write(json.dumps(entry) + "\n")


def error(function: int, code: int) -> bytes:
    return bytes((function | 0x80, code))


def handle(unit: int, pdu: bytes) -> bytes:
    global WRITES, COIL_WRITES
    if not pdu:
        return error(0, 3)
    function = pdu[0]
    if function == 3:
        if len(pdu) != 5:
            return error(function, 3)
        address, quantity = struct.unpack(">HH", pdu[1:])
        if quantity < 1 or quantity > 125:
            return error(function, 3)
        if address + quantity > len(REGISTERS):
            return error(function, 2)
        payload = bytearray((function, quantity * 2))
        for value in REGISTERS[address : address + quantity]:
            payload.extend(struct.pack(">H", value))
        return bytes(payload)
    if function == 5:
        if len(pdu) != 5:
            return error(function, 3)
        address, value = struct.unpack(">HH", pdu[1:])
        if address >= len(COILS):
            return error(function, 2)
        if value not in (0, 0xFF00):
            return error(function, 3)
        COILS[address] = value == 0xFF00
        WRITES += 1
        COIL_WRITES += 1
        save_state()
        return pdu[:5]
    return error(function, 1)


def serve() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(16)
        save_state()
        print(f"Modbus receiver listening on {HOST}:{PORT}", flush=True)
        while True:
            conn, address = server.accept()
            with conn:
                conn.settimeout(5)
                while True:
                    try:
                        header = receive_exact(conn, 7)
                        transaction, protocol, length = struct.unpack(">HHH", header[:6])
                        if length < 2:
                            break
                        unit = header[6]
                        pdu = receive_exact(conn, length - 1)
                    except (ConnectionError, OSError, socket.timeout):
                        break
                    record_request(address[0], unit, protocol, pdu)
                    reply = handle(unit, pdu)
                    response_header = struct.pack(">HHHB", transaction, 0, len(reply) + 1, unit)
                    conn.sendall(response_header + reply)


if __name__ == "__main__":
    serve()
