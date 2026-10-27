#!/usr/bin/env python3
import json
import os
import socket
import struct
import time


HOST = os.environ.get("MODBUS_HOST", "0.0.0.0")
PORT = int(os.environ.get("MODBUS_PORT", "502"))
REGISTER_COUNT = int(os.environ.get("MODBUS_REGISTER_COUNT", "128"))
REGISTERS = [i for i in range(REGISTER_COUNT)]
# Point state for the smoke harness: every decoded request is appended to the
# request log and the register image is rewritten after each write, so a test
# can prove that a dropped write never reached the server. A request whose
# MBAP protocol identifier is not 0 is logged with that identifier and
# answered like any other, so a test can prove whether the firewall delivered
# nonconformant content; the reply always carries protocol identifier 0.
REQUEST_LOG = os.environ.get("MODBUS_REQUEST_LOG", "/tmp/modbus-requests.jsonl")
STATE_FILE = os.environ.get("MODBUS_STATE_FILE", "/tmp/modbus-state.json")
WRITE_COUNT = 0


def record_request(peer: str, unit_id: int, protocol_id: int, pdu: bytes) -> None:
    entry = {
        "time": time.time(),
        "peer": peer,
        "unit_id": unit_id,
        "protocol_id": protocol_id,
        "function_code": pdu[0] if pdu else None,
    }
    if len(pdu) == 5:
        first, second = struct.unpack(">HH", pdu[1:5])
        entry["address"] = first
        entry["value" if pdu[0] == 6 else "quantity"] = second
    with open(REQUEST_LOG, "a", encoding="ascii") as log:
        log.write(json.dumps(entry) + "\n")


def write_state() -> None:
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="ascii") as state:
        json.dump({"writes": WRITE_COUNT, "registers": REGISTERS}, state)
    os.replace(tmp, STATE_FILE)


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
    global WRITE_COUNT
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
        WRITE_COUNT += 1
        write_state()
        return pdu[:5]

    return exception_pdu(function_code, 1)


def serve() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(16)
        write_state()
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
                    if length < 2:
                        break
                    unit_id = mbap[6]
                    try:
                        pdu = recv_exact(conn, length - 1)
                    except (ConnectionError, OSError, socket.timeout):
                        break
                    record_request(addr[0], unit_id, protocol_id, pdu)
                    response_pdu = handle_request(unit_id, pdu)
                    response_mbap = struct.pack(">HHHB", transaction_id, 0, len(response_pdu) + 1, unit_id)
                    conn.sendall(response_mbap + response_pdu)


if __name__ == "__main__":
    serve()
