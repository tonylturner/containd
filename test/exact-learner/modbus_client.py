#!/usr/bin/env python3
"""Small Modbus/TCP client used by the exact learner receiver smoke."""

import argparse
import socket
import struct


def receive_exact(conn: socket.socket, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        chunk = conn.recv(size - len(received))
        if not chunk:
            raise ConnectionError("server closed before replying")
        received.extend(chunk)
    return bytes(received)


def transact(host: str, port: int, function: int, address: int, value: int) -> bytes:
    if function == 3:
        pdu = struct.pack(">BHH", function, address, value)
    elif function == 5:
        pdu = struct.pack(">BHH", function, address, value)
    else:
        raise ValueError(f"unsupported function code {function}")
    unit = 1
    transaction = 1
    request = struct.pack(">HHHB", transaction, 0, len(pdu) + 1, unit) + pdu
    with socket.create_connection((host, port), timeout=5) as conn:
        conn.settimeout(5)
        conn.sendall(request)
        header = receive_exact(conn, 7)
        response_id, protocol, length = struct.unpack(">HHH", header[:6])
        if response_id != transaction or protocol != 0 or length < 2:
            raise ValueError(f"invalid response MBAP header: {header.hex()}")
        response = receive_exact(conn, length - 1)
    if response[0] != function:
        raise ValueError(f"Modbus exception or unexpected response: {response.hex()}")
    return response


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("read", "coil"))
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--value", type=lambda value: int(value, 0), default=0)
    args = parser.parse_args()
    try:
        if args.mode == "read":
            response = transact(args.host, args.port, 3, 0, 2)
            if len(response) != 6 or response[1] != 4:
                raise ValueError(f"unexpected FC3 response: {response.hex()}")
            first, second = struct.unpack(">HH", response[2:])
            print(f"READ_OK {first} {second}")
        else:
            response = transact(args.host, args.port, 5, 7, args.value)
            address, value = struct.unpack(">HH", response[1:])
            if address != 7 or value != args.value:
                raise ValueError(f"FC5 response did not echo request: {response.hex()}")
            print(f"COIL_OK {address} {value}")
    except (ConnectionError, OSError, ValueError) as exc:
        print(f"REQUEST_FAILED {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
