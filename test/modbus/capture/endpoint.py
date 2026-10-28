#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unmodified pymodbus endpoints; assertions fail generation on unexpected results."""
import inspect
import json
import sys

import pymodbus
from pymodbus.client import ModbusTcpClient
from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.pdu import diag_message
from pymodbus.server import StartTcpServer

assert pymodbus.__version__ == "3.11.4"


def server():
    devices = {}
    for unit in (1, 2, 3):
        devices[unit] = ModbusDeviceContext(
            co=ModbusSequentialDataBlock(1, [False] * 65536),
            di=ModbusSequentialDataBlock(1, [True] * 65536),
            hr=ModbusSequentialDataBlock(1, [unit] * 65536),
            ir=ModbusSequentialDataBlock(1, [unit + 10] * 65536),
        )
    StartTcpServer(
        context=ModbusServerContext(devices=devices, single=False),
        address=("0.0.0.0", 502),
    )


def client(host, scenario):
    client = ModbusTcpClient(
        host, port=502, source_address=("0.0.0.0", 502 if scenario == "source502" else 0),
        timeout=3, retries=0,
    )
    assert client.connect(), "connect failed"

    def check(response, exception=None):
        assert response.isError() == (exception is not None), repr(response)
        if exception is not None:
            assert response.exception_code == exception, repr(response)
        print(repr(response), flush=True)
        return response

    try:
        if scenario == "source502":
            assert check(client.read_holding_registers(65534, count=2, device_id=1)).registers == [1, 1]
        elif scenario == "operations":
            check(client.read_coils(0, count=9, device_id=1))
            assert all(check(client.read_discrete_inputs(0, count=9, device_id=2)).bits[:9])
            assert check(client.read_holding_registers(100, count=3, device_id=3)).registers == [3] * 3
            assert check(client.read_input_registers(0, count=2, device_id=1)).registers == [11, 11]
            check(client.write_coil(10, True, device_id=1))
            assert check(client.read_coils(10, count=1, device_id=1)).bits[0]
            check(client.write_register(20, 0x1234, device_id=2))
            assert check(client.read_holding_registers(20, count=1, device_id=2)).registers == [0x1234]
            check(client.write_coils(30, [True, False, True, True, False, True, False, True, True], device_id=1))
            assert check(client.read_coils(30, count=9, device_id=1)).bits[:9] == [True, False, True, True, False, True, False, True, True]
            check(client.write_registers(40, [10, 20, 30], device_id=2))
            assert check(client.read_holding_registers(40, count=3, device_id=2)).registers == [10, 20, 30]
            check(client.mask_write_register(address=40, and_mask=0xff00, or_mask=0x0055, device_id=2))
            assert check(client.read_holding_registers(40, count=1, device_id=2)).registers == [0x55]
            r = check(client.readwrite_registers(read_address=100, read_count=2, write_address=200, values=[7, 8], device_id=3))
            assert r.registers == [3, 3]
            assert check(client.read_holding_registers(200, count=2, device_id=3)).registers == [7, 8]
            # Maximum legal quantities and the last wire address, no wraparound.
            check(client.read_coils(65536 - 2000, count=2000, device_id=1))
            check(client.read_discrete_inputs(65536 - 2000, count=2000, device_id=2))
            check(client.read_holding_registers(65536 - 125, count=125, device_id=3))
            check(client.read_input_registers(65536 - 125, count=125, device_id=1))
            check(client.write_coils(65536 - 1968, [True] * 1968, device_id=1))
            check(client.write_registers(65536 - 123, [42] * 123, device_id=2))
            check(client.readwrite_registers(read_address=65536 - 125, read_count=125,
                                           write_address=65536 - 121, values=[43] * 121, device_id=3))
            check(client.read_holding_registers(65535, count=2, device_id=1), exception=2)
            check(client.read_holding_registers(0, count=1, device_id=99), exception=11)
        elif scenario == "diagnostics":
            classes = {
                cls.sub_function_code: cls
                for _, cls in inspect.getmembers(diag_message, inspect.isclass)
                if cls.__name__.endswith("Request") and hasattr(cls, "sub_function_code")
            }
            for sub in (0, 1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 4):
                message = 0x0a00 if sub == 3 else 0
                request = classes[sub](message=message, dev_id=1)
                response = check(client.execute(False, request))
                assert response.sub_function_code == sub, repr(response)
                print(json.dumps({"subfunction": sub, "response": repr(response)}), flush=True)
                # Unknown downstream unit: genuine gateway exception from the
                # server, not an invented diagnostics reply with a subfunction.
                check(client.execute(False, classes[sub](message=message, dev_id=99)), exception=11)
        else:
            raise ValueError(scenario)
    finally:
        client.close()


if __name__ == "__main__":
    if sys.argv[1] == "server":
        server()
    else:
        client(sys.argv[2], sys.argv[3])
