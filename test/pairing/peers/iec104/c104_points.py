# SPDX-License-Identifier: Apache-2.0
"""Point configuration only: no request callbacks or response-stage code.

c104's upstream Server handlers select, execute, confirm, terminate and reject.
Each command TypeID gets a station so every command can use IOA 5000.
"""

import time

import c104

server = c104.Server(ip="0.0.0.0", port=2404, select_timeout_ms=5000)
for typ in [*range(45, 52), *range(58, 65)]:
    station = server.add_station(common_address=typ)
    station.add_point(
        io_address=5000,
        type=c104.Type(typ),
        command_mode=c104.CommandMode.DIRECT
        if typ in (51, 64)
        else c104.CommandMode.SELECT_AND_EXECUTE,
    )
    if typ not in (51, 64):
        station.add_point(
            io_address=5002, type=c104.Type(typ), command_mode=c104.CommandMode.DIRECT
        )
station = server.add_station(common_address=1)
for ioa, typ in ((100, 1), (104, 3), (110, 13), (5000, 15)):
    station.add_point(io_address=ioa, type=c104.Type(typ))
server.start()
# Autonomous stimuli use the public send API, not request-dependent replies.
# They show wire encoding, not the stack deciding when these causes are due.
while not server.has_active_connections:
    time.sleep(0.05)
station.signal_initialized(cause=c104.Coi.LOCAL_POWER_ON)
point = station.get_point(io_address=100)
for cause in (c104.Cot.PERIODIC, c104.Cot.BACKGROUND_SCAN, c104.Cot.SPONTANEOUS):
    point.transmit(cause=cause)
while True:
    time.sleep(1)
