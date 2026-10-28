#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run cpppo's unmodified simulator with its supported shutdown control API."""
import signal

from cpppo import apidict
from cpppo.server.enip.main import main

control = apidict(5, done=False, disable=False, latency=0.05)
control['timeout'] = 5


def stop(_signal, _frame):
    control.done = True


signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)
raise SystemExit(main(argv=['--no-udp', '--address', '0.0.0.0:44818', 'Value@0x6b/1/1=INT[4]'],
                      server={'control': control}))
