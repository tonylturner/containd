# SPDX-License-Identifier: Apache-2.0
"""Simulate a pre-upgrade stored service fault with the appliance stopped.

Public candidate/import writes reject new faults. This mirrors the direct
running-snapshot write in pkg/cp/config/effective_test.go:installStoredFault.
Only the WireGuard listen-interface reference changes; storage metadata and
the separately referenced IDS bank remain intact.
"""
import json
import sqlite3

with sqlite3.connect("/data/config.db") as db:
    raw, = db.execute("SELECT data FROM configs WHERE key='running'").fetchone()
    config = json.loads(raw)
    wg = config["services"]["vpn"]["wireguard"]
    assert wg["enabled"] is True
    wg["listenInterfaces"] = ["missing-ra-interface"]
    result = db.execute(
        "UPDATE configs SET data=? WHERE key='running'",
        (json.dumps(config),),
    )
    assert result.rowcount == 1
print("Installed stored WireGuard-only listen-interface fault in running snapshot")
