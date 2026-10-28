#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inventory installed source, not an unverifiable upstream checkout claim."""
import hashlib
import importlib.metadata
import json

dist = importlib.metadata.distribution("pymodbus")
assert dist.version == "3.11.4"
files = {}
for name in sorted(dist.files):
    if str(name).endswith((".py", "METADATA", "LICENSE")):
        files[str(name)] = hashlib.sha256(dist.locate_file(name).read_bytes()).hexdigest()
print(json.dumps({
    "package": "pymodbus", "version": dist.version, "license": "BSD-3-Clause",
    "base_image": "modbusspan-tools@sha256:2bbeea56d58c5192ebda1d8314637c3c9995341df21e733110405040bae77fbc",
    "python_dependencies": [],
    "source": "installed distribution inside immutable bootstrap image; source hashes below, no upstream commit asserted",
    "files": files,
}, indent=2))
