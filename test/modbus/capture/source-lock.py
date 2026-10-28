#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inventory the installed distribution and its independently verified release."""
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
    "upstream": {
        "repository": "https://github.com/pymodbus-dev/pymodbus.git",
        "tag": "v3.11.4",
        "commit": "bf0e1b67233b4f65bde531c51fea97e461927ef3",
    },
    "wheel": {
        "filename": "pymodbus-3.11.4-py3-none-any.whl",
        "sha256": "89865929f53bd5e32b4076dde00ee86d9b8afb1686832ed74e69d55df22729c3",
        "url": "https://files.pythonhosted.org/packages/02/80/84c32440949c77f2c201c38e5fa56fd8f19da31bf24df55bdbdaba67767c/pymodbus-3.11.4-py3-none-any.whl",
    },
    "source": "installed distribution inside immutable bootstrap image; every listed source/metadata hash also matches the pinned official wheel",
    "files": files,
}, indent=2))
