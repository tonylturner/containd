#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify that captured endpoint sources match the independently pinned wheel."""
import hashlib
import json
import pathlib
import sys
import zipfile

lock = json.loads(pathlib.Path(__file__).with_name("source-lock.json").read_text())
wheel = pathlib.Path(sys.argv[1])
assert hashlib.sha256(wheel.read_bytes()).hexdigest() == lock["wheel"]["sha256"]
with zipfile.ZipFile(wheel) as archive:
    for name, digest in lock["files"].items():
        assert hashlib.sha256(archive.read(name)).hexdigest() == digest, name
print(f"Official wheel and {len(lock['files'])} installed source/metadata files match")
