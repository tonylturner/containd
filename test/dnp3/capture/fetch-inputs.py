#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch only checksum-locked source inputs; run inside the generator build."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import urllib.request
import zipfile

lock = json.loads(Path(sys.argv[1]).read_text())
root = Path(sys.argv[2])
root.mkdir(parents=True, exist_ok=True)
for name, source in lock.items():
    data = urllib.request.urlopen(source["url"], timeout=90).read()
    if hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise RuntimeError(f"{name}: source checksum mismatch")
    dest = root / name
    dest.mkdir()
    if name == "opendnp3":
        subprocess.run(["tar", "xz", "--strip-components=1", "-C", str(dest)],
                       input=data, check=True)
    else:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for entry in archive.infolist():
                # Remove the archive's one top-level directory; reject traversal.
                rel = Path(*Path(entry.filename).parts[1:])
                if rel.is_absolute() or ".." in rel.parts:
                    raise RuntimeError(f"{name}: unsafe archive member")
                if not rel.parts or entry.is_dir():
                    continue
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(entry))
