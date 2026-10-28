#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Download and authenticate the unmodified reference stack archives."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

for name, source in json.loads(Path(sys.argv[1]).read_text()).items():
    data = urllib.request.urlopen(source['url'], timeout=90).read()
    if hashlib.sha256(data).hexdigest() != source['sha256']:
        raise RuntimeError(f'{name}: source checksum mismatch')
    dest = Path(sys.argv[2]) / name
    dest.mkdir(parents=True)
    subprocess.run(['tar', 'xz', '--strip-components=1', '-C', str(dest)],
                   input=data, check=True)
