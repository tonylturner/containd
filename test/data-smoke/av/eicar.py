#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The EICAR test file for the scanning-gate smoke, assembled at runtime.

The 68-byte EICAR string is split into pieces so that no file in the
repository carries the contiguous string that antivirus scanners on
development machines flag. eicar_bytes() rebuilds it and checks its MD5
against the published value, which is also the hash the smoke installs as
a ClamAV signature.
"""
import hashlib

EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SIZE = 68

_PIECES = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EIC",
    "AR-STANDARD-ANTIVIR",
    "US-TEST-FILE!$H+H*",
)


def eicar_bytes() -> bytes:
    data = "".join(_PIECES).encode("ascii")
    digest = hashlib.md5(data).hexdigest()
    if len(data) != EICAR_SIZE or digest != EICAR_MD5:
        raise RuntimeError(f"EICAR assembly is wrong: {len(data)} bytes, md5 {digest}")
    return data
