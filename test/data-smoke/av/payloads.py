# SPDX-License-Identifier: Apache-2.0
"""Deterministic clean objects shared by the smoke's sender and receiver."""


def clean_upload() -> bytes:
    return b"clean upload from the scanning-gate smoke\n" * 8


def clean_download(name: str, port: int, client: str) -> bytes:
    line = f"server={name} port={port} client={client}\n"
    filler = "".join(f"clean line {i:03d} from {name}\n" for i in range(40))
    return (line + filler).encode("ascii")
