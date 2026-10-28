#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate independent coverage and authenticate the exact fixture inventory."""
import csv
import hashlib
import json
from pathlib import Path
import shutil
import sys
import xml.etree.ElementTree as ET


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def finalize(out, inputs):
    names = ["link-only", "startup-integrity", "class-range", "unsolicited", "crob", "iin-error", "large-response", "crc-flip", "header-crc", "qualifier-tail"]
    rows = {}
    for name in names:
        with (out / (name + ".expected.tsv")).open() as source:
            rows[name] = list(csv.DictReader(source, delimiter="\t"))
        if not rows[name]:
            raise RuntimeError(f"{name}: empty oracle")
        pdml = ET.parse(out / (name + ".pdml"))
        for reason in ["tcp.analysis.retransmission", "tcp.analysis.lost_segment", "tcp.analysis.out_of_order"]:
            if pdml.find(f".//field[@name='{reason}']") is not None:
                raise RuntimeError(f"{name}: pristine generation has {reason}; regenerate rather than pretending contiguous")

    def require(name, predicate, reason):
        if not any(predicate(r) for r in rows[name]):
            raise RuntimeError(f"{name}: missing independent coverage: {reason}")

    require("link-only", lambda r: r["dnp3.src"] and not r["dnp3.tr.seq"], "link-only exchange")
    require("startup-integrity", lambda r: r["dnp3.al.func"] == "129", "integrity response")
    require("class-range", lambda r: r["group"] == "60" and r["dnp3.al.func"] == "1", "class read")
    for qualifier in ["0", "1"]:
        require("class-range", lambda r: r["qualifier"] == qualifier and r["dnp3.al.func"] == "1", "range width " + qualifier)
    require("unsolicited", lambda r: r["dnp3.al.func"] == "130" and r["points.json"] not in ["", "[]"], "unsolicited point values")
    for fc in ["3", "4", "5"]:
        require("crob", lambda r: r["dnp3.al.func"] == fc and '"crob"' in r["points.json"], "CROB function " + fc)
    require("iin-error", lambda r: r["dnp3.al.iin"] and int(r["dnp3.al.iin"], 0) & 2, "OBJECT_UNKNOWN IIN")
    require("large-response", lambda r: r["dnp3.tr.fir"] == "False", "transport segmentation")
    require("large-response", lambda r: r["dnp3.al.fin"] == "False", "application fragmentation")
    require("large-response", lambda r: r["dnp3.al.fir"] == "False" and r["dnp3.al.func"] == "129", "application continuation")
    mutation = json.loads((out / "crc-flip.mutation.json").read_text())
    if mutation["parent_sha256"] != digest(out / mutation["parent"]):
        raise RuntimeError("mutation parent no longer matches")
    scenarios, inventory = [], []
    for name in names:
        expected = {"conformance": ["dnp3.data_crc"] if name == "crc-flip" else [], "undecoded": [], "eof_partial": False}
        if name in ["crc-flip", "header-crc", "qualifier-tail"]:
            meta = json.loads((out / (name + ".mutation.json")).read_text())
            if meta["parent_sha256"] != digest(out / meta["parent"]):
                raise RuntimeError("mutation parent no longer matches")
            expected["mutation"] = meta
        if name == "header-crc":
            expected["frame_error"] = "dnp3 header CRC mismatch"
        if name == "qualifier-tail":
            expected["conformance"] = ["dnp3.object_walk"]
            expected["undecoded"] = ["dnp3.object_qualifier"]
        expectation = out / (name + ".expectations.json")
        expectation.write_text(json.dumps(expected, indent=2) + "\n")
        files = [name + ".pcap", name + ".expected.tsv", expectation.name]
        scenario = {"name": name, "pcap": files[0], "oracle": files[1], "expectations": files[2], "transport": "tcp",
                    "checksum_offload": "server-side Docker bridge capture; endpoint TX offload checksums retained, not an L4 checksum oracle",
                    "oracle_frames": sorted({int(r["frame.number"]) for r in rows[name]}), "contiguous": True}
        if name in ["crc-flip", "header-crc", "qualifier-tail"]:
            scenario["assets"] = [name + ".mutation.json"]
            files += scenario["assets"]
        scenarios.append(scenario)
        inventory += files
    # Keep source locks and observed package/image metadata with the fixture.
    for source, target in [(inputs / "source-lock.json", "source-lock.json"),
                           (out / "logs/image.json", "generator-image.json"),
                           (out / "logs/packages.txt", "generator-packages.txt")]:
        shutil.copyfile(source, out / target)
        scenarios[0].setdefault("assets", []).append(target)
        inventory.append(target)
    input_hashes = {p.name: digest(p) for p in sorted(inputs.iterdir()) if p.is_file()}
    manifest = {"version": 1, "protocol": "dnp3", "provenance": {
        "source": "opendnp3 3.1.2 commit 26b4c01e4839bbbda8866655e086471c4917ee53 (archived upstream); dependencies in source-lock.json",
        "generator": "generator-image.json and generator-packages.txt; Release CMake, C++14, TLS/tests disabled; Debian snapshot 20261001T000000Z",
        "oracle": "tshark 4.6.7; -2; tcp.desegment_tcp_streams:TRUE tcp.reassemble_out_of_order:TRUE tcp.check_checksum:FALSE ip.defragment:TRUE dnp3.desegment:TRUE; PDML object-subtree normalization",
        "license": "Apache-2.0; adapted opendnp3 examples retain upstream notices under capture/LICENSES",
        "topology": "independent opendnp3 master and outstation on a private Docker bridge, TCP/20000, link master=1 outstation=10; no containd in path",
        "capture_side": "tcpdump on outstation eth0 via network-namespace sidecar; no host ports",
        "inputs_sha256": json.dumps(input_hashes, separators=(",", ":")),
    }, "scenarios": scenarios}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (out / "SHA256SUMS").write_text("".join(digest(out / name) + "  " + name + "\n" for name in sorted(inventory)))
    if sum((out / f).stat().st_size for f in inventory) > 2 * 1024 * 1024:
        raise RuntimeError("fixture inventory exceeds 2 MiB; reduce captured traffic, never drop required coverage")


if __name__ == "__main__":
    finalize(Path(sys.argv[1]), Path(sys.argv[2]))
