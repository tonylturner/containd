#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Export independent per-CIP-object observations from tshark PDML."""
import csv
import argparse
import pathlib
import subprocess
import xml.etree.ElementTree as ET

FIELDS = [
    "enip.command", "enip.status", "enip.session",
    "cip.sc", "cip.rr", "cip.genstat", "cip.class", "cip.instance",
    "cip.attribute", "cip.msp.num_services",
]
PREFS = ["-o", "tcp.desegment_tcp_streams:TRUE", "-o", "enip.desegment:TRUE",
         "-o", "enip.o2t_run_idle:TRUE", "-o", "enip.t2o_run_idle:FALSE"]


def own_fields(node):
    """Do not flatten descendant CIP objects into the enclosing MSP."""
    for child in node:
        if child.tag == "proto" and child.get("name") == "cip":
            continue
        if child.tag == "field":
            yield child
        yield from own_fields(child)


def export(pcap, transport):
    version = subprocess.check_output(["tshark", "--version"], text=True)
    if "TShark (Wireshark) 4.6.7 " not in version:
        raise RuntimeError("oracle requires tshark 4.6.7")
    pdml = subprocess.check_output(["tshark", "-n", "-r", str(pcap), *PREFS, "-T", "pdml"])
    pcap.with_suffix(".pdml").write_bytes(pdml)
    rows = []
    for packet in ET.fromstring(pdml).findall("packet"):
        all_fields = {f.get("name"): f.get("show", "") for f in packet.iter("field")}
        tcp, udp = all_fields.get("tcp.payload", ""), all_fields.get("udp.payload", "")
        if (transport == "tcp" and not tcp) or (transport == "udp" and not udp):
            continue
        if not tcp and not udp:
            continue
        objects = packet.findall(".//proto[@name='cip']") or [None]
        for index, obj in enumerate(objects):
            fields = {}
            if obj is not None:
                for field in own_fields(obj):
                    fields.setdefault(field.get("name"), field.get("show", ""))
            row = [all_fields["frame.number"], "0", str(index), tcp, udp]
            for name in FIELDS:
                row.append(all_fields.get(name, "") if name.startswith("enip.") else fields.get(name, ""))
            rows.append(row)
    with pcap.with_suffix(".expected.tsv").open("w") as out:
        writer = csv.writer(out, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL)
        writer.writerow(["frame.number", "pdu", "object", "tcp.payload", "udp.payload", *FIELDS])
        writer.writerows(rows)
    return sorted({int(row[0]) for row in rows})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=["tcp", "udp"], required=True)
    parser.add_argument("pcap", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    for filename in args.pcap:
        print(filename, export(filename, args.transport))
