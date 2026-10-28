#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Normalize tshark PDML object subtrees, never comma-joined field lists."""
import csv
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def field(node, name):
    return node.find(f".//field[@name='{name}']")


def show(node, name):
    item = field(node, name)
    return "" if item is None else item.get("show", "")


def integer(node, name):
    text = show(node, name)
    return None if not text else int(text, 0)


def points(node):
    result = []
    for child in node:
        index = integer(child, "dnp3.al.index")
        if index is None:
            index = integer(child, "dnp3.al.point_index")
        if index is None:
            continue
        point = {"index": index}
        control = field(child, "dnp3.ctl.op")
        if control is not None:
            point["crob"] = {
                "control": int(control.attrib["unmaskedvalue"], 16),
                "count": integer(child, "dnp3.al.count"),
                "on_time_ms": integer(child, "dnp3.al.on_time"),
                "off_time_ms": integer(child, "dnp3.al.off_time"),
                "status": integer(child, "dnp3.al.ctrlstatus"),
            }
            if any(v is None for v in point["crob"].values()):
                raise RuntimeError("incomplete independent CROB observation")
        result.append(point)
    return result


def normalize(source, target):
    common = ["dnp3.src", "dnp3.dst", "dnp3.tr.fir", "dnp3.tr.fin", "dnp3.tr.seq",
              "dnp3.al.func", "dnp3.al.fir", "dnp3.al.fin", "dnp3.al.con", "dnp3.al.uns", "dnp3.al.seq", "dnp3.al.iin"]
    columns = ["frame.number", "tcp.payload", "pdu", "object"] + common + ["group", "variation", "qualifier", "start", "stop", "quantity", "points.json"]
    count = 0
    with Path(target).open("w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=columns, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        for _, packet in ET.iterparse(source, events=("end",)):
            if packet.tag != "packet":
                continue
            frame = show(packet, "frame.number")
            payload = field(packet, "tcp.payload")
            if payload is None:
                raise RuntimeError(f"frame {frame}: no original TCP payload")
            protos = packet.findall("proto[@name='dnp3']")
            for pdu, proto in enumerate(protos if protos else [ET.Element("empty")]):
                row = {"frame.number": frame, "tcp.payload": payload.attrib["value"], "pdu": pdu}
                row.update({key: show(proto, key) for key in common})
                objects = proto.findall(".//field[@name='dnp3.al.obj']")
                for ordinal, obj in enumerate(objects if objects else [None]):
                    record = dict(row, object=ordinal, **{"points.json": "[]"})
                    if obj is not None:
                        gv = int(obj.attrib["show"], 0)
                        record["group"], record["variation"] = gv >> 8, gv & 255
                        prefix, rc = integer(obj, "dnp3.al.objq.prefix"), integer(obj, "dnp3.al.objq.range")
                        if prefix is None or rc is None:
                            raise RuntimeError(f"frame {frame}: object qualifier missing")
                        record["qualifier"] = prefix << 4 | rc
                        record["start"] = show(obj, "dnp3.al.range.start")
                        record["stop"] = show(obj, "dnp3.al.range.stop")
                        record["quantity"] = show(obj, "dnp3.al.range.quantity")
                        record["points.json"] = json.dumps(points(obj), separators=(",", ":"))
                    writer.writerow(record)
                    count += 1
            packet.clear()
    if not count:
        raise RuntimeError("empty independent oracle")


if __name__ == "__main__":
    normalize(sys.argv[1], sys.argv[2])
