# SPDX-License-Identifier: Apache-2.0
"""Derive stage observations, never expected stages, from master logs and TCP."""

import csv
import io
import sys
from pathlib import Path


def apdus(chunks):
    """Reassemble each TCP direction, tolerating identical retransmission only."""
    streams = {}
    result = {"TX": [], "RX": []}
    for frame, source, sequence, payload in chunks:
        if not payload:
            continue
        direction = "RX" if source == "2404" else "TX"
        seq = int(sequence)
        data = bytes.fromhex(payload.replace(":", ""))
        state = streams.setdefault(
            direction, {"start": seq, "all": bytearray(), "used": 0}
        )
        offset = seq - state["start"]
        if offset < 0 or offset > len(state["all"]):
            raise ValueError("out-of-order/gapped capture is not supported")
        overlap = min(len(data), len(state["all"]) - offset)
        if state["all"][offset : offset + overlap] != data[:overlap]:
            raise ValueError("conflicting TCP retransmission")
        state["all"].extend(data[overlap:])
        while len(state["all"]) - state["used"] >= 2:
            start = state["used"]
            if state["all"][start] != 0x68:
                raise ValueError("lost IEC APDU boundary")
            size = state["all"][start + 1] + 2
            if size < 6:
                raise ValueError("invalid APDU length")
            if len(state["all"]) - start < size:
                break
            result[direction].append((frame, bytes(state["all"][start : start + size])))
            state["used"] += size
    for state in streams.values():
        if state["used"] != len(state["all"]):
            raise ValueError("incomplete captured APDU")
    return result


def decode(data):
    if data[2] & 1 == 0:
        if len(data) < 15:
            raise ValueError("short I frame")
        return {
            "kind": "I",
            "type": data[6],
            "cot": data[8] & 63,
            "pn": "N" if data[8] & 64 else "P",
            "ca": int.from_bytes(data[10:12], "little"),
            "ioa": int.from_bytes(data[12:15], "little"),
        }
    if data[2] & 3 == 1:
        return {"kind": "S"}
    names = {
        7: "STARTDT-act",
        11: "STARTDT-con",
        19: "STOPDT-act",
        35: "STOPDT-con",
        67: "TESTFR-act",
        131: "TESTFR-con",
    }
    return {"kind": names[data[2]]}


FIELDS = [
    "stack",
    "case",
    "procedure",
    "type",
    "qualifier",
    "variant",
    "direction",
    "request_cot",
    "cot_sequence",
    "reply_types",
    "pn_sequence",
    "control_sequence",
    "optional_stages_observed",
    "status",
    "stage_owner",
    "capture_reference",
]


def analyze(stack, directory):
    cases = []
    raw = {"TX": [], "RX": []}
    current = None
    log = (directory / f"{stack}.master.log").read_text()
    for line in log.splitlines():
        if line.startswith("CASE "):
            _, ident, procedure, typ, qualifier, variant = line.split()
            current = {
                "id": ident,
                "procedure": procedure,
                "type": typ,
                "qualifier": qualifier,
                "variant": variant,
                "units": [],
            }
            cases.append(current)
        elif line.startswith(("TX ", "RX ")):
            direction, hexdata = line.split()
            data = bytes.fromhex(hexdata)
            raw[direction].append(data)
            current["units"].append((direction, data, decode(data)))
        else:
            raise ValueError(f"unexpected master output: {line}")
    chunks = csv.reader(
        io.StringIO((directory / f"{stack}.tcp.tsv").read_text()), delimiter="\t"
    )
    captured = apdus(chunks)
    for direction, units in raw.items():
        if units != [data for _, data in captured[direction]]:
            raise ValueError(f"{stack}: {direction} log does not match captured TCP")
    if len(cases) != 138:
        raise ValueError(f"incomplete request suite: {len(cases)} cases")

    wire = []
    positions = {"TX": 0, "RX": 0}
    rows = []
    autonomous = []
    controls = []
    for case in cases:
        for direction, data, unit in case["units"]:
            frame, _ = captured[direction][positions[direction]]
            positions[direction] += 1
            wire.append([case["id"], frame, direction, data.hex()])
            if unit["kind"] != "I":
                controls.append((direction, unit["kind"]))
            elif direction == "RX" and unit["cot"] in (1, 2, 3, 4):
                autonomous.append(unit)
        if case["type"] == "0":
            continue
        sent = [
            unit
            for direction, _, unit in case["units"]
            if direction == "TX" and unit["kind"] == "I"
        ]
        if len(sent) != 1 or sent[0]["type"] != int(case["type"]):
            raise ValueError(f"missing/wrong request in case {case['id']}")
        replies = [
            unit
            for direction, _, unit in case["units"]
            if direction == "RX"
            and unit["kind"] == "I"
            and unit["cot"] not in (1, 2, 3, 4)
        ]
        # This suite has no pipelining and a fixed 650 ms observation window.
        # A late reply is a harness error, not evidence for the following request.
        for unit in replies:
            if (
                unit["type"] != int(case["type"])
                and not (case["type"] == "100" and 20 <= unit["cot"] <= 36)
                and not (case["type"] == "101" and 37 <= unit["cot"] <= 41)
                and not (case["type"] == "102" and unit["cot"] == 5)
            ):
                raise ValueError(f"unattributable late reply: {case['id']} {unit}")
        status = "observed"
        if not replies:
            status = "unsupported-by-stack"
        elif all(unit["pn"] == "N" or unit["cot"] >= 44 for unit in replies):
            status = "rejected-by-stack"
        owner = "application-defined"
        if (
            (stack == "lib60870" and case["type"] not in ("45", "100", "103"))
            or (stack == "c104" and case["type"] == "107")
            or (
                stack == "lib60870"
                and case["type"] == "103"
                and case["variant"] == "invalid-ioa"
            )
        ):
            owner = "library-default"
        elif stack == "c104":
            owner = "c104-default-handler"
        rows.append(
            {
                "stack": stack,
                "case": case["id"],
                "procedure": case["procedure"],
                "type": case["type"],
                "qualifier": case["qualifier"],
                "variant": case["variant"],
                "direction": "station-to-master",
                "request_cot": sent[0]["cot"],
                "cot_sequence": ",".join(str(unit["cot"]) for unit in replies),
                "reply_types": ",".join(str(unit["type"]) for unit in replies),
                "pn_sequence": ",".join(unit["pn"] for unit in replies),
                "optional_stages_observed": "10"
                if any(u["cot"] == 10 for u in replies)
                else "",
                "status": status,
                "stage_owner": owner,
                "capture_reference": f"{stack}.wire.tsv:case={case['id']}",
            }
        )
    for cot in (1, 2, 3, 4):
        units = [u for u in autonomous if u["cot"] == cot]
        types = sorted({u["type"] for u in units})
        rows.append(
            {
                "stack": stack,
                "case": f"monitor-{cot}",
                "procedure": "initialization" if cot == 4 else "monitor",
                "type": ",".join(map(str, types))
                if types
                else ("70" if cot == 4 else "*"),
                "qualifier": "",
                "variant": "entire-session",
                "direction": "station-to-master",
                "cot_sequence": str(cot) if units else "",
                "reply_types": ",".join(map(str, types)),
                "pn_sequence": ",".join(sorted({u["pn"] for u in units})),
                "status": "observed" if units else "unsupported-by-stack",
                "stage_owner": "application-triggered-api"
                if stack == "c104"
                else "application-defined",
                "capture_reference": f"{stack}.wire.tsv:all",
            }
        )
    for direction, kind in (
        ("TX", "S"),
        ("RX", "S"),
        ("TX", "STARTDT-act"),
        ("RX", "STARTDT-con"),
        ("TX", "STOPDT-act"),
        ("RX", "STOPDT-con"),
        ("TX", "TESTFR-act"),
        ("RX", "TESTFR-con"),
    ):
        present = (direction, kind) in controls
        if kind != "S" and not present:
            raise ValueError(
                f"{stack}: required control probe missing: {direction} {kind}"
            )
        rows.append(
            {
                "stack": stack,
                "case": f"{direction}-{kind}",
                "procedure": "session",
                "type": kind,
                "variant": "entire-session",
                "direction": "master-to-station"
                if direction == "TX"
                else "station-to-master",
                "control_sequence": kind if present else "",
                "status": "observed" if present else "unsupported-by-stack",
                "stage_owner": "library-default",
                "capture_reference": f"{stack}.wire.tsv:all",
            }
        )
    with (directory / f"{stack}.wire.tsv").open("w") as out:
        writer = csv.writer(out, delimiter="\t", lineterminator="\n")
        writer.writerow(["case", "completion_frame", "direction", "apdu_hex"])
        writer.writerows(wire)
    return rows


def main():
    directory = Path(sys.argv[1])
    rows = [
        row
        for stack in ("lib60870", "j60870", "c104")
        for row in analyze(stack, directory)
    ]
    with (directory / "stages.tsv").open("w") as out:
        writer = csv.DictWriter(out, FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"validated {len(rows)} observations against captured TCP")


if __name__ == "__main__":
    main()
