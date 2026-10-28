#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Seal independently exported observations and separate product expectations."""
import csv
import hashlib
import json
import pathlib
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(directory):
    directory = pathlib.Path(directory)
    capture = pathlib.Path(__file__).resolve().parent
    # Server trace lines end in spaces. Normalize only this textual evidence,
    # never packet bytes or oracle cells; preserve the raw log in capture output.
    server_log = directory / "server.log"
    server_log.write_text("".join(line.rstrip() + "\n" for line in server_log.read_text().splitlines()))
    scenarios = []
    inventory = []
    expected_counts = {"operations": 50, "diagnostics": 64, "source502": 2,
                       "pid-nonzero": 1, "bad-layout": 1, "bad-length": 1, "truncation": 0}
    for name, count in expected_counts.items():
        with (directory / f"{name}.expected.tsv").open() as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))
        assert rows and all(row["tcp.payload"] for row in rows)
        conformance, undecoded = {}, {}
        if name == "pid-nonzero":
            conformance["4"] = ["modbus.pid_nonzero"]
        elif name == "bad-layout":
            conformance["4"] = ["modbus.pdu_layout"]
        elif name == "diagnostics":
            for row in rows:
                if row["modbus.diagnostic_code"] == "19":
                    undecoded[row["frame.number"]] = ["modbus.diagnostics_subfunction"]
                if row["modbus.diagnostic_code"] == "4" and len(bytes.fromhex(row["tcp.payload"])) == 10:
                    conformance[row["frame.number"]] = ["modbus.pdu_layout"]
        expectations = {
            "origin": "captured-stack" if name in ("operations", "diagnostics", "source502") else "mutation",
            "events": count, "conformance": conformance, "undecoded": undecoded,
            "frame_error": name == "bad-length", "eof_partial": name == "truncation",
            "supplemental": {},
        }
        if name == "source502":
            # tshark observes MBAP/FC but cannot classify the two service ports.
            # These are endpoint scenario assertions, NOT tshark observations.
            expectations["supplemental"] = {
                rows[0]["frame.number"]: {"address": 65534, "quantity": 2},
                rows[1]["frame.number"]: {"byte_count": 4, "register_count": 2},
            }
        (directory / f"{name}.expectations.json").write_text(json.dumps(expectations, indent=2) + "\n")
        scenario = {
            "name": name, "pcap": f"{name}.pcap", "oracle": f"{name}.expected.tsv",
            "expectations": f"{name}.expectations.json", "transport": "tcp", "contiguous": True,
            "checksum_offload": ("retained handshake has endpoint partial checksums; mutation recalculates full IPv4/TCP checksum of modified frame" if expectations["origin"] == "mutation"
                                 else "server eth0 capture retains Linux partial pseudo-header TCP checksums (endpoint offload); no byte repair"),
            "oracle_frames": [int(row["frame.number"]) for row in rows],
        }
        if name == "operations":
            scenario["assets"] = ["images.json", "mutations.json", "server.log", "operations.client.log", "operations.capture.log"]
        elif name in ("diagnostics", "source502"):
            scenario["assets"] = [f"{name}.client.log", f"{name}.capture.log"]
        scenarios.append(scenario)
        inventory += [scenario["pcap"], scenario["oracle"], scenario["expectations"]] + scenario.get("assets", [])
    provenance = {
        "source": "pymodbus 3.11.4, BSD-3-Clause; installed source hashes in capture/source-lock.json sha256:" + sha(capture / "source-lock.json"),
        "generator": "modbusspan-tools@sha256:2bbeea56d58c5192ebda1d8314637c3c9995341df21e733110405040bae77fbc; actual built image in images.json",
        "oracle": "TShark (Wireshark) 4.6.7 (b439fb7b47a9); -2 -o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:TRUE -o mbtcp.desegment:TRUE -o modbus.mbus_register_format:UINT16; tcp.len > 0; occurrence=a aggregator=, quote=d; re-serialize identical cells with Python csv.QUOTE_ALL",
        "license": "Apache-2.0 wire fixtures; BSD-3-Clause pymodbus runs only as generator, notice in capture/LICENSES/pymodbus.txt",
        "topology": "Docker private auto-IPAM bridge; pymodbus TCP client directly to unmodified pymodbus TCP server; units 1/2/3; no containd in path",
        "capture_side": "tcpdump 4.99.3 on server eth0 via shared network namespace; full opening handshakes; no kernel drops",
        "diagnostics_profile": "MODBUS Application Protocol V1.1b3 section 6.8.1 pp22-24; https://www.modbus.org/file/secure/modbusprotocolspecification.pdf sha256:f80d0d7132fd035104c3f21b01026470e3310ca3d8d493d9a9737d0d32ad2eb1",
        "log_normalization": "server.log strips trailing whitespace only; raw original retained by capture.sh output directory",
    }
    for name in ("endpoint.py", "generator.Dockerfile", "capture.sh", "export-oracle.sh", "mutate.py", "finalize.py"):
        provenance[name + "_sha256"] = sha(capture / name)
    (directory / "manifest.json").write_text(json.dumps({
        "version": 1, "protocol": "modbus", "provenance": provenance, "scenarios": scenarios,
    }, indent=2) + "\n")
    (directory / "SHA256SUMS").write_text("".join(f"{sha(directory / name)}  {name}\n" for name in sorted(inventory)))


if __name__ == "__main__":
    main(sys.argv[1])
