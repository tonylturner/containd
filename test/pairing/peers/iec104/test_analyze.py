# SPDX-License-Identifier: Apache-2.0
import csv
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from analyze import apdus, decode, replay_sequences


class CaptureTests(unittest.TestCase):
    def test_split_coalesced_and_retransmitted(self):
        first = "680407000000"
        second = "680401000200"
        chunks = [
            ("1", "40000", "100", first[:6]),
            ("2", "40000", "103", first[6:] + second),
            ("3", "40000", "100", first),
        ]
        frames = apdus(chunks)
        self.assertEqual([b.hex() for _, b in frames["TX"]], [first, second])
        self.assertEqual(frames["RX"], [])

    def test_conflict_fails(self):
        with self.assertRaisesRegex(ValueError, "conflicting"):
            apdus(
                [
                    ("1", "2404", "100", "68040b000000"),
                    ("2", "2404", "100", "680407000000"),
                ]
            )

    def test_gap_fails(self):
        with self.assertRaisesRegex(ValueError, "gapped"):
            apdus([("1", "2404", "100", "6804"), ("2", "2404", "103", "0b000000")])

    def test_incomplete_fails(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            apdus([("1", "2404", "100", "68040b")])

    def test_negative_cause_is_not_masked_away(self):
        unit = decode(bytes.fromhex("680e000000002d014700010088130001"))
        self.assertEqual(
            (unit["type"], unit["cot"], unit["pn"], unit["ioa"]), (45, 7, "N", 5000)
        )

    def test_control_kinds(self):
        self.assertEqual(decode(bytes.fromhex("680401000200")), {"kind": "S"})
        for control, name in (
            (7, "STARTDT-act"),
            (11, "STARTDT-con"),
            (19, "STOPDT-act"),
            (35, "STOPDT-con"),
            (67, "TESTFR-act"),
            (131, "TESTFR-con"),
        ):
            self.assertEqual(decode(bytes([104, 4, control, 0, 0, 0])), {"kind": name})

    def test_documented_source_hashes_are_verified_in_build(self):
        root = Path(__file__).parent
        dockerfile = (root / "Dockerfile").read_text()
        with (root / "sources.tsv").open() as source:
            records = list(csv.DictReader(source, delimiter="\t"))
        self.assertEqual(len(records), 6)
        for record in records:
            self.assertRegex(record["commit"], r"^[0-9a-f]{40}$")
            self.assertRegex(record["archive_sha256"], r"^[0-9a-f]{64}$")
            self.assertIn(record["archive_sha256"], dockerfile)

    def test_rejected_replay_eligibility(self):
        controls = [
            (direction, data, decode(data))
            for direction, control in (
                ("TX", 7),
                ("RX", 11),
                ("TX", 19),
                ("RX", 35),
                ("TX", 67),
                ("RX", 131),
            )
            for data in (bytes([104, 4, control, 0, 0, 0]),)
        ]
        request = bytes.fromhex("680e000000002d010600010088130001")
        for cot, pn, eligible in (
            *((cot, pn, True) for cot in range(44, 48) for pn in ("P", "N")),
            (7, "N", True),
            (7, "P", False),
            (8, "N", False),
            (43, "N", False),
            (48, "N", False),
        ):
            for status in ("rejected-by-stack", "unsupported-by-stack"):
                with self.subTest(cot=cot, pn=pn, status=status):
                    response = bytearray(request)
                    response[8] = cot | (64 if pn == "N" else 0)
                    response = bytes(response)
                    case = {
                        "id": "002",
                        "type": "45",
                        "procedure": "execute",
                        "variant": "without-select",
                        "units": [
                            ("TX", request, decode(request)),
                            ("RX", response, decode(response)),
                            *controls,
                        ],
                    }
                    rows = [{"case": "002", "status": status}]
                    sequences = replay_sequences("j60870", "peer", [case], rows)
                    episodes = [s for s in sequences if "-case-" in s["id"]]
                    if eligible and status == "rejected-by-stack":
                        self.assertEqual(
                            episodes,
                            [
                                {
                                    "id": "j60870-case-002",
                                    "peer": "peer",
                                    "frames": [
                                        {"direction": "request", "apdu": request.hex()},
                                        {
                                            "direction": "response",
                                            "apdu": response.hex(),
                                        },
                                    ],
                                }
                            ],
                        )
                    else:
                        self.assertEqual(episodes, [])

    def test_replay_schema_and_exact_wire_subsequences(self):
        root = Path(__file__).parent
        oracle = json.loads((root / "oracle.json").read_text())
        self.assertEqual(set(oracle), {"version", "sequences"})
        self.assertIs(type(oracle["version"]), int)
        self.assertEqual(oracle["version"], 1)
        self.assertEqual(len(oracle["sequences"]), 261)
        with (root / "sources.tsv").open() as source:
            peers = {
                row["name"]: f"{row['name']} {row['version']}@{row['commit']}"
                for row in csv.DictReader(source, delimiter="\t")
            }
        with (root / "stages.tsv").open() as source:
            rows = {
                (row["stack"], row["case"]): row
                for row in csv.DictReader(source, delimiter="\t")
            }
        wires = {}
        for stack in ("lib60870", "j60870", "c104"):
            with (root / f"{stack}.wire.tsv").open() as source:
                wires[stack] = list(csv.DictReader(source, delimiter="\t"))
        seen = set()
        command_types = set()
        positive = []
        rejected_counts = {"lib60870": 0, "j60870": 0, "c104": 0}
        for sequence in oracle["sequences"]:
            self.assertEqual(set(sequence), {"id", "peer", "frames"})
            self.assertNotIn(sequence["id"], seen)
            seen.add(sequence["id"])
            stack = sequence["id"].split("-")[0]
            self.assertEqual(sequence["peer"], peers[stack])
            self.assertGreaterEqual(len(sequence["frames"]), 2)
            wire = wires[stack]
            if "-case-" in sequence["id"]:
                ident = sequence["id"].split("-case-")[1]
                row = rows[(stack, ident)]
                self.assertIn(row["status"], ("observed", "rejected-by-stack"))
                if row["status"] == "rejected-by-stack":
                    rejected_counts[stack] += 1
                    replies = [
                        decode(bytes.fromhex(frame["apdu"]))
                        for frame in sequence["frames"]
                        if frame["direction"] == "response"
                    ]
                    self.assertTrue(
                        any(
                            44 <= unit["cot"] <= 47
                            or (unit["cot"] == 7 and unit["pn"] == "N")
                            for unit in replies
                        )
                    )
                    self.assertEqual(
                        ",".join(str(unit["cot"]) for unit in replies),
                        row["cot_sequence"],
                    )
                    self.assertEqual(
                        ",".join(unit["pn"] for unit in replies), row["pn_sequence"]
                    )
                else:
                    positive.append(sequence)
                self.assertTrue(row["request_cot"])
                wire = [frame for frame in wire if frame["case"] == ident]
                if row["procedure"] in ("select", "execute"):
                    command_types.add(int(row["type"]))
            else:
                positive.append(sequence)
            actual = iter(
                {
                    "direction": "request"
                    if frame["direction"] == "TX"
                    else "response",
                    "apdu": frame["apdu_hex"],
                }
                for frame in wire
            )
            for frame in sequence["frames"]:
                self.assertEqual(set(frame), {"direction", "apdu"})
                self.assertIn(frame["direction"], ("request", "response"))
                self.assertRegex(frame["apdu"], r"^(?:[0-9a-f]{2})+$")
                data = bytes.fromhex(frame["apdu"])
                self.assertGreaterEqual(len(data), 6)
                self.assertEqual(data[0], 0x68)
                self.assertEqual(len(data), data[1] + 2)
                self.assertTrue(any(value == frame for value in actual))
        self.assertEqual(command_types, {*range(45, 52), *range(58, 65)})
        self.assertEqual(rejected_counts, {"lib60870": 0, "j60870": 95, "c104": 85})
        # Freeze every original positive/control episode, including APCI bytes.
        self.assertEqual(len(positive), 81)
        digest = hashlib.sha256(
            json.dumps(
                sorted(positive, key=lambda sequence: sequence["id"]),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        self.assertEqual(
            digest, "8cb84578041f1764d9e9858d38d5e7ac819bb336ffb2cde697ba4759f41ad290"
        )

    def test_byte_unstable_episodes_remain_evidence_only(self):
        root = Path(__file__).parent
        sequences = json.loads((root / "oracle.json").read_text())["sequences"]
        ids = {sequence["id"] for sequence in sequences}
        with (root / "stages.tsv").open() as source:
            rows = list(csv.DictReader(source, delimiter="\t"))
        for row in rows:
            if not row["case"].isdigit():
                continue
            ident = f"{row['stack']}-case-{row['case']}"
            if (row["stack"] == "lib60870" and row["case"] != "002") or (
                row["stack"] == "j60870" and row["procedure"] == "clock"
            ):
                self.assertNotIn(ident, ids)
            elif row["status"] in ("observed", "rejected-by-stack"):
                self.assertIn(ident, ids)
            else:
                self.assertNotIn(ident, ids)

    def test_committed_oracles_regenerate_byte_exactly(self):
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(prefix="pairingpeer-oracle-") as temp:
            target = Path(temp)
            for stack in ("lib60870", "j60870", "c104"):
                for suffix in ("master.log", "tcp.tsv"):
                    name = f"{stack}.{suffix}"
                    shutil.copyfile(root / name, target / name)
            for _ in range(2):
                subprocess.run(
                    [sys.executable, str(root / "analyze.py"), str(target)],
                    check=True,
                    capture_output=True,
                )
                for name in (
                    "oracle.json",
                    "stages.tsv",
                    "lib60870.wire.tsv",
                    "j60870.wire.tsv",
                    "c104.wire.tsv",
                ):
                    self.assertEqual(
                        (root / name).read_bytes(), (target / name).read_bytes()
                    )


if __name__ == "__main__":
    unittest.main()
