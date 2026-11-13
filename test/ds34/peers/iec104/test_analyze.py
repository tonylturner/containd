# SPDX-License-Identifier: Apache-2.0
import csv
import unittest
from pathlib import Path

from analyze import apdus, decode


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


if __name__ == "__main__":
    unittest.main()
