#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic unit tests for generation tools; these are not stack fixtures."""
import csv
import json
from pathlib import Path
import struct
import tempfile
import unittest

import mutate
import normalize


class OracleTools(unittest.TestCase):
    def test_object_boundaries_and_crob(self):
        xml = '''<pdml><packet>
        <proto name="frame"><field name="frame.number" show="7"/></proto>
        <proto name="tcp"><field name="tcp.payload" value="0564"/></proto>
        <proto name="dnp3"><field name="dnp3.src" show="1"/><field name="dnp3.dst" show="10"/>
          <field name="dnp3.al.func" show="5"/>
          <field name="dnp3.al.obj" show="0x0c01">
            <field name="dnp3.al.objq.prefix" show="2"/><field name="dnp3.al.objq.range" show="8"/>
            <field name="dnp3.al.range.quantity" show="1"/>
            <field name=""><field name="dnp3.al.index" show="300"/>
              <field name="dnp3.ctl.op" show="1" unmaskedvalue="81"/>
              <field name="dnp3.al.count" show="2"/><field name="dnp3.al.on_time" show="250"/>
              <field name="dnp3.al.off_time" show="500"/><field name="dnp3.al.ctrlstatus" show="0"/>
            </field>
          </field>
          <field name="dnp3.al.obj" show="0x0102">
            <field name="dnp3.al.objq.prefix" show="0"/><field name="dnp3.al.objq.range" show="0"/>
            <field name="dnp3.al.range.start" show="7"/><field name="dnp3.al.range.stop" show="7"/>
            <field name=""><field name="dnp3.al.point_index" show="7"/></field>
          </field>
        </proto></packet></pdml>'''
        with tempfile.TemporaryDirectory() as temp:
            source, target = Path(temp) / "input.pdml", Path(temp) / "output.tsv"
            source.write_text(xml)
            normalize.normalize(source, target)
            with target.open() as out:
                rows = list(csv.DictReader(out, delimiter="\t"))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["qualifier"], "40")
        self.assertEqual(rows[1]["object"], "1")
        self.assertEqual(json.loads(rows[1]["points.json"]), [{"index": 7}])
        value = json.loads(rows[0]["points.json"])[0]
        self.assertEqual(value["index"], 300)
        self.assertEqual(value["crob"], {"control": 129, "count": 2, "on_time_ms": 250, "off_time_ms": 500, "status": 0})
        self.assertEqual(rows[0]["tcp.payload"], rows[1]["tcp.payload"])

    def test_named_mutation_offset_and_checksum(self):
        # Deliberately synthetic: only the mutation tool's offsets/checksums
        # are under test, not authenticity or DNP3 CRC conformance.
        payload = bytes.fromhex("056408c40a0001000000c0c0010000")
        ip = bytearray(20)
        ip[0], ip[9] = 0x45, 6
        struct.pack_into("!H", ip, 2, 40 + len(payload))
        ip[12:20] = bytes([192, 0, 2, 1, 192, 0, 2, 2])
        tcp = bytearray(20)
        tcp[12] = 0x50
        raw = bytes(12) + b"\x08\x00" + bytes(ip) + bytes(tcp) + payload
        pcap = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        pcap += struct.pack("<IIII", 1, 0, len(raw), len(raw)) + raw
        with tempfile.TemporaryDirectory() as temp:
            source, target = Path(temp) / "named-good.pcap", Path(temp) / "crc-flip.pcap"
            source.write_bytes(pcap)
            mutate.mutate(source, target)
            result = target.read_bytes()
            meta = json.loads(target.with_suffix(".mutation.json").read_text())
        self.assertEqual(meta["parent"], "named-good.pcap")
        offset = meta["pcap_byte_offset"]
        self.assertEqual(result[offset], pcap[offset] ^ 1)
        tcp_start = 24 + 16 + 14 + 20
        segment = result[tcp_start:]
        pseudo = bytes(ip[12:20]) + b"\0\x06" + struct.pack("!H", len(segment))
        self.assertEqual(mutate.checksum(pseudo + segment), 0)
        self.assertEqual(source.name, "named-good.pcap")

    def test_empty_oracle_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            source, target = Path(temp) / "empty.pdml", Path(temp) / "out.tsv"
            source.write_text("<pdml/>")
            with self.assertRaisesRegex(RuntimeError, "empty independent"):
                normalize.normalize(source, target)


if __name__ == "__main__":
    unittest.main()
