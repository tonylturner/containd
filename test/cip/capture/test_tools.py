# SPDX-License-Identifier: Apache-2.0
"""Guard evidence normalization, mutation checksums and coverage gates."""
import csv
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
import xml.etree.ElementTree as ET

from finalize import finalize
from mutate import checksum, records, short_udp

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / 'testdata'
spec = importlib.util.spec_from_file_location('oracle_export', HERE / 'export.py')
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


class OracleTests(unittest.TestCase):
    def packet(self, objects):
        return ET.fromstring('''<packet><field name="frame.number" size="0" show="9"/>
          <field name="tcp.payload" size="10" pos="66" show="8e:00:01:02:34:12:78:56:00:00"/>
          <field name="enip.command" size="2" show="0x006f"/>''' + objects + '</packet>')

    def test_repeated_status_and_inferred_response_path(self):
        packet = self.packet('''<proto name="cip" pos="66" size="8">
          <field name="cip.sc" size="1" show="0x0e"/>
          <field name="cip.rr" size="1" show="0x01"/>
          <field name="cip.addstat" size="2" show="0x1234"/>
          <field name="cip.addstat" size="2" show="0x5678"/>
          <field name="cip.class" size="0" show="0x01"/>
          <field name="cip.attribute" size="0" show="7"/></proto>''')
        row, = export.normalize(packet, 'tcp')
        self.assertEqual(json.loads(row['additional_status.json']), [0x1234, 0x5678])
        self.assertEqual(row['cip.class'], '')
        self.assertEqual(row['cip.attribute'], '')
        self.assertEqual(row['cip.message_hex'], '8e00010234127856')

    def test_children_do_not_replace_parent(self):
        packet = self.packet('''<proto name="cip" pos="66" size="10">
          <field name="cip.sc" size="1" show="0x0a"/>
          <field name="cip.msp.num_services" size="2" show="1"/>
          <proto name="cip" pos="74" size="2">
            <field name="cip.sc" size="1" show="0x10"/>
          </proto></proto>''')
        parent, child = export.normalize(packet, 'tcp')
        self.assertEqual(parent['cip.sc'], '0x0a')
        self.assertEqual(child['cip.sc'], '0x10')
        self.assertEqual(child['cip.msp.num_services'], '')

    def test_coalesced_pdu_fails_instead_of_flattening(self):
        packet = self.packet('<field name="enip.command" size="2" show="0x0070"/>')
        with self.assertRaisesRegex(RuntimeError, 'not one complete'):
            export.normalize(packet, 'tcp')


class MutationTests(unittest.TestCase):
    def test_native_short_preserves_identity_and_has_valid_checksums(self):
        _, _, original = next(records((DATA / 'native-io.pcap').read_bytes()))
        mutated, offset = short_udp(original)
        udp = 14 + (original[14] & 15) * 4
        self.assertEqual(offset, len(original) - udp - 8 - 1)
        self.assertEqual(mutated[udp + 8:], original[udp + 8:-1])
        self.assertEqual(mutated[udp:udp + 4], original[udp:udp + 4])
        self.assertEqual(checksum(mutated[14:udp]), 0)
        length = len(mutated) - udp
        pseudo = mutated[26:34] + struct.pack('!BBH', 0, 17, length)
        self.assertEqual(checksum(pseudo + mutated[udp:]), 0)
        self.assertEqual(struct.unpack_from('!H', mutated, 16)[0], len(mutated) - 14)
        self.assertEqual(struct.unpack_from('!H', mutated, udp + 4)[0], length)

    def test_filter_is_unchanged_original_evidence(self):
        lineage = json.loads((DATA / 'native-io.lineage.json').read_text())
        original = list(records((DATA / lineage['parent']).read_bytes()))
        filtered = list(records((DATA / 'native-io.pcap').read_bytes()))
        self.assertEqual(filtered, [original[i - 1] for i in lineage['parent_frames']])


class CoverageTests(unittest.TestCase):
    def test_missing_additional_status_cannot_be_certified(self):
        with tempfile.TemporaryDirectory(prefix='containd-corpus-cip-') as scratch:
            out = Path(scratch) / 'data'
            shutil.copytree(DATA, out)
            path = out / 'explicit.expected.tsv'
            with path.open() as source:
                reader = csv.DictReader(source, delimiter='\t')
                fields, rows = reader.fieldnames, list(reader)
            for row in rows:
                words = json.loads(row['additional_status.json'])
                if words:
                    row['additional_status.json'] = json.dumps([word ^ 1 for word in words])
            with path.open('w') as target:
                writer = csv.DictWriter(target, fieldnames=fields, delimiter='\t')
                writer.writeheader()
                writer.writerows(rows)
            with self.assertRaisesRegex(RuntimeError, 'additional status'):
                finalize(out, HERE)

    def test_blocked_msp_cannot_be_relabelled_success(self):
        with tempfile.TemporaryDirectory(prefix='containd-corpus-cip-') as scratch:
            out = Path(scratch) / 'data'
            shutil.copytree(DATA, out)
            (out / 'msp-scanner.exit').write_text('0\n')
            with self.assertRaisesRegex(RuntimeError, 'preserve its failed exit'):
                finalize(out, HERE)


if __name__ == '__main__':
    unittest.main()
