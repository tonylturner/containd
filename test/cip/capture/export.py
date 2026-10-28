#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Export per-object wire observations, excluding tshark's inferred paths."""
import argparse
import csv
import gzip
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

FIELDS = [
    'enip.command', 'enip.status', 'enip.session', 'enip.cpf.itemcount',
    'enip.cpf.cai.connid', 'enip.cpf.sai.connid', 'enip.cpf.sai.seq',
    'cip.seq', 'cip.sc', 'cip.rr', 'cip.genstat', 'cip.addstat_size',
    'cip.class', 'cip.instance', 'cip.attribute', 'cip.msp.num_services',
    'additional_status.json', 'cpf_types.json', 'cpf_lengths.json', 'cip.message_hex',
]
PREFS = ['-o', 'tcp.desegment_tcp_streams:TRUE', '-o', 'enip.desegment:TRUE',
         '-o', 'enip.o2t_run_idle:TRUE', '-o', 'enip.t2o_run_idle:FALSE']


def own_fields(node):
    """Do not flatten children or inferred (size zero) request paths."""
    for child in node:
        if child.tag == 'proto' and child.get('name') == 'cip':
            continue
        if child.tag == 'field' and int(child.get('size', '0')) > 0:
            yield child
        yield from own_fields(child)


def values(fields):
    result = {}
    for field in fields:
        if int(field.get('size', '0')) > 0:
            result.setdefault(field.get('name'), []).append(field.get('show', ''))
    return result


def normalize(packet, transport):
    all_values = values(packet.iter('field'))
    payload_key = transport + '.payload'
    if payload_key not in all_values:
        return []
    # This generator intentionally exchanges one encapsulation PDU per segment.
    # Fail, rather than flatten a future generator's coalesced PDU observations.
    if transport == 'tcp' and len(all_values.get('enip.command', [])) != 1:
        raise RuntimeError('TCP payload is not one complete independently dissected ENIP PDU')
    payload_field = packet.find(f".//field[@name='{payload_key}']")
    payload_pos = int(payload_field.get('pos'))
    payload = bytes.fromhex(payload_field.get('show').replace(':', ''))
    rows = []
    for index, obj in enumerate(packet.findall(".//proto[@name='cip']") or [None]):
        fields = values(own_fields(obj)) if obj is not None else {}
        row = {'frame.number': packet.find(".//field[@name='frame.number']").get('show'),
               'pdu': '0', 'object': str(index),
               'tcp.payload': all_values.get('tcp.payload', [''])[0],
               'udp.payload': all_values.get('udp.payload', [''])[0]}
        for name in FIELDS:
            source = all_values if name.startswith('enip.') or name == 'cip.seq' else fields
            row[name] = source.get(name, [''])[0]
        row['additional_status.json'] = json.dumps([int(x, 0) for x in fields.get('cip.addstat', [])])
        row['cpf_types.json'] = json.dumps([int(x, 0) for x in all_values.get('enip.cpf.typeid', [])])
        row['cpf_lengths.json'] = json.dumps([int(x, 0) for x in all_values.get('enip.cpf.length', [])])
        if obj is not None:
            start = int(obj.get('pos')) - payload_pos
            end = start + int(obj.get('size'))
            if start < 0 or end > len(payload):
                raise RuntimeError('CIP object outside captured transport payload')
            row['cip.message_hex'] = payload[start:end].hex()
        rows.append(row)
    return rows


def export(pcap, transport):
    version = subprocess.check_output(['tshark', '--version'], text=True)
    if 'TShark (Wireshark) 4.6.7 ' not in version:
        raise RuntimeError('oracle requires tshark 4.6.7')
    pdml = subprocess.check_output(['tshark', '-n', '-r', str(pcap), *PREFS, '-T', 'pdml'])
    pcap.with_suffix('.pdml.gz').write_bytes(gzip.compress(pdml, mtime=0))
    rows = [row for packet in ET.fromstring(pdml).findall('packet') for row in normalize(packet, transport)]
    if not rows:
        raise RuntimeError(f'{pcap}: empty oracle')
    with pcap.with_suffix('.expected.tsv').open('w') as out:
        writer = csv.DictWriter(out, fieldnames=['frame.number', 'pdu', 'object', 'tcp.payload', 'udp.payload', *FIELDS],
                                delimiter='\t', lineterminator='\n', quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
    return sorted({int(row['frame.number']) for row in rows})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--transport', choices=['tcp', 'udp'], required=True)
    parser.add_argument('pcap', nargs='+', type=Path)
    args = parser.parse_args()
    for filename in args.pcap:
        print(filename, export(filename, args.transport))
