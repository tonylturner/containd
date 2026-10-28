#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate observed layouts, label stopped probes, write protocol expectations."""
import csv
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import socket
import struct
import sys
import xml.etree.ElementTree as ET

from mutate import records

NAMES = ['explicit', 'connected', 'io', 'msp', 'msp32', 'native-io', 'udp-short-mutation']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def udp_roles(path, adapter):
    roles = []
    for _, _, raw in records(path.read_bytes()):
        ip_size = (raw[14] & 15) * 4
        src, dst = [socket.inet_ntoa(raw[i:i + 4]) for i in [26, 30]]
        sport, dport = struct.unpack_from('!HH', raw, 14 + ip_size)
        # The adapter is io.pcap's TCP listener; all other endpoints are scanner.
        if src == adapter:
            src, dst, sport, dport = dst, src, dport, sport
        role = {'transport': 'udp', 'client': f'{src}:{sport}', 'server': f'{dst}:{dport}'}
        if role not in roles:
            roles.append(role)
    return roles


def expected_objects(rows, name):
    objects = []
    for row in rows:
        raw = bytes.fromhex(row['cip.message_hex'])
        codes = []
        conformance = []
        kind = 'session'
        if raw:
            response = bool(raw[0] & 0x80)
            kind = 'response' if response else 'request'
            # Header and body boundary, independent of containd output. Opaque
            # service bodies are deliberately reported by the current decoder.
            start = 4 + 2 * raw[3] if response else 2 + 2 * raw[1]
            msp_body = raw[0] & 0x7f == 0x0a and (not response or raw[2] in [0, 0x1e])
            if len(raw) > start and not msp_body:
                codes.append('cip.service_payload_unsupported')
        elif row['enip.command'] == '0x0065':
            codes.append('cip.encapsulation_payload_unsupported')
        if any(x not in [0, 0xa1, 0xb1, 0xb2, 0x8002] for x in json.loads(row['cpf_types.json'])):
            codes.append('cip.cpf_item_unsupported')
        if name == 'udp-short-mutation':
            conformance.append('cip.cpf_layout')
        objects.append({'kind': kind, 'conformance': conformance, 'undecoded': sorted(codes)})
    if len(objects) > 1:
        # MSP parent aggregates descendants; envelope limitations are inherited.
        objects[0]['undecoded'] = sorted({c for obj in objects for c in obj['undecoded']})
    return objects


def finalize(out, inputs):
    rows = {}
    for name in NAMES:
        with (out / f'{name}.expected.tsv').open() as source:
            rows[name] = list(csv.DictReader(source, delimiter='\t'))
        if not rows[name]:
            raise RuntimeError(f'{name}: empty oracle')
        tree = ET.fromstring(gzip.decompress((out / f'{name}.pdml.gz').read_bytes()))
        if name != 'udp-short-mutation':
            for reason in ['tcp.analysis.retransmission', 'tcp.analysis.lost_segment', 'tcp.analysis.out_of_order', '_ws.malformed']:
                if tree.find(f".//*[@name='{reason}']") is not None:
                    raise RuntimeError(f'{name}: pristine generation contains {reason}')
    def require(name, predicate, message):
        if not any(predicate(row) for row in rows[name]):
            raise RuntimeError(f'{name}: missing independent coverage: {message}')
    require('explicit', lambda r: r['cip.sc'] == '0x10' and r['cip.rr'] == '0x01' and r['cip.genstat'] == '0x00', 'successful write reply')
    require('explicit', lambda r: r['cip.genstat'] == '0x14', 'unknown attribute error')
    require('explicit', lambda r: r['cip.genstat'] == '0x13', 'bad attribute size error')
    require('explicit', lambda r: json.loads(r['additional_status.json']) == [0x12f], 'ForwardOpen additional status')
    for state in ['0x00', '0x14']:
        require('connected', lambda r: r['enip.command'] == '0x0070' and r['cip.genstat'] == state and r['cip.seq'] != '', 'connected reply ' + state)
    for service in ['0x54', '0x4e']:
        require('io', lambda r: r['cip.sc'] == service and r['cip.genstat'] == '0x00', 'successful negotiation/close ' + service)
    io_tree = ET.fromstring(gzip.decompress((out / 'io.pdml.gz').read_bytes()))
    if io_tree.find(".//field[@name='cip.cm.fwo.transport'][@show='1']") is None:
        raise RuntimeError('missing independently dissected class 1 negotiation')
    for name, count in [('msp', '3'), ('msp32', '32')]:
        require(name, lambda r: r['cip.msp.num_services'] == count and r['cip.rr'] == '0x00', 'MSP request count ' + count)
        require(name, lambda r: r['cip.sc'] == '0x0a' and r['cip.genstat'] == '0x08', 'documented unsupported-service blocker')
        if (out / f'{name}-scanner.exit').read_text().strip() != '1':
            raise RuntimeError('MSP coverage probe must preserve its failed exit')
    if not all(json.loads(r['cpf_types.json']) == [0x8002, 0xb1] for r in rows['native-io']):
        raise RuntimeError('native I/O CPF layout missing')
    negotiated = set()
    for packet in io_tree.findall('packet'):
        if packet.find(".//field[@name='cip.sc'][@show='0x54']") is not None and packet.find(".//field[@name='cip.rr'][@show='0x01']") is not None:
            for field in packet.iter('field'):
                if field.get('name') in ['cip.cm.ot_connid', 'cip.cm.to_connid'] and int(field.get('size', '0')) > 0:
                    negotiated.add(int(field.get('show'), 0))
    observed = {int(row['enip.cpf.sai.connid'], 0) for row in rows['native-io']}
    if len(negotiated) != 2 or observed != negotiated:
        raise RuntimeError('native I/O connection IDs do not match ForwardOpen reply')
    for name in NAMES[:5]:
        if '0 packets dropped by kernel' not in (out / f'{name}-tcpdump.log').read_text():
            raise RuntimeError(f'{name}: capture drops or missing tcpdump summary')
    for name in ['native-io.lineage', 'udp-short-mutation.mutation']:
        meta = json.loads((out / f'{name}.json').read_text())
        if meta['parent_sha256'] != digest(out / meta['parent']):
            raise RuntimeError('derived capture parent digest changed')
    first_tcp = next(p[2] for p in records((out / 'io.pcap').read_bytes()) if p[2][23] == 6)
    adapter = socket.inet_ntoa(first_tcp[30:34])
    scenarios, inventory = [], []
    for name in NAMES:
        grouped = {}
        for row in rows[name]:
            grouped.setdefault(int(row['frame.number']), []).append(row)
        expected = {'events': [{'frame': frame, 'objects': expected_objects(group, name)} for frame, group in grouped.items()]}
        if name in ['msp', 'msp32']:
            expected['coverage_blocker'] = 'adapter returns service-not-supported (0x08); no MSP child replies or 0x1e; scanner exits 1'
        if name == 'udp-short-mutation':
            expected['mutation'] = json.loads((out / 'udp-short-mutation.mutation.json').read_text())
        (out / f'{name}.expectations.json').write_text(json.dumps(expected, indent=2) + '\n')
        assets = [f'{name}.pdml.gz']
        if name in NAMES[:5]:
            assets += [f'{name}-{suffix}' for suffix in ['scanner.log', 'adapter.log', 'tcpdump.log', 'scanner.exit']]
        if name == 'native-io':
            assets.append('native-io.lineage.json')
        if name == 'udp-short-mutation':
            assets.append('udp-short-mutation.mutation.json')
        transport = 'udp' if name in NAMES[-2:] else 'tcp'
        scenario = {'name': name, 'pcap': f'{name}.pcap', 'oracle': f'{name}.expected.tsv',
                    'expectations': f'{name}.expectations.json', 'transport': transport,
                    'checksum_offload': 'none; IPv4/UDP checksums recomputed' if name == 'udp-short-mutation' else 'Docker bridge TX partial checksums retained; not a checksum-validity oracle',
                    'contiguous': transport == 'tcp', 'oracle_frames': list(grouped), 'assets': assets}
        if transport == 'udp':
            scenario['roles'] = udp_roles(out / f'{name}.pcap', adapter)
        scenarios.append(scenario)
        inventory += [scenario[k] for k in ['pcap', 'oracle', 'expectations']] + assets
    shutil.copyfile(inputs / 'source-lock.json', out / 'source-lock.json')
    for asset in ['generator-image.json', 'generator-packages.txt', 'source-lock.json']:
        scenarios[0]['assets'].append(asset)
        inventory.append(asset)
    recipes = {str(p.relative_to(inputs)): digest(p) for p in sorted(inputs.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
    manifest = {'version': 1, 'protocol': 'cip', 'provenance': {
        'source': (inputs / 'source-lock.json').read_text().strip(),
        'generator': 'generator.Dockerfile; Debian bookworm base pinned by digest and packages from snapshot 20261001T000000Z; generator-image.json and generator-packages.txt; unmodified OpENer POSIX sample and EIPScanner; Release CMake',
        'oracle': 'tshark 4.6.7 b439fb7b47a9; -n -o tcp.desegment_tcp_streams:TRUE -o enip.desegment:TRUE -o enip.o2t_run_idle:TRUE -o enip.t2o_run_idle:FALSE -T pdml; gzip mtime=0; size-zero inferred paths excluded from TSV',
        'license': 'Apache-2.0 fixtures and local driver; BSD-style OpENer and MIT EIPScanner notices retained in capture/LICENSES; no bundled captures',
        'topology': 'independent EIPScanner originator and OpENer adapter on invocation-owned private Docker bridges, no containd or host ports',
        'capture_side': 'tcpdump --immediate-mode -U -i eth0 in adapter network namespace; classic Ethernet pcap',
        'limitations': 'MSP probes fail with service-not-supported 0x08, not 0x1e; only request children and count32 have captured coverage. Current decoder deliberately reports opaque service/registration bodies and socket-address CPF items as undecoded; these are decoder limitations, not stack deviations.',
        'inputs_sha256': json.dumps(recipes, separators=(',', ':')),
    }, 'scenarios': scenarios}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (out / 'SHA256SUMS').write_text(''.join(digest(out / name) + '  ' + name + '\n' for name in sorted(inventory)))
    if sum(p.stat().st_size for p in out.iterdir() if p.is_file()) > 2 * 1024 * 1024:
        raise RuntimeError('testdata exceeds 2 MiB')


if __name__ == '__main__':
    finalize(Path(sys.argv[1]), Path(sys.argv[2]))
