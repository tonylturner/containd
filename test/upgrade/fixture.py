# SPDX-License-Identifier: Apache-2.0
"""Historical API fixtures and exact, intentional migration assertions."""
import copy
import json
import re

MATRIX = [(f'0.1.{v}', 'training') for v in range(30, 43)] + [
    (f'0.1.{v}', 'strict') for v in range(39, 43)]


def patch(version):
    return int(version.split('.')[2])


def has_cas(version):
    return patch(version) >= 37


def schema_authority(root):
    text = (root / 'pkg/cp/config/version.go').read_text()
    return re.search(r'SchemaVersionCurrent\s*=\s*"([^"]+)"', text)[1]


def seed(base, version, devices, lan, wan, bank):
    cfg = copy.deepcopy(base)
    cfg['system']['hostname'] = f'upgrade-{bank}'
    # Stored listener intent must match the explicitly selected container ports;
    # nft management admission uses the saved ports, not Docker's host mapping.
    cfg['system'].setdefault('mgmt', {}).update(
        listenAddr=':18080', httpListenAddr=':18080', httpsListenAddr=':18443')
    cfg['description'] = f'upgrade {bank} sentinel'
    cfg['zones'] = [{'name': 'lan'}, {'name': 'wan'}]
    cfg['interfaces'] = []
    for name, zone, address in [('lan1', 'lan', lan), ('wan', 'wan', wan)]:
        row = {'name': name, 'zone': zone, 'addresses': [address + '.2/24'],
               'addressMode': 'static'}
        if patch(version) < 41:
            row['device'] = devices[name]
        cfg['interfaces'].append(row)
    cfg['dataplane'] = {'enforcement': True, 'enforceTable': 'containd',
                        'dpiMode': 'learn' if patch(version) < 36 else 'monitor'}
    cfg['firewall'] = {'defaultAction': 'DENY', 'nat': {'enabled': False}, 'rules': [
        {'id': 'allow-http', 'sourceZones': ['lan'], 'destZones': ['wan'],
         'protocols': [{'name': 'tcp', 'port': '18081'}], 'action': 'ALLOW'},
        {'id': 'deny-http', 'sourceZones': ['lan'], 'destZones': ['wan'],
         'protocols': [{'name': 'tcp', 'port': '18082'}], 'action': 'DENY'},
        {'id': 'mode-sentinel', 'sourceZones': ['lan'], 'destZones': ['wan'],
         'protocols': [{'name': 'tcp', 'port': '502'}], 'action': 'DENY',
         'ics': {'protocol': 'modbus', 'mode': 'learn' if patch(version) < 36 else 'monitor'}}]}
    # Custom evaluable bank, distinct across previous/running/candidate.
    cfg['ids'] = {'enabled': True, 'rules': [{'id': f'upgrade-{bank}',
        'title': f'Upgrade {bank}', 'proto': 'http', 'severity': 'low',
        'when': {'field': 'kind', 'op': 'equals', 'value': 'http.request'},
        'message': f'upgrade {bank} sentinel'}]}
    # Keep services disabled; this is a storage and routed-policy test, not an AV/VPN test.
    cfg['services'] = {}
    return cfg


def assert_config(cfg, schema, bank, lan, wan):
    assert cfg['schema_version'] == schema, cfg.get('schema_version')
    assert cfg['system']['hostname'] == f'upgrade-{bank}'
    assert cfg['description'] == f'upgrade {bank} sentinel'
    assert cfg['zones'] == [{'name': 'lan'}, {'name': 'wan'}]
    rows = {r['name']: r for r in cfg['interfaces']}
    assert set(rows) == {'lan1', 'wan'}, rows
    for name, prefix, zone in [('lan1', lan, 'lan'), ('wan', wan, 'wan')]:
        assert 'device' not in rows[name], rows[name]
        assert rows[name]['zone'] == zone
        assert rows[name]['addresses'] == [prefix + '.2/24']
    assert cfg['dataplane']['enforcement'] is True
    assert cfg['dataplane']['dpiMode'] == 'monitor'
    assert cfg['firewall']['defaultAction'] == 'DENY'
    rules = cfg['firewall']['rules']
    assert [r['id'] for r in rules] == ['allow-http', 'deny-http', 'mode-sentinel']
    assert [r['action'] for r in rules] == ['ALLOW', 'DENY', 'DENY']
    assert rules[2]['ics']['mode'] == 'monitor'
    assert [r['id'] for r in cfg['ids']['rules']] == [f'upgrade-{bank}']


def assert_protection(status):
    assert status.get('ready') is True, status
    assert status.get('state') == 'protecting', status
    revision = status.get('desiredRevision')
    assert revision and not revision.startswith('recovery:'), status
    assert status.get('appliedRevision') == revision, status
    assert status.get('protectingRevision') == revision, status
    return revision


def assert_revision(old, new):
    assert re.fullmatch(r'[0-9a-f]{16}\.[1-9][0-9]*', new), new
    if old:
        epoch, counter = old.split('.')
        new_epoch, new_counter = new.split('.')
        assert epoch == new_epoch and int(new_counter) >= int(counter), (old, new)


def assert_mode_audit(records):
    records = [json.loads(r['detail']) for r in records
               if r.get('action') == 'config.rule_modes.migrated']
    assert len(records) == 3, records
    assert {r['bank'] for r in records} == {'running', 'previous', 'candidate'}, records
    for record in records:
        assert record['schemaAfter'] == '0.1.9', record
        assert len(record['changes']) == 2, record
