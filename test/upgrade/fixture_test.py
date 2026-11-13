# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch as mock_patch

from fixture import (MATRIX, assert_config, assert_mode_audit, assert_protection, assert_revision,
                     has_cas, schema_authority, seed)
from run import API, Row, free_subnets, resources


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[2]
        self.schema = schema_authority(self.root)
        self.cfg = seed({'system': {}}, '0.1.35', {'lan1': 'eth0', 'wan': 'eth1'},
                        '10.210.42', '10.211.42', 'running')

    def migrated(self):
        cfg = copy.deepcopy(self.cfg)
        cfg['schema_version'] = self.schema
        cfg['dataplane']['dpiMode'] = 'monitor'
        cfg['firewall']['rules'][2]['ics']['mode'] = 'monitor'
        for row in cfg['interfaces']:
            del row['device']
        return cfg

    def verify(self, cfg):
        assert_config(cfg, self.schema, 'running', '10.210.42', '10.211.42')

    def test_exact_matrix(self):
        self.assertEqual(len(MATRIX), 17)
        self.assertEqual(len(set(MATRIX)), 17)
        self.assertEqual([v for v, p in MATRIX if p == 'strict'],
                         ['0.1.39', '0.1.40', '0.1.41', '0.1.42'])

    def test_cas_cutover(self):
        self.assertFalse(has_cas('0.1.36'))
        self.assertTrue(has_cas('0.1.37'))

    def test_historical_modes_and_devices(self):
        self.assertEqual(self.cfg['dataplane']['dpiMode'], 'learn')
        self.assertEqual(self.cfg['interfaces'][0]['device'], 'eth0')
        self.assertEqual(self.cfg['system']['mgmt']['httpListenAddr'], ':18080')
        self.assertEqual(self.cfg['system']['mgmt']['httpsListenAddr'], ':18443')
        modern = seed({'system': {}}, '0.1.41', {}, '10.210.42', '10.211.42', 'candidate')
        self.assertNotIn('device', modern['interfaces'][0])
        self.assertEqual(modern['dataplane']['dpiMode'], 'monitor')

    def test_no_base_mutation(self):
        base = {'system': {'hostname': 'untouched'}}
        seed(base, '0.1.42', {}, '10.210.42', '10.211.42', 'candidate')
        self.assertEqual(base, {'system': {'hostname': 'untouched'}})

    def test_valid_migration(self):
        self.verify(self.migrated())

    def test_wrong_schema(self):
        cfg = self.migrated()
        cfg['schema_version'] = self.schema + '-mismatch'
        with self.assertRaises(AssertionError):
            self.verify(cfg)

    def test_lost_or_committed_candidate(self):
        cfg = self.migrated()
        cfg['system']['hostname'] = 'upgrade-candidate'
        with self.assertRaises(AssertionError):
            self.verify(cfg)

    def test_lost_bank(self):
        cfg = self.migrated()
        cfg['ids']['rules'] = []
        with self.assertRaises(AssertionError):
            self.verify(cfg)

    def test_retained_device_is_failure(self):
        cfg = self.migrated()
        cfg['interfaces'][0]['device'] = 'eth0'
        with self.assertRaises(AssertionError):
            self.verify(cfg)

    def test_mode_not_migrated(self):
        cfg = self.migrated()
        cfg['firewall']['rules'][2]['ics']['mode'] = 'learn'
        with self.assertRaises(AssertionError):
            self.verify(cfg)

    def test_protection_requires_revision_agreement(self):
        status = {'ready': True, 'state': 'protecting', 'desiredRevision': 'abc',
                  'appliedRevision': 'abc', 'protectingRevision': 'abc'}
        self.assertEqual(assert_protection(status), 'abc')
        for field, value in [('ready', False), ('state', 'degraded'),
                             ('protectingRevision', 'other'), ('appliedRevision', 'other'),
                             ('desiredRevision', 'recovery:abc')]:
            wrong = dict(status, **{field: value})
            with self.subTest(field=field), self.assertRaises(AssertionError):
                assert_protection(wrong)

    def test_revision_preserves_epoch_not_counter_equality(self):
        assert_revision('0123456789abcdef.1', '0123456789abcdef.2')
        assert_revision('', '0123456789abcdef.1')
        for old, new in [('0123456789abcdef.2', '0123456789abcdef.1'),
                         ('0123456789abcdef.1', 'fedcba9876543210.1'), ('', '')]:
            with self.subTest(old=old, new=new), self.assertRaises(AssertionError):
                assert_revision(old, new)

    def test_exact_mode_audit_payloads_and_banks(self):
        records = [{'action': 'config.rule_modes.migrated',
                    'detail': json.dumps({'bank': bank, 'schemaAfter': '0.1.9',
                                          'changes': [{}, {}]})}
                   for bank in ('running', 'previous', 'candidate')]
        assert_mode_audit(records)
        for bad in (records[:-1], records + records[:1]):
            with self.assertRaises(AssertionError):
                assert_mode_audit(bad)
        records[0]['detail'] = json.dumps({'bank': 'running', 'schemaAfter': 'wrong', 'changes': [{}, {}]})
        with self.assertRaises(AssertionError):
            assert_mode_audit(records)

    @mock_patch('run.command', return_value='')
    def test_resource_queries_are_project_scoped(self, command):
        self.assertEqual(resources('upgrade-test'), {'containers': [], 'networks': [], 'volumes': []})
        for call in command.call_args_list:
            self.assertEqual(call.args[-1], 'label=com.docker.compose.project=upgrade-test')

    @mock_patch('run.secrets.randbelow', side_effect=[42, 43])
    @mock_patch('run.command', side_effect=['net1', '[{"IPAM":{"Config":[{"Subnet":"10.210.42.0/24"}]}}]'])
    def test_subnet_overlap_is_rejected(self, _command, _random):
        self.assertEqual(free_subnets(), ['10.210.43', '10.211.43'])

    @mock_patch('run.secrets.randbelow', return_value=42)
    @mock_patch('run.command', side_effect=['net1', '[{"IPAM":{"Config":null}}]'])
    def test_network_without_ipam(self, _command, _random):
        self.assertEqual(free_subnets(), ['10.210.42', '10.211.42'])

    def test_transport_will_not_forge_revision(self):
        api = API('http://127.0.0.1', None, True)
        with self.assertRaises(AssertionError):
            api.call('/config/candidate', {}, config_write=True)

    def test_running_snapshot_uses_export_with_bank(self):
        api = API('http://127.0.0.1', None, True)
        cfg = self.migrated()
        with mock_patch.object(api, 'call', return_value=cfg) as call:
            self.assertEqual(api.snapshot('running'), cfg)
            call.assert_called_once_with('/config/export')

    def test_candidate_snapshot_reads_its_own_bank(self):
        api = API('http://127.0.0.1', None, True)
        cfg = self.migrated()
        ids = cfg.pop('ids')
        with mock_patch.object(api, 'call', side_effect=[cfg, ids]) as call:
            self.assertEqual(api.snapshot('candidate')['ids'], ids)
            self.assertEqual([c.args for c in call.call_args_list],
                             [('/config/candidate',), ('/ids/rules',)])

    def test_manifest_is_private_and_names_every_attachment(self):
        with tempfile.TemporaryDirectory() as tmp:
            class Run:
                path = Path(tmp)
                endpoint = 'endpoint:test'
                secret = 'a' * 64
            row = Row(Run(), '0.1.35', 'strict', '10.210.42', '10.211.42')
            with mock_patch.object(row, 'compose'):
                row.manifest('candidate:test', True)
            doc = json.loads(row.compose_file.read_text())
            appliance = doc['services']['appliance']
            self.assertEqual(appliance['ports'], ['127.0.0.1::18443'])
            self.assertEqual({n: c['interface_name'] for n, c in appliance['networks'].items()},
                             {'lan': 'lan1', 'wan': 'wan'})
            self.assertEqual(appliance['volumes'], [f'{row.data}:/data'])
            self.assertNotIn('CONTAIND_LAB_MODE', appliance['environment'])


if __name__ == '__main__':
    unittest.main()
