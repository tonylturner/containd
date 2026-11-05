# SPDX-License-Identifier: Apache-2.0
import copy
import json
import tempfile
import unittest
from pathlib import Path
from common import assert_filename, csaf_filename, includes, load_triage, version_key, write_csaf
from generate import generate
from ignore import ignorefile

VERSION = '0.1.42'
DATE = '2026-11-04T12:00:00Z'
CVE = 'CVE-2026-20337'


def statement(status='known_not_affected'):
    return {'cve': CVE, 'products': ['containd'],
            'version_range': {'introduced': VERSION, 'before': '0.1.43'},
            'status': status, 'details': 'The vulnerable component is not present.',
            'flag': 'component_not_present'}


class GeneratorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / 'release-images.txt'
        lines = []
        for prefix, product, digit in [('mgmt', 'containd', 'a'), ('engine', 'containd-engine', 'b')]:
            repo, digest = f'ghcr.io/tonylturner/{product}', 'sha256:' + digit * 64
            lines += [f'{prefix}_image={repo}:{VERSION}', f'{prefix}_digest={digest}']
            for arch in ('amd64', 'arm64'):
                data = {'ArtifactType': 'container_image', 'ArtifactName': f'{repo}@{digest}',
                        'Metadata': {'RepoDigests': [f'{repo}@{digest}'], 'ImageConfig': {'architecture': arch}},
                        'Results': [{'Vulnerabilities': [{'VulnerabilityID': CVE,
                                     'PkgIdentifier': {'PURL': 'pkg:apk/wolfi/clamav-1.5@1.5.2-r7'}}]}]}
                (self.root / f'trivy-{product}-{arch}.json').write_text(json.dumps(data))
        self.manifest.write_text('\n'.join(lines))

    def run_generator(self, statements=()):
        return generate(VERSION, self.manifest, self.root, statements, DATE)

    def empty_scans(self):
        for path in self.root.glob('trivy-*.json'):
            scan = json.loads(path.read_text())
            scan['Results'] = []
            path.write_text(json.dumps(scan))

    def load(self, statements):
        path = self.root / 'triage.json'
        path.write_text(json.dumps({'schema_version': 1, 'statements': statements}))
        return load_triage(path)

    def test_normalized_filename_enforced(self):
        doc, _ = self.run_generator()
        name = csaf_filename(doc['document']['tracking']['id'])
        self.assertEqual(name, 'containd-vex-0_1_42.json')
        self.assertEqual(csaf_filename('A.B/ C+X'), 'a_b_c+x.json')
        assert_filename(doc, name)
        with self.assertRaises(ValueError):
            write_csaf(self.root / 'containd-vex-0.1.42.json', doc)
        write_csaf(self.root / name, doc)

    def test_untriaged_and_deterministic(self):
        doc, summary = self.run_generator()
        self.assertEqual((doc, summary), self.run_generator())
        self.assertEqual(len(doc['vulnerabilities'][0]['product_status']['under_investigation']), 6)
        self.assertIn('containd-engine', summary)
        self.assertIn(CVE, summary)
        self.assertEqual(doc['document']['tracking']['current_release_date'], DATE)
        purl = doc['product_tree']['branches'][0]['branches'][0]['product']['product_identification_helper']['purl']
        self.assertIn('@sha256:' + 'a' * 64, purl)
        self.assertIn('repository_url=ghcr.io%2Ftonylturner%2Fcontaind', purl)

    def test_all_statuses_and_product_scope(self):
        for status in ('known_not_affected', 'known_affected', 'fixed', 'under_investigation'):
            with self.subTest(status=status):
                s = statement(status)
                if status == 'known_affected':
                    s['remediation'] = {'category': 'none_available', 'details': 'Investigation continues.'}
                doc, summary = self.run_generator(self.load([s]))
                v = doc['vulnerabilities'][0]
                self.assertIn('containd-0.1.42', v['product_status'][status])
                self.assertIn('containd-engine-0.1.42', v['product_status']['under_investigation'])
                self.assertEqual(bool(ignorefile([s], 'containd', VERSION)['vulnerabilities']), status == 'known_not_affected')
                self.assertFalse(ignorefile([s], 'containd-engine', VERSION)['vulnerabilities'])
                if status in ('known_affected', 'under_investigation'):
                    self.assertIn(f'— {status}', summary)

    def test_triage_without_hit_and_empty_document(self):
        self.empty_scans()
        self.assertIsNone(self.run_generator()[0])
        doc, _ = self.run_generator([statement()])
        self.assertEqual(doc['vulnerabilities'][0]['cve'], CVE)
        self.assertEqual(len(doc['vulnerabilities'][0]['product_status']['known_not_affected']), 3)

    def test_range_boundaries_and_prerelease(self):
        s = statement()
        self.assertFalse(includes(s, '0.1.41'))
        self.assertFalse(includes(s, '0.1.42-rc.1'))
        self.assertTrue(includes(s, VERSION))
        self.assertFalse(includes(s, '0.1.43'))
        self.assertFalse(ignorefile([s], 'containd', '0.1.43')['vulnerabilities'])
        self.assertLess(version_key('1.0.0-rc.2'), version_key('1.0.0-rc.10'))
        self.assertLess(version_key('1.0.0-rc.10'), version_key('1.0.0'))
        with self.assertRaises(ValueError):
            version_key('1.0.0-01')

    def test_reject_bad_triage(self):
        for field, value in [('details', ''), ('flag', 'wrong'), ('status', 'ignored'),
                             ('products', ['other']), ('version_range', {'introduced': 'latest'})]:
            s = statement()
            s[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load([s])
        s = statement()
        del s['flag']
        with self.assertRaises(ValueError):
            self.load([s])
        s['status'] = 'known_affected'
        with self.assertRaises(ValueError):
            self.load([s])
        with self.assertRaises(ValueError):
            self.load([statement(), statement()])

    def test_impact_justification_and_ignorefile_shape(self):
        s = statement()
        del s['flag']
        s['threat'] = 'The input is not reachable in the supported deployment.'
        self.load([s])
        doc, _ = self.run_generator([s])
        self.assertEqual(doc['vulnerabilities'][0]['threats'][0]['category'], 'impact')
        self.assertEqual(ignorefile([s], 'containd', VERSION),
                         {'vulnerabilities': [{'id': CVE, 'statement': s['details']}]})

    def test_wrong_scan_identity_or_arch_rejected(self):
        path = self.root / 'trivy-containd-amd64.json'
        original = json.loads(path.read_text())
        for key in ('ArtifactName', 'architecture'):
            scan = copy.deepcopy(original)
            if key == 'architecture':
                scan['Metadata']['ImageConfig'][key] = 'arm64'
            else:
                scan[key] = 'ghcr.io/other/image@sha256:' + 'c' * 64
            path.write_text(json.dumps(scan))
            with self.assertRaises(ValueError):
                self.run_generator()

    def test_non_cve_scan_ids(self):
        path = self.root / 'trivy-containd-amd64.json'
        scan = json.loads(path.read_text())
        scan['Results'][0]['Vulnerabilities'][0]['VulnerabilityID'] = 'GHSA-w67g-5rqw-f597'
        path.write_text(json.dumps(scan))
        doc, _ = self.run_generator()
        v = next(v for v in doc['vulnerabilities'] if 'ids' in v)
        self.assertEqual(v['ids'][0]['text'], 'GHSA-w67g-5rqw-f597')
        self.assertEqual(v['product_status']['under_investigation'], ['containd-0.1.42-amd64'])


if __name__ == '__main__':
    unittest.main()
