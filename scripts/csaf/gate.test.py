# SPDX-License-Identifier: Apache-2.0
import copy
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from common import ROOT
from gate import check


class GateTest(unittest.TestCase):
    def setUp(self):
        self.doc = {'document': {'category': 'csaf_security_advisory', 'tracking': {'id': 'example'}},
                    'product_tree': {'branches': [{'category': 'product_version', 'name': '1.2.3',
                                                  'product': {'product_id': 'fixed-1.2.3', 'name': 'containd 1.2.3'}}]},
                    'vulnerabilities': [{'product_status': {'fixed': ['fixed-1.2.3']}}]}
        self.changelog = '## [Unreleased]\n### Security\n- Pending\n## [1.2.3] - 2026-01-01\n### Security\n- Fix\n## [1.2.2]\n'

    def test_warns_unless_exact_fixed_version(self):
        self.assertIn('example', check('1.2.3', self.changelog, [self.doc]))
        for value in ('1.2.2', '1.2.30', '1.2.3-rc.1'):
            doc = copy.deepcopy(self.doc)
            doc['product_tree']['branches'][0]['name'] = value
            with self.subTest(value=value):
                self.assertTrue(check('1.2.3', self.changelog, [doc]).startswith('::warning::'))

    def test_unreleased_and_previous_sections_ignored(self):
        self.assertIn('no advisory required', check('1.2.3', self.changelog.replace('### Security\n- Fix', '### Fixed\n- Fix'), []))

    def test_missing_changelog_fails_and_missing_fix_warns(self):
        with self.assertRaisesRegex(ValueError, 'Missing CHANGELOG'):
            check('2.0.0', self.changelog, [])
        self.assertIn('does not block', check('1.2.3', self.changelog, []))
        self.doc['vulnerabilities'][0]['product_status'] = {'known_affected': ['fixed-1.2.3']}
        self.assertTrue(check('1.2.3', self.changelog, [self.doc]).startswith('::warning::'))

    def test_vex_is_not_an_advisory(self):
        self.doc['document']['category'] = 'csaf_vex'
        self.assertTrue(check('1.2.3', self.changelog, [self.doc]).startswith('::warning::'))

    def test_malformed_inputs_fail_even_after_valid_advisory(self):
        for doc in ({}, {'document': None}, dict(self.doc, vulnerabilities=None),
                    dict(self.doc, vulnerabilities=[]),
                    dict(self.doc, vulnerabilities=[{'product_status': {'fixed': []}}]),
                    dict(self.doc, vulnerabilities=[{'product_status': {'fixed': ['unknown']}}])):
            for changelog in (self.changelog, self.changelog.replace('### Security', '### Fixed')):
                with self.subTest(doc=doc), self.assertRaises(ValueError):
                    check('1.2.3', changelog, [self.doc, doc])
        with self.assertRaises(ValueError):
            check('latest', self.changelog, [])

    def test_warning_cli_exits_zero_and_writes_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'VERSION').write_text('1.2.3\n')
            (root / 'CHANGELOG').write_text(self.changelog)
            (root / 'advisories').mkdir()
            summary = root / 'summary'
            command = ['python3', 'scripts/csaf/gate.py', '--version-file', str(root / 'VERSION'),
                       '--changelog', str(root / 'CHANGELOG'), '--advisories', str(root / 'advisories')]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                    env=dict(os.environ, GITHUB_STEP_SUMMARY=str(summary)))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.startswith('::warning::'))
            self.assertIn('no advisory', summary.read_text())
            (root / 'advisories/bad.json').write_text('{broken')
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
