# SPDX-License-Identifier: Apache-2.0
import copy
import unittest
from gate import check


class GateTest(unittest.TestCase):
    def setUp(self):
        self.doc = {'document': {'category': 'csaf_security_advisory', 'tracking': {'id': 'example'}},
                    'product_tree': {'branches': [{'category': 'product_version', 'name': '1.2.3',
                                                  'product': {'product_id': 'fixed-1.2.3', 'name': 'containd 1.2.3'}}]},
                    'vulnerabilities': [{'product_status': {'fixed': ['fixed-1.2.3']}}]}
        self.changelog = '## [Unreleased]\n### Security\n- Pending\n## [1.2.3] - 2026-01-01\n### Security\n- Fix\n## [1.2.2]\n'

    def test_requires_exact_fixed_version(self):
        self.assertIn('example', check('1.2.3', self.changelog, [self.doc]))
        for value in ('1.2.2', '1.2.30', '1.2.3-rc.1'):
            doc = copy.deepcopy(self.doc)
            doc['product_tree']['branches'][0]['name'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'advisory is required'):
                check('1.2.3', self.changelog, [doc])

    def test_unreleased_and_previous_sections_ignored(self):
        self.assertIn('no advisory required', check('1.2.3', self.changelog.replace('### Security\n- Fix', '### Fixed\n- Fix'), []))

    def test_missing_or_wrong_status_fails(self):
        with self.assertRaisesRegex(ValueError, 'Missing CHANGELOG'):
            check('2.0.0', self.changelog, [])
        with self.assertRaisesRegex(ValueError, 'move the entry to Changed/Fixed'):
            check('1.2.3', self.changelog, [])
        self.doc['vulnerabilities'][0]['product_status'] = {'known_affected': ['fixed-1.2.3']}
        with self.assertRaises(ValueError):
            check('1.2.3', self.changelog, [self.doc])

    def test_vex_is_not_an_advisory(self):
        self.doc['document']['category'] = 'csaf_vex'
        with self.assertRaises(ValueError):
            check('1.2.3', self.changelog, [self.doc])


if __name__ == '__main__':
    unittest.main()
