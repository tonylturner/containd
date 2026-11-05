# SPDX-License-Identifier: Apache-2.0
"""Exercise generated VEX with the same full validator used by CI and releases."""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from common import ROOT, csaf_filename, write_csaf
from generate import generate


class FullValidationTest(unittest.TestCase):
    def test_every_status_and_mandatory_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, lines = root / 'release-images.txt', []
            for prefix, product, digit in [('mgmt', 'containd', 'a'), ('engine', 'containd-engine', 'b')]:
                repo, digest = f'ghcr.io/tonylturner/{product}', 'sha256:' + digit * 64
                lines += [f'{prefix}_image={repo}:1.2.3', f'{prefix}_digest={digest}']
                for arch in ('amd64', 'arm64'):
                    scan = {'ArtifactType': 'container_image', 'ArtifactName': f'{repo}@{digest}',
                            'Metadata': {'RepoDigests': [f'{repo}@{digest}'], 'ImageConfig': {'architecture': arch}},
                            'Results': []}
                    (root / f'trivy-{product}-{arch}.json').write_text(json.dumps(scan))
            manifest.write_text('\n'.join(lines))
            docs = root / 'documents'
            docs.mkdir()
            for status in ('known_not_affected', 'known_affected', 'fixed', 'under_investigation'):
                statement = {'cve': 'CVE-2026-1111', 'products': ['containd'],
                             'version_range': {'introduced': '1.2.3'}, 'status': status,
                             'details': 'Synthetic validation fixture; not a vendor assessment.'}
                if status == 'known_not_affected':
                    statement['flag'] = 'component_not_present'
                if status == 'known_affected':
                    statement['remediation'] = {'category': 'none_available', 'details': 'Synthetic fixture.'}
                doc, _ = generate('1.2.3', manifest, root, [statement], '2026-01-01T00:00:00Z')
                doc['document']['tracking']['id'] += '-' + status
                write_csaf(docs / csaf_filename(doc['document']['tracking']['id']), doc)
            result = subprocess.run(['bash', 'scripts/csaf/validate.sh', str(docs)], cwd=ROOT,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            # Schema-valid but semantically invalid product reference: mandatory tests must fail.
            doc['vulnerabilities'][0]['product_status'] = {'under_investigation': ['nonexistent-product']}
            bad = root / csaf_filename(doc['document']['tracking']['id'])
            write_csaf(bad, doc)
            result = subprocess.run(['bash', 'scripts/csaf/validate.sh', str(bad)], cwd=ROOT,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 8, result.stdout + result.stderr)
            self.assertIn('does not pass remote validation', result.stdout + result.stderr)
            self.assertIn('mandatoryTest_6_1_1', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
