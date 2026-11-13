# SPDX-License-Identifier: Apache-2.0
import json
import tempfile
import unittest
from pathlib import Path
from validate import documents


class ValidationTest(unittest.TestCase):
    def test_file_discovery_and_filename_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            doc = {'document': {'tracking': {'id': 'example-1.2'}}}
            with self.assertRaises(ValueError):
                documents([root])
            (root / 'provider-metadata.json').write_text('{}')
            path = root / 'example-1_2.json'
            path.write_text(json.dumps(doc))
            self.assertEqual(documents([root, path]), [path])
            bad = root / 'example-1.2.json'
            bad.write_text(json.dumps(doc))
            with self.assertRaisesRegex(ValueError, 'CSAF filename must be'):
                documents([root])
            with self.assertRaisesRegex(ValueError, 'Missing validation input'):
                documents([root / 'absent'])


if __name__ == '__main__':
    unittest.main()
