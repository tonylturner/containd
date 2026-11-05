# SPDX-License-Identifier: Apache-2.0
import copy
import csv
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from build_site import build, collect
from fetch_archives import fetch


def document(identifier='example', date='2026-04-09T00:00:00Z', category='csaf_vex'):
    return {'document': {'category': category, 'tracking': {'id': identifier,
            'initial_release_date': date, 'current_release_date': date}}}


class SiteTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.advisories = self.root / 'advisories'
        self.advisories.mkdir()
        self.archives = self.root / 'archives'
        self.archives.mkdir()

    def archive(self, doc, name='../../example.json', path='release.tgz'):
        with tarfile.open(self.archives / path, 'w:gz') as archive:
            data = json.dumps(doc).encode()
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))

    def test_layout_dates_hashes_and_determinism(self):
        first = document()
        first['document']['tracking']['current_release_date'] = '2027-01-02T00:00:00Z'
        docs = {'example': first, 'new': document('new', '2027-01-01T00:00:00Z')}
        directory = build(docs, self.root / 'site')
        metadata = json.loads((directory / 'provider-metadata.json').read_text())
        self.assertEqual(metadata['last_updated'], '2027-01-02T00:00:00Z')
        self.assertEqual(metadata['role'], 'csaf_publisher')
        self.assertIn('/containd/.well-known/csaf/', metadata['canonical_url'])
        self.assertEqual((directory / 'index.txt').read_text().splitlines(), ['2026/example.json', '2027/new.json'])
        with (directory / 'changes.csv').open() as stream:
            self.assertEqual(list(csv.reader(stream))[0], ['2026/example.json', '2027-01-02T00:00:00Z'])
        for path in directory.glob('*/*.json'):
            for algorithm in ('sha256', 'sha512'):
                self.assertEqual(path.with_suffix('.json.' + algorithm).read_text().split()[0],
                                 hashlib.new(algorithm, path.read_bytes()).hexdigest())
            self.assertIn(path.name, (path.parent / 'index.html').read_text())
        other = build(docs, self.root / 'other')
        self.assertEqual({p.relative_to(directory): p.read_bytes() for p in directory.rglob('*') if p.is_file()},
                         {p.relative_to(other): p.read_bytes() for p in other.rglob('*') if p.is_file()})
        with self.assertRaises(ValueError):
            build(docs, self.root / 'site')

    def test_newest_date_compares_instants_not_calendar_strings(self):
        docs = {'advisory': document('advisory', '2026-11-05T00:00:00Z'),
                'vex': document('vex', '2026-11-04T19:45:25-05:00')}
        directory = build(docs, self.root / 'timezones')
        metadata = json.loads((directory / 'provider-metadata.json').read_text())
        self.assertEqual(metadata['last_updated'], '2026-11-04T19:45:25-05:00')
        with (directory / 'changes.csv').open() as stream:
            self.assertEqual(next(csv.reader(stream))[0], '2026/vex.json')

    def test_archived_vex_only_and_repository_wins(self):
        archived = document()
        self.archive(archived)
        # Reading archive JSON never creates the archive-supplied traversal path.
        self.assertEqual(collect(self.advisories, archives=self.archives), {'example': archived})
        repo = document(category='csaf_security_advisory')
        repo['document']['tracking']['current_release_date'] = '2026-11-05T00:00:00Z'
        (self.advisories / 'example.json').write_text(json.dumps(repo))
        self.assertEqual(collect(self.advisories, archives=self.archives)['example'], repo)
        other_revision = copy.deepcopy(archived)
        other_revision['extra'] = True
        self.archive(other_revision, path='another-revision.tgz')
        self.assertEqual(collect(self.advisories, archives=self.archives)['example'], repo)
        self.archive(document('old', category='csaf_security_advisory'), name='old.json', path='legacy.tgz')
        self.assertNotIn('old', collect(self.advisories, archives=self.archives))

    def test_conflicting_archives_rejected(self):
        doc = document()
        self.archive(doc)
        other = copy.deepcopy(doc)
        other['extra'] = True
        self.archive(other, path='different.tgz')
        with self.assertRaisesRegex(ValueError, 'Conflicting archived'):
            collect(self.advisories, archives=self.archives)

    def test_unsafe_ids_and_empty_site_rejected(self):
        with self.assertRaises(ValueError):
            build({}, self.root / 'empty')
        with self.assertRaises(ValueError):
            build({'other': document('example')}, self.root / 'bad')

    def test_archive_links_rejected(self):
        with tarfile.open(self.archives / 'link.tgz', 'w:gz') as archive:
            member = tarfile.TarInfo('example.json')
            member.type = tarfile.SYMTYPE
            member.linkname = '/etc/passwd'
            archive.addfile(member)
        with self.assertRaisesRegex(ValueError, 'Unsafe JSON archive member'):
            collect(self.advisories, archives=self.archives)

    def test_normalized_site_names_and_mismatch_rejected(self):
        doc = document('containd-vex-0.1.42')
        directory = build({'containd-vex-0.1.42': doc}, self.root / 'normalized')
        self.assertTrue((directory / '2026/containd-vex-0_1_42.json').is_file())
        self.archive(doc, name='containd-vex-0.1.42.json')
        with self.assertRaisesRegex(ValueError, 'CSAF filename must be'):
            collect(self.advisories, archives=self.archives)
        with self.assertRaisesRegex(ValueError, 'collision'):
            build({'a.b': document('a.b'), 'a_b': document('a_b')}, self.root / 'collision')

    def test_fetch_all_pages_prereleases_and_missing_assets(self):
        release = {'draft': False, 'published_at': '2026-01-01', 'tag_name': 'v1.0.0',
                   'assets': [{'name': 'csaf-documents.tgz', 'id': 42}]}
        prerelease = dict(release, tag_name='v1.1.0-rc.1', assets=[{'name': 'csaf-documents.tgz', 'id': 43}])
        with patch('fetch_archives.subprocess.run') as run:
            fetch([[release, dict(release, draft=True)], [prerelease, dict(release, assets=[])]],
                  'tonylturner/containd', self.root / 'downloads')
            self.assertEqual(run.call_count, 2)
            self.assertIn('repos/tonylturner/containd/releases/assets/43', run.call_args.args[0])
            self.assertTrue(run.call_args.kwargs['check'])


if __name__ == '__main__':
    unittest.main()
