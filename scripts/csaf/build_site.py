# SPDX-License-Identifier: Apache-2.0
"""Assemble a browsable CSAF directory from source advisories and release VEX archives."""
import argparse
import csv
import hashlib
import html
import io
import tarfile
from pathlib import Path
from common import CONFIG, assert_filename, csaf_filename, provider_template, read_json, timestamp, write_csaf, write_json


def document_id(doc):
    tracking = doc['document']['tracking']
    identifier = tracking['id']
    csaf_filename(identifier)
    timestamp(tracking['initial_release_date'])
    timestamp(tracking['current_release_date'])
    return identifier


def collect(advisories, vex=None, archives=None):
    docs = {}
    for path in sorted(Path(advisories).glob('*.json')):
        doc = read_json(path)
        assert_filename(doc, path)
        docs[document_id(doc)] = doc
    source_ids = set(docs)

    def add_vex(doc, path):
        if doc.get('document', {}).get('category') != 'csaf_vex':
            return
        assert_filename(doc, path)
        identifier = document_id(doc)
        if identifier in source_ids:
            return  # The repository is authoritative for revisions.
        if identifier in docs and docs[identifier] != doc:
            raise ValueError(f'Conflicting archived VEX documents: {identifier}')
        docs[identifier] = doc
    if archives:
        import json
        for path in sorted(Path(archives).glob('*.tgz')):
            with tarfile.open(path, 'r:gz') as archive:
                for member in archive:
                    if not member.name.endswith('.json'):
                        continue
                    if not member.isfile() or member.size > 20 * 1024 * 1024:
                        raise ValueError(f'Unsafe JSON archive member: {path}: {member.name}')
                    # Parse in memory: never extract an archive-controlled filesystem path.
                    with archive.extractfile(member) as stream:
                        add_vex(json.load(stream), member.name)
    if vex:
        for path in sorted(Path(vex).glob('*.json')):
            add_vex(read_json(path), path)
    return docs


def listing(directory, names):
    links = '\n'.join(f'<li><a href="{html.escape(name, quote=True)}">{html.escape(name)}</a></li>'
                      for name in sorted(names))
    (directory / 'index.html').write_text('<!doctype html>\n<html lang="en"><meta charset="utf-8">'
                                          '<title>containd CSAF directory</title>'
                                          f'<h1>containd CSAF directory</h1><ul>{links}</ul></html>\n', encoding='utf-8')


def build(docs, output):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError(f'Refusing non-empty site output: {output}')
    if not docs:
        raise ValueError('Cannot date provider metadata without any documents')
    directory = output / '.well-known/csaf'
    directory.mkdir(parents=True)
    rows, years = [], set()
    for identifier, doc in sorted(docs.items()):
        if document_id(doc) != identifier:
            raise ValueError('Document id does not match collection key')
        tracking = doc['document']['tracking']
        year = str(timestamp(tracking['initial_release_date']).year)
        years.add(year)
        folder = directory / year
        folder.mkdir(exist_ok=True)
        relative = f'{year}/{csaf_filename(identifier)}'
        if any(row[0] == relative for row in rows):
            raise ValueError(f'Normalized filename collision: {relative}')
        path = directory / relative
        write_csaf(path, doc)
        for algorithm in ('sha256', 'sha512'):
            digest = hashlib.new(algorithm, path.read_bytes()).hexdigest()
            path.with_suffix('.json.' + algorithm).write_text(f'{digest}  {path.name}\n', encoding='utf-8')
        rows.append((relative, tracking['current_release_date']))
    metadata = provider_template()
    metadata['last_updated'] = max((date for _, date in rows), key=timestamp)
    write_json(directory / 'provider-metadata.json', metadata)
    (directory / 'index.txt').write_text(''.join(path + '\n' for path, _ in sorted(rows)), encoding='utf-8')
    changes = io.StringIO(newline='')
    writer = csv.writer(changes, quoting=csv.QUOTE_ALL, lineterminator='\n')
    writer.writerows(sorted(rows, key=lambda row: (timestamp(row[1]), row[0]), reverse=True))
    (directory / 'changes.csv').write_text(changes.getvalue(), encoding='utf-8')
    for year in sorted(years):
        listing(directory / year, [path.name for path in (directory / year).iterdir()])
    listing(directory, ['provider-metadata.json', 'index.txt', 'changes.csv', *(year + '/' for year in years)])
    listing(output, ['.well-known/csaf/'])
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--advisories', type=Path, default=CONFIG / 'advisories')
    parser.add_argument('--vex', type=Path)
    parser.add_argument('--archives', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(build(collect(args.advisories, args.vex, args.archives), args.output))


if __name__ == '__main__':
    main()
