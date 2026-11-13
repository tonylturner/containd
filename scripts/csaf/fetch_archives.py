# SPDX-License-Identifier: Apache-2.0
"""Download published releases' CSAF archives using the authenticated GitHub CLI."""
import argparse
import subprocess
from pathlib import Path
from common import read_json


def fetch(pages, repository, output):
    output.mkdir(parents=True, exist_ok=True)
    seen = set()
    for page in pages:
        for release in page:
            if release['draft'] or not release['published_at']:
                continue
            assets = [a for a in release['assets'] if a['name'] == 'csaf-documents.tgz']
            if not assets:
                print(f'{release["tag_name"]}: no csaf-documents.tgz asset')
                continue
            if len(assets) != 1:
                raise ValueError('Duplicate CSAF release assets')
            asset_id = assets[0]['id']
            if not isinstance(asset_id, int) or asset_id <= 0 or asset_id in seen:
                raise ValueError('Invalid or duplicate release asset id')
            seen.add(asset_id)
            path = output / f'{asset_id}.tgz'
            with path.open('xb') as stream:
                subprocess.run(['gh', 'api', f'repos/{repository}/releases/assets/{asset_id}',
                                '-H', 'Accept: application/octet-stream'], stdout=stream, check=True)
            print(f'{release["tag_name"]}: downloaded {path.name}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--releases', type=Path, required=True, help='gh api --paginate --slurp releases output')
    parser.add_argument('--repository', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fetch(read_json(args.releases), args.repository, args.output)


if __name__ == '__main__':
    main()
