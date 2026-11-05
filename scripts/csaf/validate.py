# SPDX-License-Identifier: Apache-2.0
"""Check filenames, then validate every supplied document with the pinned CSAF client."""
import argparse
import os
import subprocess
from pathlib import Path
from common import assert_filename, read_json


def documents(paths):
    files = set()
    for value in paths:
        path = Path(value)
        if path.is_dir():
            files.update(p for p in path.rglob('*.json') if p.name != 'provider-metadata.json')
        elif path.is_file():
            files.add(path)
        else:
            raise ValueError(f'Missing validation input: {path}')
    if not files:
        raise ValueError('No CSAF documents to validate')
    for path in sorted(files):
        assert_filename(read_json(path), path)
    return sorted(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args()
    result = subprocess.run([os.environ['CSAF_VALIDATOR_BIN'], '--validator', os.environ['CSAF_VALIDATOR_URL'],
                             '--validator_preset', 'basic', '--output', 'important',
                             *map(str, documents(args.paths))], check=False)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
