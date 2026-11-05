# SPDX-License-Identifier: Apache-2.0
"""Require a fixed-version advisory for the current release's Security changelog."""
import argparse
import re
from pathlib import Path
from common import CONFIG, ROOT, read_json, version_key


def products(tree):
    """Collect CSAF full product names, carrying their product_version branch."""
    result = {}

    def visit(node, version=None):
        if isinstance(node, list):
            for child in node:
                visit(child, version)
        elif isinstance(node, dict):
            if node.get('category') == 'product_version':
                version = node['name']
            if 'product_id' in node:
                result[node['product_id']] = version
            for value in node.values():
                if isinstance(value, (dict, list)):
                    visit(value, version)
    visit(tree)
    return result


def check(version, changelog, advisories):
    version_key(version)
    match = re.search(r'^## \[' + re.escape(version) + r'\][^\n]*\n(.*?)(?=^## \[|\Z)', changelog, re.M | re.S)
    if not match:
        raise ValueError(f'Missing CHANGELOG section for VERSION {version}')
    if not re.search(r'^### Security\s*$', match[1], re.M):
        return f'{version}: no Security section; no advisory required.'
    for advisory in advisories:
        if advisory['document']['category'] != 'csaf_security_advisory':
            continue
        versions = products(advisory.get('product_tree', {}))
        for vulnerability in advisory.get('vulnerabilities', []):
            if any(versions.get(pid) == version for pid in vulnerability.get('product_status', {}).get('fixed', [])):
                return f'{version}: fixed advisory {advisory["document"]["tracking"]["id"]}.'
    raise ValueError(f'An advisory is required: CHANGELOG {version} has ### Security, but no advisory '
                     f'under security/csaf/advisories marks product_version {version} fixed. '
                     'For hardening rather than a vulnerability fix, move the entry to Changed/Fixed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version-file', type=Path, default=ROOT / 'VERSION')
    parser.add_argument('--changelog', type=Path, default=ROOT / 'CHANGELOG.md')
    parser.add_argument('--advisories', type=Path, default=CONFIG / 'advisories')
    args = parser.parse_args()
    try:
        print(check(args.version_file.read_text().strip(), args.changelog.read_text(),
                    [read_json(p) for p in sorted(args.advisories.glob('*.json'))]))
    except ValueError as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
