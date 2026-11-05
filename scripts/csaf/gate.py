# SPDX-License-Identifier: Apache-2.0
"""Warn when the current release's Security changelog lacks a fixed-version advisory."""
import argparse
import os
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
    fixed = {}
    for advisory in advisories:
        try:
            category = advisory['document']['category']
            identifier = advisory['document']['tracking']['id']
            versions = products(advisory['product_tree'])
            vulnerabilities = advisory['vulnerabilities']
            if (not isinstance(category, str) or not category or
                    not isinstance(identifier, str) or not identifier or
                    not isinstance(vulnerabilities, list) or not vulnerabilities):
                raise ValueError('Invalid advisory category, tracking ID or vulnerabilities')
            for vulnerability in vulnerabilities:
                statuses = vulnerability['product_status']
                if not isinstance(statuses, dict) or not statuses:
                    raise ValueError('Invalid advisory product_status')
                for ids in statuses.values():
                    if (not isinstance(ids, list) or not ids or
                            any(not isinstance(pid, str) or pid not in versions for pid in ids)):
                        raise ValueError('Invalid advisory product reference')
                if category == 'csaf_security_advisory':
                    for pid in statuses.get('fixed', []):
                        fixed.setdefault(versions[pid], identifier)
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError(f'Malformed advisory input: {error}') from error
    match = re.search(r'^## \[' + re.escape(version) + r'\][^\n]*\n(.*?)(?=^## \[|\Z)', changelog, re.M | re.S)
    if not match:
        raise ValueError(f'Missing CHANGELOG section for VERSION {version}')
    if not re.search(r'^### Security\s*$', match[1], re.M):
        return f'{version}: no Security section; no advisory required.'
    if version in fixed:
        return f'{version}: fixed advisory {fixed[version]}.'
    return (f'::warning::CHANGELOG {version} has ### Security, but no advisory under '
            f'security/csaf/advisories marks product_version {version} fixed. '
            'Discuss advisory coverage with the maintainer; this warning does not block publication.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version-file', type=Path, default=ROOT / 'VERSION')
    parser.add_argument('--changelog', type=Path, default=ROOT / 'CHANGELOG.md')
    parser.add_argument('--advisories', type=Path, default=CONFIG / 'advisories')
    args = parser.parse_args()
    try:
        if not args.advisories.is_dir():
            raise ValueError(f'Missing advisories directory: {args.advisories}')
        message = check(args.version_file.read_text().strip(), args.changelog.read_text(),
                        [read_json(p) for p in sorted(args.advisories.glob('*.json'))])
        print(message)
        if summary := os.environ.get('GITHUB_STEP_SUMMARY'):
            with Path(summary).open('a', encoding='utf-8') as stream:
                stream.write('### Advisory coverage\n\n' + message.removeprefix('::warning::') + '\n')
    except ValueError as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
