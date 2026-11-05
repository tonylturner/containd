# SPDX-License-Identifier: Apache-2.0
"""Render a Trivy YAML ignorefile from justified, release-scoped vendor triage."""
import argparse
from common import CONFIG, PRODUCTS, includes, load_triage, statement_id, version_key, write_json


def ignorefile(statements, product, version):
    version_key(version)
    if product not in PRODUCTS:
        raise ValueError(f'Unknown product: {product}')
    # JSON is YAML 1.2. Do not suppress unresolved or purportedly fixed findings.
    return {'vulnerabilities': [
        {'id': statement_id(s), 'statement': s['details']}
        for s in sorted(statements, key=statement_id)
        if product in s['products'] and includes(s, version) and s['status'] == 'known_not_affected'
    ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--triage', default=CONFIG / 'triage.json')
    parser.add_argument('--product', choices=PRODUCTS, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', required=True, help='Must end in .yaml for Trivy')
    args = parser.parse_args()
    if not args.output.endswith('.yaml'):
        parser.error('Trivy YAML ignorefile output must end in .yaml')
    write_json(args.output, ignorefile(load_triage(args.triage), args.product, args.version))


if __name__ == '__main__':
    main()
