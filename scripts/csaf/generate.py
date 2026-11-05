# SPDX-License-Identifier: Apache-2.0
"""Build deterministic, digest-bound CSAF VEX from complete per-platform Trivy scans."""
import argparse
import re
from pathlib import Path
from urllib.parse import quote
from common import (CONFIG, PRODUCTS, includes, load_triage, provider_template,
                    csaf_filename, read_json, timestamp, version_key, write_csaf)

ARCHES = ('amd64', 'arm64')


def release_images(path, version):
    entries = {}
    for line in Path(path).read_text().splitlines():
        key, value = line.split('=', 1)
        if key in entries:
            raise ValueError(f'Duplicate image manifest key: {key}')
        entries[key] = value
    if set(entries) != {'mgmt_image', 'mgmt_digest', 'engine_image', 'engine_digest'}:
        raise ValueError('Incomplete release-images.txt')
    images = {}
    for prefix, product in zip(('mgmt', 'engine'), PRODUCTS):
        image, digest = entries[f'{prefix}_image'], entries[f'{prefix}_digest']
        if not image.endswith(':' + version) or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            raise ValueError(f'Invalid release image: {image}@{digest}')
        repository = image.rsplit(':', 1)[0]
        if repository.rsplit('/', 1)[-1] != product:
            raise ValueError(f'Image does not name {product}')
        images[product] = (repository, digest)
    return images


def product_id(product, version, arch=None):
    return f'{product}-{version}' + (f'-{arch}' if arch else '')


def generate(version, images_path, scans_dir, statements, created):
    version_key(version)
    timestamp(created)
    images = release_images(images_path, version)
    branches, findings = [], {}
    for product, (repository, digest) in images.items():
        versions = []
        for arch in (None, *ARCHES):
            pid = product_id(product, version, arch)
            purl = f'pkg:oci/{product}@{digest}?'
            if arch:
                purl += f'arch={arch}&'
            purl += 'repository_url=' + quote(repository, safe='')
            versions.append({'category': 'product_version', 'name': version + (f' linux/{arch}' if arch else ''),
                             'product': {'product_id': pid, 'name': f'{product} {version}' + (f' linux/{arch}' if arch else ''),
                                         'product_identification_helper': {'purl': purl}}})
        branches.append({'category': 'product_name', 'name': product, 'branches': versions})
        for arch in ARCHES:
            scan = read_json(Path(scans_dir) / f'trivy-{product}-{arch}.json')
            reference = f'{repository}@{digest}'
            if (scan.get('ArtifactType') != 'container_image' or scan.get('ArtifactName') != reference or
                    reference not in scan.get('Metadata', {}).get('RepoDigests', []) or
                    scan['Metadata'].get('ImageConfig', {}).get('architecture') != arch or
                    not isinstance(scan.get('Results'), list)):
                raise ValueError(f'Scan identity/platform mismatch: {product} {arch}')
            for result in scan['Results']:
                for v in result.get('Vulnerabilities', []):
                    identifier = v['VulnerabilityID']
                    if not identifier or not v.get('PkgIdentifier', {}).get('PURL', '').startswith('pkg:'):
                        raise ValueError('Scan finding lacks identifier or package purl')
                    entry = findings.setdefault(identifier, {})
                    entry.setdefault(product, set()).add(arch)
    active = [s for s in statements if includes(s, version)]
    for s in active:
        for product in s['products']:
            findings.setdefault(s['cve'], {}).setdefault(product, set()).update(ARCHES)
    if not findings:
        return None, 'No scan findings or applicable triage statements; no VEX document generated.\n'
    vulnerabilities, summary = [], ['## Release vulnerability status', '']
    for identifier, products in sorted(findings.items()):
        vuln = {'notes': [{'category': 'description', 'text': f'{identifier}: vendor triage and release image scan findings.'}],
                'product_status': {}}
        if re.fullmatch(r'CVE-\d{4}-\d{4,}', identifier):
            vuln['cve'] = identifier
        else:
            vuln['ids'] = [{'system_name': 'Trivy', 'text': identifier}]
        for product, arches in sorted(products.items()):
            s = next((s for s in active if s['cve'] == identifier and product in s['products']), None)
            status = s['status'] if s else 'under_investigation'
            ids = [product_id(product, version, arch) for arch in sorted(arches)]
            # A status for an index applies to all its supported platforms only.
            if arches == set(ARCHES):
                ids.insert(0, product_id(product, version))
            vuln['product_status'].setdefault(status, []).extend(ids)
            if s:
                vuln['notes'].append({'category': 'general', 'text': f'{product}: {s["details"]}'})
                if s.get('flag'):
                    vuln.setdefault('flags', []).append({'label': s['flag'], 'product_ids': ids})
                if s.get('threat'):
                    vuln.setdefault('threats', []).append({'category': 'impact', 'details': s['threat'], 'product_ids': ids})
                if s.get('remediation'):
                    vuln.setdefault('remediations', []).append(dict(s['remediation'], product_ids=ids))
            if status in {'under_investigation', 'known_affected'}:
                summary.append(f'- {identifier}: {product} {version} ({", ".join(sorted(arches))}) — {status}')
        vulnerabilities.append(vuln)
    template = provider_template()
    doc = {'document': {'category': 'csaf_vex', 'csaf_version': '2.0',
                        'publisher': template['publisher'], 'title': f'containd {version} release VEX',
                        'tracking': {'id': f'containd-vex-{version}', 'status': 'final', 'version': '1',
                                     'initial_release_date': created, 'current_release_date': created,
                                     'revision_history': [{'number': '1', 'date': created, 'summary': 'Initial release VEX'}]}},
           'product_tree': {'branches': branches}, 'vulnerabilities': vulnerabilities}
    return doc, '\n'.join(summary) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--images', required=True)
    parser.add_argument('--scans', required=True)
    parser.add_argument('--triage', default=CONFIG / 'triage.json')
    parser.add_argument('--created', required=True, help='Release commit timestamp, never the wall clock')
    parser.add_argument('--output', required=True, type=Path, help='Output directory')
    parser.add_argument('--summary', type=Path)
    args = parser.parse_args()
    doc, summary = generate(args.version, args.images, args.scans, load_triage(args.triage), args.created)
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output / csaf_filename(f'containd-vex-{args.version}')
    if output.exists():
        raise ValueError(f'Refusing stale output: {output}; use a fresh output directory')
    if doc:
        write_csaf(output, doc)
    print(summary, end='')
    if args.summary:
        with args.summary.open('a', encoding='utf-8') as stream:
            stream.write(summary)


if __name__ == '__main__':
    main()
