# SPDX-License-Identifier: Apache-2.0
"""Shared release identities and the vendor triage contract (stdlib only)."""
import json
import re
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / 'security/csaf'
PRODUCTS = ('containd', 'containd-engine')
STATUSES = {'known_not_affected', 'known_affected', 'fixed', 'under_investigation'}
FLAGS = {'component_not_present', 'vulnerable_code_not_present',
         'vulnerable_code_not_in_execute_path',
         'vulnerable_code_cannot_be_controlled_by_adversary',
         'inline_mitigations_already_exist'}


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def csaf_filename(identifier):
    nonempty(identifier, 'tracking.id')
    return re.sub(r'[^+\-a-z0-9]+', '_', identifier.lower()) + '.json'


def assert_filename(doc, path):
    expected = csaf_filename(doc['document']['tracking']['id'])
    if Path(path).name != expected:
        raise ValueError(f'CSAF filename must be {expected}, got {Path(path).name}')


def write_csaf(path, doc):
    assert_filename(doc, path)
    write_json(path, doc)


def timestamp(value):
    date = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if date.tzinfo is None:
        raise ValueError('A release timestamp must include its timezone')
    return date


def version_key(value):
    """SemVer precedence, excluding build metadata (not used in container tags)."""
    n = r'(0|[1-9][0-9]*)'
    match = re.fullmatch(rf'{n}\.{n}\.{n}(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?', value)
    if not match:
        raise ValueError(f'Invalid release version: {value}')
    major, minor, patch, pre = match.groups()
    parts = []
    for part in pre.split('.') if pre else []:
        if part.isdigit() and len(part) > 1 and part.startswith('0'):
            raise ValueError(f'Invalid prerelease: {value}')
        parts.append((0, int(part)) if part.isdigit() else (1, part))
    return (int(major), int(minor), int(patch), not bool(pre), tuple(parts))


def includes(statement, version):
    bounds = statement['version_range']
    key = version_key(version)
    return (version_key(bounds['introduced']) <= key and
            ('before' not in bounds or key < version_key(bounds['before'])))


def nonempty(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{name} must be non-empty text')


def statement_id(statement):
    """One exact scanner identity per statement; non-CVEs retain their issuing system."""
    return statement['cve'] if 'cve' in statement else statement['ids'][0]['text']


def load_triage(path):
    data = read_json(path)
    if set(data) != {'schema_version', 'statements'} or data['schema_version'] != 1:
        raise ValueError('Expected triage schema_version 1 and statements')
    statements = data['statements']
    if not isinstance(statements, list):
        raise ValueError('statements must be a list')
    for s in statements:
        required = {'products', 'version_range', 'status', 'details', 'when'}
        if not required <= set(s) or set(s) - required - {'cve', 'ids', 'flag', 'threat', 'remediations'}:
            raise ValueError(f'Invalid triage fields: {s}')
        if ('cve' in s) == ('ids' in s):
            raise ValueError('Triage requires either cve or a single non-CVE ids entry')
        if 'cve' in s:
            if not isinstance(s['cve'], str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', s['cve']):
                raise ValueError('Triage cve must be a CVE identifier')
        else:
            ids = s['ids']
            if (not isinstance(ids, list) or len(ids) != 1 or not isinstance(ids[0], dict) or
                    set(ids[0]) != {'system_name', 'text'}):
                raise ValueError('Triage ids requires one system_name/text object')
            nonempty(ids[0]['system_name'], 'ids.system_name')
            nonempty(ids[0]['text'], 'ids.text')
            if ids[0]['text'].startswith('CVE-'):
                raise ValueError('Use cve for CVE identifiers')
        if s['when'] not in {'scan', 'always'}:
            raise ValueError('when must be scan (per-platform scan hit) or always (unconditional)')
        if (not isinstance(s['products'], list) or not s['products'] or
                len(set(s['products'])) != len(s['products']) or
                set(s['products']) - set(PRODUCTS)):
            raise ValueError('Unknown or duplicate triage products')
        bounds = s['version_range']
        if not isinstance(bounds, dict) or 'introduced' not in bounds or set(bounds) - {'introduced', 'before'}:
            raise ValueError('version_range requires introduced and optional exclusive before')
        start = version_key(bounds['introduced'])
        if 'before' in bounds and version_key(bounds['before']) <= start:
            raise ValueError('Empty version range')
        if s['status'] not in STATUSES:
            raise ValueError('Unknown triage status')
        nonempty(s['details'], 'details')
        if 'flag' in s and s['flag'] not in FLAGS:
            raise ValueError('Unknown CSAF flag')
        if 'threat' in s:
            nonempty(s['threat'], 'threat')
        if s['status'] == 'known_not_affected' and not (s.get('flag') or s.get('threat')):
            raise ValueError('known_not_affected requires a flag or impact threat justification')
        remediations = s.get('remediations', [])
        if not isinstance(remediations, list) or ('remediations' in s and not remediations):
            raise ValueError('remediations must be a nonempty list when supplied')
        for r in remediations:
            if (not isinstance(r, dict) or set(r) - {'category', 'details', 'url'} or
                    not {'category', 'details'} <= set(r)):
                raise ValueError('Invalid remediation fields')
            if r['category'] not in {'vendor_fix', 'workaround', 'mitigation', 'none_available', 'no_fix_planned'}:
                raise ValueError('Invalid remediation category')
            nonempty(r['details'], 'remediation.details')
            if 'url' in r and not r['url'].startswith('https://'):
                raise ValueError('Remediation URL must use HTTPS')
        if s['status'] == 'known_affected' and not remediations:
            raise ValueError('known_affected requires remediation')
    for i, left in enumerate(statements):
        for right in statements[i + 1:]:
            if statement_id(left) != statement_id(right) or not set(left['products']) & set(right['products']):
                continue
            a, b = left['version_range'], right['version_range']
            if not (('before' in a and version_key(a['before']) <= version_key(b['introduced'])) or
                    ('before' in b and version_key(b['before']) <= version_key(a['introduced']))):
                raise ValueError(f'Overlapping triage for {statement_id(left)}')
    return statements


def provider_template():
    data = read_json(CONFIG / 'templates/provider-metadata.json')
    return data
