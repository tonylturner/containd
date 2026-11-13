# SPDX-License-Identifier: Apache-2.0
"""Fail-fast real-image upgrade matrix. All persistent evidence is private."""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

from fixture import (MATRIX, assert_config, assert_mode_audit, assert_protection, assert_revision,
                     assert_source_config, has_cas, patch, qualify_source_result, schema_authority, seed, source_address_defect,
                     source_binding_defect, supported_floor)

ROOT = Path(__file__).resolve().parents[2]


class UnsupportedSource(Exception):
    """A reproduced defect in the published writer, not in the candidate."""
    fixed_in = '0.1.33'
    defect = 'static host addresses converted to network addresses during commit'

    def __init__(self, defect, fixed_in='0.1.33'):
        super().__init__(defect)
        self.defect, self.fixed_in = defect, fixed_in


def command(*args):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=600)
    if result.returncode:
        raise RuntimeError(f'{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}')
    return result.stdout


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def resources(project):
    label = f'label=com.docker.compose.project={project}'
    return {kind: command('docker', *args, '--filter', label).split() for kind, args in (
        ('containers', ['ps', '-aq']), ('networks', ['network', 'ls', '-q']),
        ('volumes', ['volume', 'ls', '-q']))}


def free_subnets():
    ids = command('docker', 'network', 'ls', '-q').split()
    existing = json.loads(command('docker', 'network', 'inspect', *ids)) if ids else []
    used = [ipaddress.ip_network(c['Subnet']) for n in existing
            for c in (n.get('IPAM', {}).get('Config') or []) if c.get('Subnet')]
    for _ in range(200):
        third = secrets.randbelow(250)
        prefixes = [f'10.{n}.{third}' for n in (210, 211)]
        if all(not ipaddress.ip_network(p + '.0/24').overlaps(n)
               for p in prefixes for n in used if n.version == 4):
            return prefixes
    raise RuntimeError('no unused private subnet pair found')


class API:
    def __init__(self, base, context, cas):
        self.base, self.context, self.cas = base, context, cas
        self.token, self.revision = '', ''
        self.last_status = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))

    def call(self, path, data=None, expected=200, config_write=False):
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        if config_write and self.cas:
            assert self.revision, 'write without a real read base'
            headers['X-Containd-If-Revision'] = self.revision
        request = urllib.request.Request(self.base + path,
            data=None if data is None else json.dumps(data).encode(), headers=headers)
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read().decode()
            self.last_status = response.status
            allowed = expected if isinstance(expected, tuple) else (expected,)
            if response.status not in allowed:
                raise RuntimeError(f'{path}: HTTP {response.status}, expected {expected}: {body}')
            if 200 <= response.status < 300 and path.startswith('/config') and (data is None or config_write):
                revision = response.headers.get('X-Containd-Revision', '')
                if self.cas:
                    assert revision, f'{path} missing revision acknowledgement'
                self.revision = revision
            return json.loads(body) if body else None

    def login(self, username, password):
        result = self.call('/auth/login', {'username': username, 'password': password})
        self.token = result['token']
        return result

    def snapshot(self, bank):
        # Editable config reads intentionally omit IDS rules. Exports contain
        # the running bank; the IDS endpoint reads the candidate bank.
        if bank == 'running':
            return self.call('/config/export')
        assert bank == 'candidate', bank
        cfg = self.call('/config/candidate')
        cfg['ids'] = self.call('/ids/rules')
        return cfg


class Row:
    def __init__(self, run, version, profile, lan, wan):
        self.run, self.version, self.profile = run, version, profile
        self.lan, self.wan = lan, wan
        self.path = run.path / f'{version}-{profile}'
        self.path.mkdir()
        self.data = self.path / 'data'
        self.data.mkdir()
        self.compose_file = self.path / 'compose.json'
        self.checks = []
        self.api = None
        self.phase = 'source'
        self.passwords = {u: 'UpgradeAa1-' + secrets.token_hex(16) for u in ('containd', 'upgrade-admin', 'upgrade-view')}
        save(self.path / 'credentials.json', self.passwords)

    def compose(self, *args):
        return command('docker', 'compose', '-p', self.run.project,
                       '-f', str(self.compose_file), *args)

    def check(self, name):
        self.checks.append(name)
        save(self.path / 'checks.json', self.checks)
        print(f'PASS {self.version} {self.profile}: {name}', flush=True)

    def manifest(self, image, named):
        attachments = {n: {'ipv4_address': p + '.2'} for n, p in [('lan', self.lan), ('wan', self.wan)]}
        if named:
            for n, row in [('lan', 'lan1'), ('wan', 'wan')]:
                attachments[n]['interface_name'] = row
        env = {'CONTAIND_PROFILE': self.profile, 'CONTAIND_JWT_SECRET': self.run.secret,
               'CONTAIND_MGMT_ADDR': ':18080', 'CONTAIND_MGMT_HTTPS_ADDR': ':18443',
               'CONTAIND_ENGINE_URL': 'http://127.0.0.1:8081',
               'CONTAIND_SSH_HOST_KEY': '/data/ssh/host_key'}
        for db in ('CONFIG', 'AUDIT', 'USERS', 'TELEMETRY', 'EVIDENCE'):
            env[f'CONTAIND_{db}_DB'] = '/data/' + db.lower() + '.db'
        port = 18443 if self.profile == 'strict' else 18080
        doc = {'services': {
            'appliance': {'image': image, 'user': '0', 'cap_add': ['NET_ADMIN', 'NET_RAW'],
                'sysctls': {'net.ipv4.ip_forward': '1'}, 'environment': env,
                'ports': [f'127.0.0.1::{port}'], 'volumes': [f'{self.data}:/data'],
                'networks': attachments, 'command': ['all'], 'restart': 'no'},
            'client': {'image': self.run.endpoint, 'init': True, 'cap_add': ['NET_ADMIN'],
                       'networks': {'lan': {'ipv4_address': self.lan + '.3'}}},
            'origin': {'image': self.run.endpoint, 'init': True, 'cap_add': ['NET_ADMIN'],
                       'networks': {'wan': {'ipv4_address': self.wan + '.3'}}}},
            'networks': {n: {'ipam': {'config': [{'subnet': p + '.0/24'}]}}
                         for n, p in [('lan', self.lan), ('wan', self.wan)]}}
        save(self.compose_file, doc)
        self.compose('config', '-q')

    def cert(self):
        # Trusted Docker read, never trust-on-first-use over the network.
        for name in ('server.pem', 'server.crt'):
            path = self.data / 'tls' / name
            if path.exists():
                text = path.read_text()
                match = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.S)
                if match:
                    return match[0]
        return None

    def boot(self, image, candidate=False):
        self.manifest(image, candidate or patch(self.version) >= 41)
        self.compose('up', '-d', '--force-recreate', 'appliance', 'client', 'origin')
        port = 18443 if self.profile == 'strict' else 18080
        published = self.compose('port', 'appliance', str(port)).strip()
        assert published.startswith('127.0.0.1:') and int(published.rsplit(':', 1)[1]) not in (8080, 8443, 2222, 9080, 9443)
        scheme = 'https' if self.profile == 'strict' else 'http'
        last = ''
        for _ in range(90):
            try:
                context = None
                if scheme == 'https':
                    cert = self.cert()
                    if not cert:
                        time.sleep(1)
                        continue
                    context = ssl.create_default_context(cadata=cert)
                    context.check_hostname = False
                self.api = API(f'{scheme}://{published}/api/v1', context,
                               candidate or has_cas(self.version))
                health = self.api.call('/health')
                if patch(self.version) >= 39 or candidate:
                    assert health['profile'] == self.profile, health
                return
            except (OSError, RuntimeError, AssertionError) as error:
                last = str(error)
                time.sleep(1)
        raise RuntimeError('boot did not serve health: ' + last)

    def stop(self, name):
        (self.path / f'{name}.log').write_text(self.compose('logs', '--no-color'))
        self.compose('stop', '-t', '15', 'appliance')
        cid = self.compose('ps', '-aq', 'appliance').strip()
        assert json.loads(command('docker', 'inspect', cid))[0]['State']['Running'] is False

    def device_names(self):
        state = json.loads(self.compose('exec', '-T', 'appliance', 'ip', '-j', 'addr'))
        return {name: next(i['ifname'] for i in state if any(
            a.get('local') == prefix + '.2' for a in i.get('addr_info', [])))
            for name, prefix in [('lan1', self.lan), ('wan', self.wan)]}

    def routes(self):
        for service, dest, gateway in [('client', self.wan, self.lan), ('origin', self.lan, self.wan)]:
            self.compose('exec', '-T', service, 'ip', 'route', 'replace', dest + '.0/24', 'via', gateway + '.2')

    def traffic(self, phase):
        self.routes()
        # Verify both real listeners locally before judging a network denial.
        probe = '''import urllib.request
for port in (18081,18082):
 assert urllib.request.urlopen('http://127.0.0.1:'+str(port), timeout=3).read()==b'upgrade-origin\\n'
'''
        self.compose('exec', '-T', 'origin', 'python3', '-c', probe)
        marker = '/' + phase + '-' + secrets.token_hex(6)
        client = '''import socket,sys,urllib.request
host,marker=sys.argv[1:]
assert urllib.request.urlopen('http://'+host+':18081'+marker,timeout=4).read()==b'upgrade-origin\\n'
try:
 urllib.request.urlopen('http://'+host+':18082'+marker,timeout=2)
except (TimeoutError,urllib.error.URLError) as e:
 if isinstance(e,urllib.error.URLError):
  assert isinstance(e.reason,(TimeoutError,socket.timeout)),repr(e)
else:
 raise AssertionError('denied flow was delivered')
'''
        self.compose('exec', '-T', 'client', 'python3', '-c', client, self.wan + '.3', marker)
        requests = [json.loads(line) for line in self.compose('exec', '-T', 'origin', 'cat', '/tmp/requests.jsonl').splitlines()]
        save(self.path / f'traffic-{phase}.json', requests)
        assert [r['port'] for r in requests if r['path'] == marker] == [18081], requests
        self.check(phase + ' receiver-verified allow/deny with two live listeners')

    def protection(self, phase):
        status = {}
        for _ in range(60):
            # The API explicitly returns an unknown/not-ready aggregate with
            # HTTP 502 when engine collection is unavailable during startup.
            status = self.api.call('/dataplane/protection', expected=(200, 502))
            save(self.path / f'protection-{phase}.json', dict(status, httpStatus=self.api.last_status))
            try:
                assert self.api.last_status == 200, status
                revision = assert_protection(status)
                self.check(phase + ' ready/protecting at one running generation')
                return revision
            except AssertionError:
                time.sleep(1)
        raise AssertionError(f'protection did not converge: {status}')

    def audit(self):
        records = self.api.call('/audit?limit=1000')
        return sorted((r for r in records if '.migrat' in r.get('action', '')),
                      key=lambda r: json.dumps(r, sort_keys=True))

    def snapshots(self):
        # Sole writer is stopped. Read-only SQLite inspection, never fixture repairs.
        with sqlite3.connect(f'file:{self.data}/config.db?mode=ro', uri=True) as db:
            rows = dict(db.execute("SELECT key,data FROM configs WHERE key IN ('running','candidate','previous')"))
            result = {}
            for key, raw in rows.items():
                doc = json.loads(raw)
                if doc.get('ids_bank'):
                    rules = json.loads(db.execute('SELECT data FROM ids_banks WHERE id=?', (doc['ids_bank'],)).fetchone()[0])
                    doc.setdefault('ids', {})['rules'] = rules
                result[key] = doc
            return result

    def execute(self):
        source = f'ghcr.io/tonylturner/containd:{self.version}'
        command('docker', 'pull', source)
        metadata = json.loads(command('docker', 'image', 'inspect', source))[0]
        save(self.path / 'source-image.json', {k: metadata[k] for k in ('Id', 'RepoDigests', 'Architecture')})
        self.boot(source)
        if self.profile == 'strict':
            logs = self.compose('logs', '--no-color', '--no-log-prefix', 'appliance')
            password = re.findall(r'CONTAIND ONE-TIME PASSWORD user=containd password=(\S+)', logs)[-1]
        else:
            password = 'containd'
        self.api.login('containd', password)
        self.api.call('/auth/me/password', {'currentPassword': password, 'newPassword': self.passwords['containd']})
        self.api.login('containd', self.passwords['containd'])
        accounts = {}
        for username, role in [('upgrade-admin', 'admin'), ('upgrade-view', 'view')]:
            accounts[username] = self.api.call('/users', {'username': username, 'password': self.passwords[username],
                'role': role, 'firstName': 'Upgrade', 'lastName': 'Sentinel', 'email': username + '@example.invalid'})
        save(self.path / 'source-accounts.json', accounts)
        self.api.login('upgrade-admin', self.passwords['upgrade-admin'])
        devices = self.device_names()
        if patch(self.version) < 41:
            assert all(n.startswith('eth') for n in devices.values()), devices
        self.check('genuine historical device attachment and non-default account login')
        base = self.api.call('/config/candidate')
        for bank in ('previous', 'running', 'candidate'):
            cfg = seed(base, self.version, devices, self.lan, self.wan, bank)
            save(self.path / f'seed-{bank}.json', cfg)
            self.api.call('/config/candidate', cfg, config_write=True)
            if bank != 'candidate':
                try:
                    self.api.call('/config/commit', {}, config_write=True)
                except TimeoutError as error:
                    addresses = json.loads(self.compose('exec', '-T', 'appliance', 'ip', '-j', 'addr'))
                    save(self.path / 'source-failure-addresses.json', addresses)
                    if source_address_defect(self.version, addresses, self.lan, self.wan):
                        raise UnsupportedSource(UnsupportedSource.defect) from error
                    raise
                except RuntimeError as error:
                    if self.api.last_status != 500:
                        raise
                    logs = self.compose('logs', '--no-color', 'appliance')
                    if source_binding_defect(self.version, logs, cfg['interfaces']):
                        raise UnsupportedSource(
                            'commit rebinds distinct explicit interfaces and fails with duplicate device binding',
                            fixed_in='0.1.35') from error
                    raise
        self.traffic('source')
        for bank in ('running', 'candidate'):
            snapshot = self.api.snapshot(bank)
            save(self.path / f'source-{bank}.json', snapshot)
            assert_source_config(snapshot, seed(base, self.version, devices, self.lan, self.wan, bank))
        self.check('source API retained the representative config and separate IDS banks')
        old_revision = self.api.revision
        self.stop('source')
        old_snapshots = self.snapshots()
        save(self.path / 'source-snapshots.json', old_snapshots)
        shutil.copytree(self.data, self.path / 'backup')
        key = self.data / 'ssh/host_key'
        old_key = hashlib.sha256(key.read_bytes()).hexdigest()
        old_cert = self.cert()
        self.check('clean stopped full-data backup and previous/running/candidate snapshots')
        self.phase = 'candidate'
        self.boot(self.run.image, candidate=True)
        assert self.device_names() == {'lan1': 'lan1', 'wan': 'wan'}
        self.api.login('upgrade-admin', self.passwords['upgrade-admin'])
        for bank in ('running', 'candidate'):
            cfg = self.api.snapshot(bank)
            save(self.path / f'upgraded-{bank}.json', cfg)
            assert_config(cfg, self.run.schema, bank, self.lan, self.wan)
        assert_revision(old_revision, self.api.revision)
        revision = self.api.revision
        if old_cert:
            assert ssl.PEM_cert_to_DER_cert(old_cert) == ssl.PEM_cert_to_DER_cert(self.cert())
        assert hashlib.sha256(key.read_bytes()).hexdigest() == old_key
        self.check('schema authority, distinct snapshots/banks, CAS epoch, TLS and SSH identity retained')
        users = self.api.call('/users')
        for username, old in accounts.items():
            new = next(u for u in users if u['username'] == username)
            for field in ('id', 'role', 'firstName', 'lastName', 'email', 'mustChangePassword', 'mfaEnabled', 'mfaRequired'):
                assert new.get(field) == old.get(field), (field, old, new)
            self.api.login(username, self.passwords[username])
        self.api.call('/users', expected=403)
        before_denial = self.api.revision
        self.api.call('/config/candidate', json.loads((self.path / 'upgraded-candidate.json').read_text()),
                      expected=403, config_write=True)
        assert self.api.revision == before_denial
        self.api.login('upgrade-admin', self.passwords['upgrade-admin'])
        self.check('account IDs/roles/profile/MFA flags and credential logins retained; view denied config mutation')
        generation = self.protection('upgraded')
        self.traffic('upgraded')
        audit = self.audit()
        save(self.path / 'migration-audit.json', audit)
        if patch(self.version) < 36:
            assert_mode_audit(audit)
        self.stop('upgraded')
        upgraded_snapshots = self.snapshots()
        # Retain the stopped previous snapshot for inspection. Older releases
        # have different IDS inheritance semantics; only assert its hostname here.
        previous = upgraded_snapshots['previous']
        assert previous['system']['hostname'] == 'upgrade-previous'
        save(self.path / 'upgraded-snapshots.json', upgraded_snapshots)
        self.boot(self.run.image, candidate=True)
        self.api.login('upgrade-admin', self.passwords['upgrade-admin'])
        running = self.api.snapshot('running')
        candidate = self.api.snapshot('candidate')
        assert running == json.loads((self.path / 'upgraded-running.json').read_text())
        assert candidate == json.loads((self.path / 'upgraded-candidate.json').read_text())
        assert self.api.revision == revision
        assert self.audit() == audit
        assert self.protection('restart') == generation
        self.traffic('restart')
        self.check('second boot preserves CAS/generation/config/banks and migration audit AddOnce')
        # All candidate writes chain real acknowledgements, including the final edit/commit.
        edit = copy.deepcopy(candidate)
        edit['description'] = 'upgrade post-boot edit'
        self.api.call('/config/candidate', edit, config_write=True)
        assert self.api.revision != revision
        self.api.call('/config/commit', {}, config_write=True)
        assert self.protection('commit') != generation
        self.traffic('commit')
        self.stop('completed')
        self.check('new candidate write/commit chains CAS and creates a new protecting generation')


class Run:
    def __init__(self):
        self.project = os.environ['COMPOSE_PROJECT_NAME']
        if not re.fullmatch(r'upgrade-[a-z0-9-]+', self.project):
            raise ValueError('COMPOSE_PROJECT_NAME must be upgrade-<unique-lowercase-id>')
        if any(resources(self.project).values()):
            raise RuntimeError('refusing pre-existing project resources')
        self.path = Path(os.environ['UPGRADE_RESULTS']).resolve()
        self.path.mkdir(parents=True, exist_ok=False)
        self.image = os.environ['UPGRADE_IMAGE']
        self.endpoint = f'containd/upgrade-endpoint:{self.project}'
        self.secret = secrets.token_hex(32)
        self.schema = schema_authority(ROOT)
        self.current = None
        self.results = []
        image = json.loads(command('docker', 'image', 'inspect', self.image))[0]
        self.commit = image['Config'].get('Labels', {}).get('org.opencontainers.image.revision')
        assert self.commit and self.commit != 'unknown', 'build candidate with --build-arg COMMIT=$(git rev-parse HEAD)'
        save(self.path / 'candidate.json', {'version': (ROOT / 'VERSION').read_text().strip(),
            'commit': self.commit, 'image': self.image, 'imageId': image['Id'],
            'schema': self.schema, 'project': self.project})
        (self.path / 'jwt-secret').write_text(self.secret)

    def cleanup(self):
        if self.current and self.current.compose_file.exists():
            logs = self.current.compose('logs', '--no-color')
            (self.current.path / 'final.log').write_text(logs)
            self.current.compose('down', '--volumes', '--remove-orphans', '--timeout', '15')
        remaining = resources(self.project)
        save(self.path / 'remaining-resources.json', remaining)
        assert not any(remaining.values()), remaining
        self.current = None

    def execute(self, rows):
        command('docker', 'build', '-t', self.endpoint, str(ROOT / 'test/upgrade'))
        lan, wan = free_subnets()
        try:
            for version, profile in rows:
                self.current = Row(self, version, profile, lan, wan)
                started = time.monotonic()
                result = {'from': version, 'profile': profile, 'candidateImage': self.image,
                          'candidateCommit': self.commit, 'result': 'FAIL'}
                try:
                    self.current.execute()
                    result['result'] = 'PASS'
                    result = qualify_source_result(result)
                    if result['result'] == 'UNSUPPORTED':
                        print(f'UNSUPPORTED {version} {profile}: attempt passed but source has a '
                              f'proven defect; fixed in {result["fixedIn"]}', flush=True)
                except UnsupportedSource as error:
                    result.update(result='UNSUPPORTED', defect=error.defect, fixedIn=error.fixed_in)
                    print(f'UNSUPPORTED {version} {profile}: {error.defect}; fixed in {error.fixed_in}', flush=True)
                except Exception as error:
                    result['error'] = str(error)
                    result['phase'] = self.current.phase
                    raise
                finally:
                    result['assertions'] = len(self.current.checks)
                    try:
                        self.cleanup()
                    finally:
                        result['seconds'] = round(time.monotonic() - started, 2)
                        self.results.append(result)
                        save(self.path / 'matrix.json', self.results)
            save(self.path / 'support.json', {'floor': supported_floor(self.results)})
        finally:
            self.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--from-version', choices=sorted({v for v, _ in MATRIX}),
                        help='focused diagnostic only; omit for release validation')
    parser.add_argument('--profile', choices=('training', 'strict'), help='focused diagnostic only')
    parser.add_argument('--start-version', choices=sorted({v for v, _ in MATRIX}),
                        help='resume validation at this source release; earlier rows remain unexecuted')
    args = parser.parse_args()
    rows = [(v, p) for v, p in MATRIX if (not args.from_version or args.from_version == v)
            and (not args.start_version or patch(v) >= patch(args.start_version))
            and (not args.profile or args.profile == p)]
    if not rows:
        parser.error('no declared rows match')
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    run = Run()
    print(f'Upgrade evidence (contains secrets): {run.path}', flush=True)
    run.execute(rows)
    print(json.dumps(run.results, indent=2))


if __name__ == '__main__':
    main()
