#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Destructive acceptance on disposable, project-owned volumes only. Never point
# STRICT_COMPOSE_OVERRIDE at live data. Requires modern Compose (!override), curl,
# jq, Python 3, OpenSSL and OpenSSH. Uses CONTAIND_IMAGE and a 32+ character JWT.
# COMPOSE_PROJECT_NAME owns all resources; STRICT_COMPOSE_OVERRIDE is optional.
# No image build is performed. Temporary evidence contains bootstrap secrets.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-containd-strict-$$}"
export CONTAIND_JWT_SECRET="${CONTAIND_JWT_SECRET:-$(openssl rand -hex 32)}"
[[ ${#CONTAIND_JWT_SECRET} -ge 32 ]] || { echo 'test JWT must be at least 32 characters' >&2; exit 1; }
scratch=$(mktemp -d)
base="$scratch/isolation.yml"
scenario="$scratch/scenario.yml"
cookie="$scratch/cookie"
revision="$scratch/revision"
api='' cid='' token='' case_name='' passed=0
# shellcheck source=scripts/config-revision.sh
# shellcheck disable=SC1091
source "$ROOT/scripts/config-revision.sh"
ssh-keygen -q -t ed25519 -N '' -f "$scratch/key"
export STRICT_TEST_KEY
STRICT_TEST_KEY=$(cat "$scratch/key.pub")
cat >"$base" <<'YAML'
services:
  containd:
    restart: "no"
    environment:
      CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY: ${STRICT_TEST_KEY}
    ports: !override
      - "127.0.0.1:0:8443"
      - "127.0.0.1:0:2222"
    volumes: !override
      - strict-data:/data
      - strict-av:/var/lib/clamav
    networks: !override
      - default
volumes:
  strict-data:
  strict-av:
YAML
compose() {
  local -a args=(-f "$ROOT/deploy/docker-compose.strict.yml" -f "$base")
  if [[ -n ${STRICT_COMPOSE_OVERRIDE:-} ]]; then args+=(-f "$STRICT_COMPOSE_OVERRIDE"); fi
  docker compose "${args[@]}" -f "$scenario" "$@"
}
fail() { echo "strict smoke ($case_name): $*" >&2; exit 1; }
cleanup() {
  local rc=$?
  if [[ $passed != 1 && -n $case_name ]]; then
    compose logs --no-color >&2 || true
    echo "strict smoke failed: $case_name" >&2
  fi
  if [[ -n $case_name ]]; then compose down -v --remove-orphans || rc=1; fi
  # Remove only this invocation's private scratch; do not use shell rm.
  python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1])' "$scratch"
  exit "$rc"
}
trap cleanup EXIT
# Refuse to take ownership of an existing project, including stopped resources.
existing=$(docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")
[[ -z $existing ]] || fail 'project already has containers'
existing=$(docker volume ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")
[[ -z $existing ]] || fail 'project already has volumes'
existing=$(docker network ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")
[[ -z $existing ]] || fail 'project already has networks'
new_case() {
  if [[ -n $case_name ]]; then compose down -v --remove-orphans; fi
  case_name=$1
  echo "strict smoke: $case_name"
  printf 'services:\n  containd: {}\n' >"$scenario"
  : >"$cookie"
  token='' api='' cid=''
}
container_id() { cid=$(compose ps -aq containd); [[ -n $cid ]] || fail 'missing container'; }
wait_healthy() {
  local status=''
  container_id
  for _ in $(seq 1 90); do
    status=$(docker inspect --format '{{.State.Status}}:{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$cid")
    [[ $status != exited:* ]] || fail 'exited while waiting for health'
    if [[ $status == running:healthy ]]; then
      api="https://$(compose port containd 8443)/api/v1"
      return
    fi
    sleep 2
  done
  fail "not healthy: $status"
}
start() { compose up -d containd; wait_healthy; }
logs() { compose logs --no-color --no-log-prefix containd; }
# All host API probes pin the served public key after a trusted Docker read.
# Re-pin explicitly only after a test intentionally replaces the identity.
pin() {
  compose exec -T containd cat /data/tls/server.pem | openssl x509 -out "$scratch/identity.pem"
  openssl x509 -in "$scratch/identity.pem" -pubkey -noout >"$scratch/pubkey.pem"
  openssl pkey -pubin -in "$scratch/pubkey.pem" -outform DER >"$scratch/pubkey.der"
  pin_value="sha256//$(openssl dgst -sha256 -binary "$scratch/pubkey.der" | openssl base64 -A)"
}
# -k disables CA/hostname checks for the disposable self-signed identity; the
# mandatory public-key pin supplies authentication on every host HTTPS request.
request() {
  curl -ksS --pinnedpubkey "$pin_value" --connect-timeout 5 --max-time 30 \
    -b "$cookie" -c "$cookie" "$@"
}
expect() {
  local status=$1 path=$2 actual
  shift 2
  actual=$(request -D "$scratch/headers" -o "$scratch/body" -w '%{http_code}' "$api/$path" "$@")
  [[ $actual == "$status" ]] || fail "$path: HTTP $actual, expected $status ($(cat "$scratch/body"))"
}
login() {
  local user=$1 password=$2 status=${3:-200}
  jq -n --arg u "$user" --arg p "$password" '{username:$u,password:$p}' >"$scratch/login.json"
  expect "$status" auth/login -H 'Content-Type: application/json' --data-binary @"$scratch/login.json"
  if [[ $status == 200 ]]; then token=$(jq -er '.token' "$scratch/body"); fi
}
password_from_log() {
  logs >"$scratch/current.log"
  awk -v user="${1:-containd}" '$1=="CONTAIND" && $2=="ONE-TIME" && $3=="PASSWORD" && $4=="user="user {sub(/^password=/,"",$5); p=$5} END {if(p=="") exit 1; print p}' "$scratch/current.log"
}
claim() {
  local old=$1
  login containd "$old"
  jq -e '.user.mustChangePassword == true' "$scratch/body" >/dev/null
  jq -n --arg old "$old" --arg new "$claimed" '{currentPassword:$old,newPassword:$new}' >"$scratch/change.json"
  expect 200 auth/me/password -H 'Content-Type: application/json' --data-binary @"$scratch/change.json"
  login containd "$claimed"
}
config_read() {
  cas_read "$revision" request -f "$api/config/candidate" >"$scratch/config.json"
}
config_write() {
  cas_write "$revision" request -f -H 'Content-Type: application/json' --data-binary @"$scratch/config.json" "$api/config" >"$scratch/result.json"
}
commit() {
  cas_write "$revision" request -f -X POST "$api/config/commit" >"$scratch/result.json"
}
# A helper mounts only this test container's volumes. Python's SQLite dump
# avoids the false negatives from grepping only a live database main file.
fixture() {
  docker run --rm -i --volumes-from "$cid" -v "$scratch:/smoke" python:3-alpine python3 -
}
assert_exit() {
  local expected=$1 status=''
  container_id
  for _ in $(seq 1 90); do
    status=$(docker inspect --format '{{.State.Status}}' "$cid")
    [[ $status == exited ]] && break
    sleep 1
  done
  [[ $status == exited ]] || fail "refusal did not exit: $status"
  [[ $(docker inspect --format '{{.State.ExitCode}}' "$cid") == 1 ]] || fail 'refusal exit code is not 1'
  logs >"$scratch/refusal.log"
  # Structured logs JSON-escape quotes inside the refusal message.
  sed 's/\\"/"/g' "$scratch/refusal.log" | grep -F -- "$expected" >/dev/null || fail "missing refusal: $expected"
}
claimed="Strict$(openssl rand -hex 12)Aa1"

new_case happy
start
[[ $(compose port containd 8443) == 127.0.0.1:* ]] || fail 'HTTPS not loopback'
[[ $(compose port containd 2222) == 127.0.0.1:* ]] || fail 'SSH not loopback'
compose config --format json >"$scratch/compose.json"
jq -e '[.services.containd.ports[].target] | sort == [2222,8443]' "$scratch/compose.json" >/dev/null
pin
expect 200 health
jq -e '.profile == "strict"' "$scratch/body" >/dev/null
grep -i '^Strict-Transport-Security:' "$scratch/headers" >/dev/null
logs >"$scratch/boot.log"
grep -F 'management TLS certificate sha256=' "$scratch/boot.log" >/dev/null
one_time=$(password_from_log)
# Expansion happens inside the container.
# shellcheck disable=SC2016
compose exec -T containd sh -c 'test "$(stat -c %a /data/bootstrap)" = 700 && test "$(stat -c %a /data/bootstrap/admin-password)" = 600'
compose exec -T containd cat /data/bootstrap/admin-password >"$scratch/password-file"
grep -Fx "containd $one_time" "$scratch/password-file" >/dev/null
login containd containd 401
login containd "$one_time"
jq -e '.user.mustChangePassword == true' "$scratch/body" >/dev/null
grep -i '^Set-Cookie:.*; Secure' "$scratch/headers" >/dev/null
expect 200 auth/me
jq -e '.profile == "strict" and .mustChangePassword == true' "$scratch/body" >/dev/null
expect 403 config -H 'Content-Type: application/json' -d '{}'
jq -e '.error == "password change required"' "$scratch/body" >/dev/null
# curl's connection-refused status is 7; a timeout is not proof of no listener.
http_rc=0
compose exec -T containd curl -sS --connect-timeout 2 http://127.0.0.1:8080/ >"$scratch/http" 2>&1 || http_rc=$?
[[ $http_rc == 7 ]] || fail "HTTP listener probe returned $http_rc"
claim "$one_time"
compose exec -T containd cat /data/bootstrap/admin-password >"$scratch/password-file"
! grep -q '^containd ' "$scratch/password-file" || fail 'claimed password entry remains'
fixture <<'PY'
import sqlite3
c=sqlite3.connect('/data/audit.db')
assert 'auth.bootstrap_password.issued' in '\n'.join(c.iterdump())
PY
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sleep 1
compose restart containd
wait_healthy
compose logs --since "$since" --no-color containd >"$scratch/restart.log"
! grep -q 'CONTAIND ONE-TIME PASSWORD' "$scratch/restart.log" || fail 'claimed account reissued'
expect 200 system/tls
tls_address=${api#https://}; tls_address=${tls_address%/api/v1}
openssl s_client -connect "$tls_address" -showcerts </dev/null >"$scratch/served.pem" 2>"$scratch/handshake.log"
fingerprint=$(openssl x509 -in "$scratch/served.pem" -noout -fingerprint -sha256)
fingerprint=${fingerprint#*=}
jq -e --arg fp "$fingerprint" '.servedCertFingerprintSHA256 == $fp and .certFingerprintSHA256 == $fp' "$scratch/body" >/dev/null
grep -F "management TLS certificate sha256=$fingerprint" "$scratch/boot.log" >/dev/null
printf 'show version\nexit\n' | compose exec -T -e CONTAIND_CLI_USER=containd -e "CONTAIND_CLI_PASSWORD=$claimed" containd containd cli >"$scratch/cli"
# Bootstrap public key belongs to the now-claimed admin; strict SSH internally
# uses pinned HTTPS. Trust only this disposable host key for the client probe.
ssh_port=$(compose port containd 2222); ssh_port=${ssh_port##*:}
ssh-keyscan -p "$ssh_port" 127.0.0.1 >"$scratch/known_hosts" 2>"$scratch/keyscan.log"
ssh -T -i "$scratch/key" -o IdentitiesOnly=yes -o BatchMode=yes -o "UserKnownHostsFile=$scratch/known_hosts" -o StrictHostKeyChecking=yes -p "$ssh_port" containd@127.0.0.1 show version >"$scratch/ssh"
[[ -s $scratch/cli && -s $scratch/ssh ]] || fail 'empty CLI output'

# Pure preflight cases retain a separate network/PID namespace so observations
# remain available after containd exits. Poll for transient AV/packet activity.
refusal() {
  local name=$1 variable=$2 value=$3 message=$4
  new_case "$name"
  cat >"$scenario" <<'YAML'
services:
  observer:
    image: ${CONTAIND_IMAGE:-ghcr.io/tonylturner/containd:latest}
    user: "0"
    cap_add: [NET_ADMIN]
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        set -eu
        trap 'exit 0' TERM INT
        # Docker's own netns state (embedded-DNS nat table, packet sockets)
        # exists before containd starts; only additions are containd's.
        nft list tables | sort -u > /tmp/tables.base
        awk 'NR > 1 { print $$9 }' /proc/net/packet | sort -u > /tmp/packets.base
        while :; do
          nft list tables >> /tmp/tables
          awk 'NR > 1 { print $$9 }' /proc/net/packet >> /tmp/packets
          ps -eo comm >> /tmp/processes
          touch /tmp/ready
          sleep 0.1
        done
    healthcheck:
      test: [CMD, test, -f, /tmp/ready]
      interval: 1s
      retries: 30
  containd:
    restart: "no"
    networks: !reset []
    network_mode: service:observer
    pid: service:observer
    ports: !reset []
    depends_on:
      observer:
        condition: service_healthy
YAML
  if [[ $name == socket ]]; then
    cat >>"$scenario" <<'YAML'
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
YAML
  else
    printf '    environment:\n      %s: %s\n' "$variable" "$(jq -Rn --arg v "$value" '$v')" >>"$scenario"
  fi
  compose up -d
  assert_exit "$message"
  compose exec -T observer sh -c 'test -f /tmp/tables && test -f /tmp/processes && test -f /tmp/packets && sort -u /tmp/tables | cmp -s - /tmp/tables.base && sort -u /tmp/packets | cmp -s - /tmp/packets.base && ! grep -Eq "clamd|freshclam|tcpdump" /tmp/processes' || fail 'refusal left netfilter, packet-socket or AV state'
  ! grep -Eq 'containd engine starting|data plane capture' "$scratch/refusal.log" || fail 'engine started before refusal'
  fixture <<'PY'
from pathlib import Path
assert not [p for p in Path('/data').rglob('*') if p.is_file()], 'preflight created persistent state'
PY
}
refusal lab CONTAIND_LAB_MODE 1 'CONTAIND_PROFILE=strict refuses CONTAIND_LAB_MODE=1: lab mode is training-only'
refusal short-secret CONTAIND_JWT_SECRET 12345678901234567890 'CONTAIND_PROFILE=strict refuses CONTAIND_JWT_SECRET: set a unique secret of at least 32 characters (openssl rand -hex 32)'
refusal static-token CONTAIND_ADMIN_TOKEN x 'CONTAIND_PROFILE=strict refuses CONTAIND_ADMIN_TOKEN/CONTAIND_AUDITOR_TOKEN: static bearer tokens are training-only'
refusal seed-password CONTAIND_DEFAULT_ADMIN_PASSWORD x 'CONTAIND_PROFILE=strict refuses CONTAIND_DEFAULT_ADMIN_PASSWORD: strict issues a one-time first-admin password'
refusal cookie CONTAIND_COOKIE_SECURE 0 'CONTAIND_PROFILE=strict refuses CONTAIND_COOKIE_SECURE="0": session cookies are always Secure'
refusal shell CONTAIND_SSH_SHELL_MODE linux 'CONTAIND_PROFILE=strict refuses CONTAIND_SSH_SHELL_MODE="linux": the Linux shell is training-only'
refusal socket '' '' 'CONTAIND_PROFILE=strict refuses a mounted Docker socket (/var/run/docker.sock)'
refusal reservation CONTAIND_MGMT_RESERVATION x 'CONTAIND_PROFILE=strict refuses CONTAIND_MGMT_RESERVATION: the reserved management path serves plain HTTP'

new_case missing-tls
cat >"$scenario" <<'YAML'
services:
  containd:
    restart: "no"
    environment:
      CONTAIND_TLS_CERT_FILE: /nonexistent
YAML
compose up -d containd
assert_exit 'CONTAIND_PROFILE=strict refuses to start without HTTPS:'
new_case users-db
cat >"$scenario" <<'YAML'
services:
  containd:
    restart: "no"
    environment:
      CONTAIND_USERS_DB: /unwritable/users.db
    tmpfs:
      - /unwritable:ro
YAML
compose up -d containd
assert_exit 'open users store:'

new_case saved-intent
start
pin
claim "$(password_from_log)"
compose stop containd
# Seed a migrated saved configuration while its sole management owner is stopped.
fixture <<'PY'
import json,sqlite3
c=sqlite3.connect('/data/config.db')
for key,raw in c.execute("SELECT key,data FROM configs WHERE key IN ('running','candidate')").fetchall():
    d=json.loads(raw)
    d.setdefault('system',{}).setdefault('ssh',{})['shellMode']='linux'
    d['system'].setdefault('mgmt',{}).update(enableHTTPS=False,enableHSTS=False,enableHTTP=True)
    c.execute('UPDATE configs SET data=? WHERE key=?',(json.dumps(d),key))
c.commit()
PY
compose start containd
wait_healthy
expect 200 system/tls
jq -e '.httpEnabled == false and .httpEnabledSource == "profile" and .httpEnabledSaved == true and .httpsEnabled == true and .httpsEnabledSource == "profile" and .httpsEnabledSaved == false and .hstsEnabled == true and .hstsEnabledSource == "profile" and .hstsEnabledSaved == false' "$scratch/body" >/dev/null
expect 200 cli/execute -H 'Content-Type: application/json' -d '{"line":"show system"}'
jq -er '.output' "$scratch/body" >"$scratch/show-system"
grep -F 'profile (strict)' "$scratch/show-system" >/dev/null
grep -F 'linux' "$scratch/show-system" >/dev/null
config_read
jq '.system.hostname="strict-smoke"' "$scratch/config.json" >"$scratch/edit.json"
mv "$scratch/edit.json" "$scratch/config.json"
config_write
commit
config_read
cp "$scratch/config.json" "$scratch/weak.json"
jq '.system.ssh.shellMode="appliance"' "$scratch/config.json" >"$scratch/edit.json"
mv "$scratch/edit.json" "$scratch/config.json"
config_write
commit
config_read
expect 400 config -H "X-Containd-If-Revision: $(cas_revision "$revision")" -H 'Content-Type: application/json' --data-binary @"$scratch/weak.json"
jq -e '.error | contains("the Linux shell is training-only")' "$scratch/body" >/dev/null
expect 400 config/import -H "X-Containd-If-Revision: $(cas_revision "$revision")" -H 'Content-Type: application/json' --data-binary @"$scratch/weak.json"
jq -e '.error | contains("the Linux shell is training-only")' "$scratch/body" >/dev/null
cas_write "$revision" request -f -X POST "$api/config/rollback" >"$scratch/result.json"
expect 200 config
jq -e '.system.ssh.shellMode == "linux"' "$scratch/body" >/dev/null

new_case unclaimed-recovery
start
pin
old=$(password_from_log)
compose stop containd
compose start containd
wait_healthy
fresh=$(password_from_log)
[[ $fresh != "$old" ]] || fail 'restart did not reissue'
login containd "$old" 401
login containd "$fresh"
compose exec -T containd sh -c 'mv /data/bootstrap/admin-password /data/bootstrap/retired-smoke'
compose up -d --force-recreate containd
wait_healthy
recreated=$(password_from_log)
[[ $recreated != "$fresh" ]] || fail 'recreate did not reissue'
login containd "$fresh" 401
login containd "$recreated"
compose exec -T containd cat /data/bootstrap/admin-password >"$scratch/password-file"
grep -Fx "containd $recreated" "$scratch/password-file" >/dev/null
claim "$recreated"
config_read
expect 200 system/factory-reset -H "X-Containd-If-Revision: $(cas_revision "$revision")" -H 'Content-Type: application/json' -d '{"confirm":"NUCLEAR"}'
jq -e '.loggedOut == true and (.message | contains("/data/bootstrap/admin-password"))' "$scratch/body" >/dev/null
reset_password=$(password_from_log)
[[ $reset_password != "$recreated" ]] || fail 'reset did not issue'
login containd "$reset_password"
jq -e '.user.mustChangePassword == true' "$scratch/body" >/dev/null
fixture <<'PY'
import sqlite3
assert 'auth.bootstrap_password.issued' in '\n'.join(sqlite3.connect('/data/audit.db').iterdump())
PY
# Host-authorized lost-password procedure preserves config and audit, loses users.
compose stop containd
fixture <<'PY'
from pathlib import Path
import hashlib
root=Path('/data')
before={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ['config.db','audit.db']}
(root/'users-recovery').mkdir(mode=0o700)
for n in ['users.db','users.db-wal','users.db-shm']:
    p=root/n
    if p.exists(): p.rename(root/'users-recovery'/n)
assert before=={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in before}
PY
compose start containd
wait_healthy
recovered=$(password_from_log)
login containd "$reset_password" 401
login containd "$recovered"
jq -e '.user.mustChangePassword == true' "$scratch/body" >/dev/null

new_case interrupted-boot
# Attach before starting, rather than polling after detached up (which can return
# only after issuance). Kill on the first profile line observed from stdout.
compose create containd
container_id
python3 - "$cid" "$scratch/crash.log" <<'PY'
import os,selectors,subprocess,sys,time
cid,path=sys.argv[1:]
p=subprocess.Popen(['docker','start','--attach',cid],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
selector=selectors.DefaultSelector()
selector.register(p.stdout,selectors.EVENT_READ)
deadline=time.monotonic()+60
seen=b''
try:
    with open(path,'wb') as log:
        while time.monotonic()<deadline:
            if not selector.select(timeout=1): continue
            chunk=os.read(p.stdout.fileno(),65536)
            if not chunk: raise RuntimeError('startup exited before profile line')
            log.write(chunk)
            seen+=chunk
            if b'profile=strict' in seen:
                subprocess.run(['docker','kill','--signal','KILL',cid],check=True,timeout=15)
                p.wait(timeout=30)
                break
        else: raise RuntimeError('profile line not observed before timeout')
finally:
    selector.close()
    p.stdout.close()
    if p.poll() is None:
        p.terminate()
        p.wait(timeout=10)
PY
[[ $(docker inspect --format '{{.State.ExitCode}}' "$cid") == 137 ]] || fail 'boot interruption was not SIGKILL'
compose up -d --force-recreate containd
wait_healthy
pin
logs >"$scratch/recovered-boot.log"
[[ $(grep -c 'CONTAIND ONE-TIME PASSWORD user=containd ' "$scratch/recovered-boot.log") == 1 ]] || fail 'recovery did not publish exactly one password'
login containd "$(password_from_log)"
jq -e '.user.mustChangePassword == true' "$scratch/body" >/dev/null

new_case training-migration
cat >"$scenario" <<'YAML'
services:
  containd:
    environment:
      CONTAIND_PROFILE: training
      CONTAIND_DEFAULT_ADMIN_USERNAME: first
YAML
start
pin
login first containd
old_token=$token
compose stop containd
# Create a second bootstrap account via the supported boot environment.
cat >"$scenario" <<'YAML'
services:
  containd:
    environment:
      CONTAIND_PROFILE: training
      CONTAIND_DEFAULT_ADMIN_USERNAME: second
YAML
compose up -d containd
wait_healthy
login second containd
second_token=$token
compose stop containd
fixture <<'PY'
import sqlite3,time
c=sqlite3.connect('/data/users.db')
for uid,version in c.execute('SELECT id,credential_version FROM users').fetchall():
    c.execute('INSERT INTO mfa_challenges VALUES (?,?,?,?,?)',('smoke-'+uid,uid,'login',version,int(time.time())+3600))
c.commit()
PY
cat >"$scenario" <<'YAML'
services:
  containd:
    environment:
      CONTAIND_PROFILE: strict
      CONTAIND_DEFAULT_ADMIN_USERNAME: first
YAML
compose up -d containd
wait_healthy
logs >"$scratch/migration.log"
[[ $(grep -c 'CONTAIND ONE-TIME PASSWORD user=' "$scratch/migration.log") == 2 ]] || fail 'expected two rotations'
compose exec -T containd cat /data/bootstrap/admin-password >"$scratch/password-file"
[[ $(wc -l <"$scratch/password-file" | tr -d ' ') == 2 ]] || fail 'expected two file entries'
for user in first second; do
  login "$user" containd 401
  login "$user" "$(password_from_log "$user")"
  jq -e '.user.mustChangePassword == true' "$scratch/body" >/dev/null
done
# Explicit bearer auth must not silently fall back to the new cookie.
expect 401 auth/me -H "Authorization: Bearer $old_token"
expect 401 auth/me -H "Authorization: Bearer $second_token"
fixture <<'PY'
import sqlite3
c=sqlite3.connect('/data/users.db')
assert c.execute("SELECT count(*) FROM mfa_challenges WHERE id LIKE 'smoke-%'").fetchone()[0]==0
assert c.execute('SELECT count(*) FROM sessions WHERE revoked=1').fetchone()[0]>=2
PY

new_case no-secret-leak
cat >"$scenario" <<'YAML'
services:
  syslog:
    image: python:3-alpine
    volumes: [strict-syslog:/capture]
    entrypoint: [python3, -u, -c]
    command:
      - |
        import socket
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.bind(('0.0.0.0',5514))
        open('/capture/ready','w').close()
        with open('/capture/syslog','ab',buffering=0) as f:
          while True: f.write(s.recv(65535)+b'\n')
    healthcheck:
      test: [CMD, python3, -c, "from pathlib import Path; assert Path('/capture/ready').exists()"]
      interval: 1s
      retries: 30
  containd:
    environment:
      CONTAIND_LOG_SYSLOG_ADDR: syslog:5514
      CONTAIND_LOG_SYSLOG_PROTO: udp
    depends_on:
      syslog:
        condition: service_healthy
volumes:
  strict-syslog:
YAML
start
pin
secret=$(password_from_log)
printf '%s' "$secret" >"$scratch/secret"
compose exec -T syslog cat /capture/syslog >"$scratch/syslog"
[[ -s $scratch/syslog ]] || fail 'syslog capture empty (sink not exercised)'
! grep -F "$secret" "$scratch/syslog" || fail 'secret leaked to syslog'
fixture <<'PY'
from pathlib import Path
import sqlite3
secret=Path('/smoke/secret').read_text()
audit='\n'.join(sqlite3.connect('/data/audit.db').iterdump())
assert 'auth.bootstrap_password.issued' in audit
assert secret not in audit
for p in Path('/data/logs').rglob('*'):
    if p.is_file(): assert secret.encode() not in p.read_bytes(), str(p)
PY

new_case tls-rotation
start
pin
claim "$(password_from_log)"
old_fp=$(openssl x509 -in "$scratch/identity.pem" -noout -fingerprint -sha256)
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=strict-smoke -addext 'subjectAltName=DNS:strict-smoke,IP:127.0.0.1' -keyout "$scratch/new.key" -out "$scratch/new.crt" >"$scratch/openssl.log" 2>&1
jq -n --rawfile cert "$scratch/new.crt" --rawfile key "$scratch/new.key" '{certPEM:$cert,keyPEM:$key}' >"$scratch/upload.json"
expect 200 system/tls/cert -H 'Content-Type: application/json' --data-binary @"$scratch/upload.json"
# The next TLS handshake reloads the uploaded bundle; pin it from trusted storage.
pin
expect 200 system/tls
new_fp=$(openssl x509 -in "$scratch/identity.pem" -noout -fingerprint -sha256)
[[ $new_fp != "$old_fp" ]] || fail 'certificate not replaced'
jq -e --arg fp "${new_fp#*=}" '.servedCertFingerprintSHA256 == $fp' "$scratch/body" >/dev/null
logs >"$scratch/rotation.log"
grep -F "management TLS certificate sha256=${new_fp#*=}" "$scratch/rotation.log" >/dev/null
read -r expired_start expired_end expired_not_before expired_not_after <<<"$(python3 - <<'PY'
from datetime import datetime, timedelta, timezone

now = datetime.now(timezone.utc).replace(microsecond=0)
start, end = now - timedelta(hours=2), now - timedelta(hours=1)
print(start.strftime("%Y%m%d%H%M%SZ"), end.strftime("%Y%m%d%H%M%SZ"),
      start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"
mkdir -p "$scratch/expired-certs/newcerts"
: >"$scratch/expired-certs/index.txt"
printf '1000\n' >"$scratch/expired-certs/serial"
openssl req -new -newkey rsa:2048 -nodes -subj /CN=expired-strict-smoke \
  -addext 'subjectAltName=DNS:expired-strict-smoke,IP:127.0.0.1' \
  -keyout "$scratch/expired-certs/expired.key" -out "$scratch/expired-certs/expired.csr" \
  >"$scratch/expired-certs/req.log" 2>&1
cat >"$scratch/expired-certs/ca.cnf" <<EOF
[ ca ]
default_ca = local
[ local ]
database = $scratch/expired-certs/index.txt
new_certs_dir = $scratch/expired-certs/newcerts
serial = $scratch/expired-certs/serial
private_key = $scratch/expired-certs/expired.key
certificate = $scratch/expired-certs/unused.crt
default_md = sha256
policy = policy_any
copy_extensions = copy
[ policy_any ]
commonName = supplied
[ server ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
openssl ca -selfsign -batch -config "$scratch/expired-certs/ca.cnf" \
  -in "$scratch/expired-certs/expired.csr" -keyfile "$scratch/expired-certs/expired.key" \
  -startdate "$expired_start" -enddate "$expired_end" -extensions server \
  -out "$scratch/expired-certs/expired.crt" >"$scratch/expired-certs/ca.log" 2>&1
jq -n --rawfile cert "$scratch/expired-certs/expired.crt" \
  --rawfile key "$scratch/expired-certs/expired.key" '{certPEM:$cert,keyPEM:$key}' \
  >"$scratch/expired-upload.json"
expect 400 system/tls/cert -H 'Content-Type: application/json' --data-binary @"$scratch/expired-upload.json"
jq -e --arg before "$expired_not_before" --arg after "$expired_not_after" \
  '.error | contains("has expired") and contains("NotBefore="+$before) and contains("NotAfter="+$after) and contains("current UTC time=")' \
  "$scratch/body" >/dev/null || fail 'expired certificate upload error omitted its validity dates or current time'
expect 200 system/tls
jq -e --arg fp "${new_fp#*=}" '.servedCertFingerprintSHA256 == $fp and .certFingerprintSHA256 == $fp' \
  "$scratch/body" >/dev/null || fail 'expired certificate upload changed the served or configured identity'
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=strict-cn-only -keyout "$scratch/cn-only.key" -out "$scratch/cn-only.crt" >"$scratch/cn-only-openssl.log" 2>&1
jq -n --rawfile cert "$scratch/cn-only.crt" --rawfile key "$scratch/cn-only.key" '{certPEM:$cert,keyPEM:$key}' >"$scratch/cn-only-upload.json"
expect 400 system/tls/cert -H 'Content-Type: application/json' --data-binary @"$scratch/cn-only-upload.json"
jq -e '.error | contains("subject alternative name") and contains("-addext")' "$scratch/body" >/dev/null || fail 'CN-only upload error did not explain the SAN requirement and fix'
expect 200 system/tls
jq -e --arg fp "${new_fp#*=}" '.servedCertFingerprintSHA256 == $fp' "$scratch/body" >/dev/null || fail 'CN-only upload changed the served identity'
expect 400 system/tls/cert -H 'Content-Type: application/json' -d '{"certPEM":"invalid","keyPEM":"invalid"}'
expect 200 system/tls
jq -e --arg fp "${new_fp#*=}" '.servedCertFingerprintSHA256 == $fp' "$scratch/body" >/dev/null
compose restart containd
wait_healthy
expect 200 system/tls
jq -e --arg fp "${new_fp#*=}" '.servedCertFingerprintSHA256 == $fp' "$scratch/body" >/dev/null
compose stop containd
fixture <<'PY'
from pathlib import Path
Path('/data/tls/server.pem').write_text('corrupt identity\n')
PY
compose start containd
assert_exit 'CONTAIND_PROFILE=strict refuses to start without HTTPS:'
cat >"$scenario" <<'YAML'
services:
  containd:
    environment:
      CONTAIND_PROFILE: training
    ports: !override
      - "127.0.0.1:0:8080"
YAML
compose up -d containd
container_id
http_api="http://$(compose port containd 8080)/api/v1/health"
http_ok=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 2 "$http_api" >"$scratch/training-health"; then http_ok=1; break; fi
  sleep 2
done
[[ $http_ok == 1 ]] || fail 'training did not retain HTTP after TLS corruption'
jq -e '.profile == "training"' "$scratch/training-health" >/dev/null
passed=1
echo 'strict smoke passed'
