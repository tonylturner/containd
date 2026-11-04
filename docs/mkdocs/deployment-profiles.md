# Deployment profiles

`CONTAIND_PROFILE` selects `training` or `strict` at process start. An unset or
blank value selects training and emits a startup warning. An unknown value
refuses startup. Profiles are not saved configuration and cannot change at runtime.
The supplied manifests set their profile explicitly; changing `.env` does not
change that manifest choice.

| Boundary | Training | Strict |
| --- | --- | --- |
| Manifest | `deploy/docker-compose.yml` (also dev and smoke) | `deploy/docker-compose.strict.yml` |
| Published management | HTTP, HTTPS and SSH on all host interfaces by default | HTTPS and SSH on `127.0.0.1` only; no HTTP port |
| HTTP listener | Configurable | Off, including inside the container; no redirect listener |
| HTTPS failure at boot | Can disable HTTPS and retain HTTP | Refuses startup; never downgrades to HTTP |
| Fresh admin password | `containd` / `containd` by default | Random one-time password; first-login change required |
| Session cookies / HSTS | Configurable | Always Secure / enabled |
| SSH | Appliance CLI or Linux shell | Appliance CLI only; `shell` is refused |
| Docker socket | Dev manifest mounts it | Mount refused by management and engine |
| Lab authentication, static tokens, default password override | Training-only | Refused |

Strict is not a host-security boundary. The container still needs root,
networking capabilities and `/dev/net/tun` for the dataplane. Host administrators
can read its data and logs. Loopback publication restricts host access, not access
from other containers on attached networks. Bind interfaces and management
access policy to match your topology. A reverse proxy must use HTTPS upstream.
Resource limits and a read-only root filesystem need deployment-specific testing;
the strict manifest does not prescribe them.

## Start strict

Requires Docker Engine 28.1+ and Compose with `interface_name` support (2.36.0+).
The default host data folder is `deploy/data-strict/`, not the starter's
`deploy/data/`. Set `CONTAIND_DATA_DIR` for a different strict-only folder.
Existing users must [move their data before starting](update-policy.md#existing-data-directories)
to avoid creating a fresh appliance.

From a repository checkout, create a private `.env` if you do not have one:

```bash
(umask 077; set -C; sed "s/^CONTAIND_JWT_SECRET=.*/CONTAIND_JWT_SECRET=$(openssl rand -hex 32)/" .env.example > .env)
docker compose --env-file .env -f deploy/docker-compose.strict.yml config --quiet
docker compose --env-file .env -f deploy/docker-compose.strict.yml up -d
docker compose --env-file .env -f deploy/docker-compose.strict.yml logs containd
```

Use an image version that supports profiles. Check subnet conflicts and edit
`.env` before starting. The strict file uses the same eight-role topology as the
[training starter](docker-compose.md). HTTPS is at `https://127.0.0.1:8443` and
SSH at `ssh -p 2222 containd@127.0.0.1`, unless you change the published ports.
The engine API stays namespace-local and is not published.

A fresh strict boot prints this line directly to container stdout:

```text
CONTAIND ONE-TIME PASSWORD user=containd password=<secret> generation=<n> (a password change is required at first login)
```

It also writes `<users-db-directory>/bootstrap/admin-password` (normally
`/data/bootstrap/admin-password`), one `username password` line per pending
account. The directory is mode 0700 and the file is 0600, owned by the container
process user. A file-write failure logs a warning; stdout remains authoritative.
Restrict access to both the host data directory and container logs.
The password is not sent through application logging, syslog or audit records.
Audit records contain only issuance metadata.

Verify `management TLS certificate sha256=<fingerprint>` in the container log
through a trusted host connection before trusting the self-signed certificate.
`GET /api/v1/system/tls` reports served and configured SHA-256 fingerprints.
[Replace the management identity](config-format.md#management-https-identity)
with an operator certificate when appropriate. Valid reloads log the new
fingerprint; invalid replacements retain the last-good served identity.

Log in with the one-time password and change it. Until then, ordinary API writes
are refused. SSH password and bootstrap-key logins also require the change
before entering the CLI. Direct `containd cli` cannot perform the change; use
web/API or SSH first, then set `CONTAIND_CLI_USER` and `CONTAIND_CLI_PASSWORD`.
The CLI, SSH server and health check call the local management API over pinned
HTTPS, not insecure TLS bypasses.
Strict requires the management certificate to include a DNS or IP SAN; a
stored SAN-less certificate prevents strict startup. Training keeps serving an
existing SAN-less identity with a warning until it is replaced.

Every strict boot reissues passwords for accounts still awaiting the change,
invalidating their old passwords, sessions and MFA challenges. A claimed,
non-default password is unchanged. The file entry is removed after password
change. Factory reset issues a new password by the same stdout/file paths and
retains a secret-free issuance audit record after the reset's audit wipe.
A boot that fails later on TLS may already have issued a password; the next
strict boot reissues it.

## Startup refusals

Strict management requires a unique JWT secret of at least 32 characters
(`openssl rand -hex 32`), and refuses:

- Enabled `CONTAIND_LAB_MODE`.
- `CONTAIND_ADMIN_TOKEN` or `CONTAIND_AUDITOR_TOKEN`.
- `CONTAIND_DEFAULT_ADMIN_PASSWORD` (a custom username is allowed).
- A nonempty `CONTAIND_COOKIE_SECURE` other than `1` or `true`.
- A nonempty `CONTAIND_SSH_SHELL_MODE` other than `appliance`.
- A mounted `/var/run/docker.sock`, or inability to inspect that path.
- `CONTAIND_MGMT_RESERVATION`.
- An unusable HTTPS identity or inability to bind HTTPS after listener recovery.
- A management certificate without a DNS or IP subject alternative name.

In standalone engine mode, strict preflight checks only the Docker socket.
Management users-database creation or open failure is fatal in **both** profiles;
there is no fallback to `data/users.db`. Correct paths and permissions instead
of starting against a second users database.

## Existing installations and migration

**Keep one profile per data directory.** Do not alternate the manifests over
the same data. Starting training over strict data can republish management on
all interfaces. Never run two management processes against one users database:
each strict boot can invalidate the other's unclaimed passwords.

Back up the data, record the existing management boundary and stop the old
stack before migrating. Use the strict manifest deliberately, not a profile
flag added to the training manifest. Remove training-only overrides and socket
mounts. Preserve a tested host access path and verify HTTPS and credentials
before retiring the old access path.

Strict does not support the reserved management path: that path requires plain
HTTP. **Do not simply remove the reservation** to make strict start; this changes
the management boundary. Keep that deployment in training until you have designed
and tested a replacement HTTPS management boundary.

At first strict boot, every account still using the password `containd` is
rotated to its own one-time password. Claimed non-default credentials remain.
Saved Linux-shell, HTTPS-off and HSTS-off values are retained as saved intent,
but strict overrides them at runtime. TLS status shows effective values, `profile`
sources and overridden saved values. `show system` and `show system ssh` show
SSH source `profile (strict)`. Unrelated candidate edits can carry these values;
repair them one at a time and commit. Once repaired, new writes or imports
cannot reintroduce them. Rollback preserves previously accepted saved intent,
but cannot disable the strict runtime protections.

Training keeps its authentication behavior. New common behavior includes profile
status in `/health` and `/auth/me`, fingerprint reporting, fatal users-database
failures and effective `enableHSTS=false` (previously a duplicate header defeated
that setting).

## Lost password

If the account has not claimed its one-time password, restart strict and read
the new stdout line or password file. Removing just the file does not reset an
account. If another admin can sign in, use that admin to reset the password.
An authenticated factory reset is **not** a recovery path if nobody can log in.

For host-authorized recovery with no usable admin, stop the sole management
container, then move the users database and its WAL/SHM sidecars aside. This
**loses all accounts, MFA enrollments and sessions**, not configuration or audit
history. For the strict manifest's default `deploy/data` mount, from the repo root:

```bash
docker compose --env-file .env -f deploy/docker-compose.strict.yml stop containd
# Use the actual configured users DB path if it differs. Keep this backup private.
backup="deploy/users-recovery-$(date +%Y%m%d%H%M%S)"
(umask 077; mkdir "$backup")
for file in deploy/data/users.db deploy/data/users.db-wal deploy/data/users.db-shm; do
  if test -e "$file"; then sudo mv "$file" "$backup/"; fi
done
docker compose --env-file .env -f deploy/docker-compose.strict.yml start containd
docker compose --env-file .env -f deploy/docker-compose.strict.yml logs --since 2m containd
```

Use host administrator privileges as needed. Strict seeds a fresh admin, prints
a new password and requires a change at first login. Enroll MFA again and review
the retained SSH authorized keys. Keep the backup private; it contains password hashes and MFA material.

## Helper scripts

`quickstart.sh`, `bootstrap-starter.sh`, `scripts/containd` and
`scripts/containd-connect` select the training starter only. They are not strict
provisioning or recovery tools. Use explicit strict Compose commands above.
