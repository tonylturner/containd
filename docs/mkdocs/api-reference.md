# API Reference

containd exposes a REST API under `/api/v1`. All authenticated endpoints require a JWT obtained via `POST /auth/login`.

When optional local-account MFA is enabled, `POST /auth/login` returns an MFA challenge instead of a session token, and `POST /auth/login/mfa` completes the login with a TOTP code.

Admins can also require MFA for specific local accounts. When MFA is required for a user who has not enrolled yet, containd grants a 7-day grace period during which the user can still log in with a password and complete MFA setup. After that grace period expires, the user is restricted to account, logout, and MFA-enrollment endpoints until MFA is enabled.

## OpenAPI Specification

A machine-readable OpenAPI 3.0 specification is maintained at [`docs/openapi.yaml`](https://github.com/tonylturner/containd/blob/main/docs/openapi.yaml). You can load this file into any OpenAPI-compatible viewer (Swagger UI, Redocly, Stoplight, etc.) for interactive exploration.

The spec covers authentication, configuration lifecycle, CRUD endpoints for zones/interfaces/firewall rules/assets, embedded services, DPI/ICS operations, PCAP analysis, learn mode, inventory, signatures, anomalies, templates, monitoring, and diagnostics.

Authentication and user-management coverage includes:

- TOTP MFA enrollment, enable, disable, and login verification
- admin-side MFA disable/reset
- admin-side MFA requirement, grace-period extension, and requirement clearing

## Quick Endpoint Overview

See [Config Format — API Endpoints](config-format.md#api-endpoints) for a concise listing of all REST endpoints.

## Staged Configuration

All persisted configuration edits stage into one shared candidate, including
object CRUD, service settings, IDS rules, saved PCAP settings, `POST /config`
and `POST /config/import`. Import replaces the candidate, never running.
Editable lists and settings read candidate desired state. Staging does not apply
anything to the engine or services; read-only discovery/validation is permitted.
Use `GET /config/diff` to review, then `POST /config/commit` or
`POST /config/commit_confirmed` to promote and apply. Running configuration and
its IDS bank are promoted and rolled back together. Plain commit cancels an
outstanding confirmed-commit timer and replaces its rollback baseline.

`GET /config`, `GET /config/export`, config backups, `GET /ids/export` and
`GET /ids/backup` read running. IDS import and restore stage desired rules.
Operational commands (blocks, reconcile, credentials, definition updates and
capture start/stop) remain immediate. `/pcap/start` uses its request body, or
running PCAP settings when absent; neither start nor stop persists settings.
CLI configuration commands report `staged; run "commit" to apply`.

Successful staged edits return `X-Containd-Config: staged`. Successful commit,
commit-confirmed, confirm and rollback return `X-Containd-Config: committed`.
Operational, read, preview-only and failed responses carry neither header value.

## Orchestrator Client Contract

Orchestrators that push a whole policy, such as RangerDanger, apply it with
these two calls (paths below are relative to `/api/v1`):

1. `POST /config/candidate` with the full document. A non-2xx response means
   staging failed; report the error body. Staging alone never activates policy.
2. `POST /config/commit`. A 200 with `X-Containd-Config: committed` means the
   requested snapshot was applied. With `dataplane.enforcement: true`, the nft
   ruleset has been installed; nft errors, including missing `NET_ADMIN`, are
   failures, never ruleset warnings. Keep enforcement enabled for a firewall.
3. Optionally, `GET /config` and compare running with what was submitted
   (secrets are redacted). Check `GET /health` for continuing runtime health.

Commit, commit-confirmed and rollback restore the pre-request running document
and IDS bank on apply failure, then reapply them. The failed candidate stays
staged for correction; previous snapshots and any pre-existing confirmed-commit
deadline are restored too. HTTP 500 returns, for example:

```json
{
  "error": "configuration apply failed",
  "detail": "ruleset: nft apply failed: ...",
  "restored": true,
  "reapplied": true
}
```

`restored` and `reapplied` describe the two recovery operations separately.
A false value includes `restoreError` or `reapplyError`; `healthError` means
persisting the recovery health failed. Do not assume a non-2xx leaves the live
firewall unchanged: a failed reapply leaves runtime synchronization uncertain.
A store preflight/validation failure before promotion is HTTP 400 without
recovery fields and does not promote running. A disconnected request is not
proof of success or failure; read running, candidate and health before retrying.

`GET /health` remains HTTP 200 liveness and uses one observation budget of
one second. General firewall health is a top-level `enforcement` object with
exactly `state` and `reason`:

- `enforcing`: enforcement is enabled and the engine reports an applied ruleset
  without error.
- `disabled`: `dataplane.enforcement: false` intentionally selects the supported
  in-memory-only mode; a successful commit does not install nft rules.
- `unavailable`: the ruleset apply failed, no ruleset has been applied while
  enforcement is enabled, or a persisted replay/recovery fault makes runtime
  synchronization uncertain (including a failed disable operation).
- `unknown`: the configuration/fault or engine state could not be read within
  the observation budget. Health waits through brief store contention, but it
  never waits past that shared budget or exposes an unapplied document. Enforcement
  and management binding report `unknown` if the store remains busy until the
  budget expires.

A persisted replay/recovery fault survives management restarts until a
successful apply and takes precedence over configured mode. Its generic
`reason` does not expose policy diagnostics without authentication; the commit
response carries details. There is no separate config-apply-error field.
The existing `iec104Enforcement` object is unchanged: only `active`, `healthy`
and `reason`, describing IEC104 queue/reset health independently. An inactive
IEC104 policy is not proof nft is available. A successful commit does not
guarantee later queue/reset readiness or packet delivery; check both health
objects and infrastructure warnings.

Interface, routing, engine service (including the auxiliary DHCP redirect),
IPv4 forwarding and PCAP problems remain 200 + `X-Containd-Warnings` when the
firewall snapshot applies. Management service-apply failures and dataplane
configuration failures are fatal and trigger recovery. Auxiliary warning
sources are best-effort during recovery too; recovery success certifies the
firewall snapshot, not every network or service side effect.

Do not fall back to `POST /config/import` when commit fails. Import only
stages: its 200 with `X-Containd-Config: staged` does not change running or
the live firewall. Older clients, including RangerDanger 0.1.36, fall back on
any commit error and can report that staged import as success. This existing
client quirk is not an activation guarantee. Nft failures now trigger that
fallback instead of returning a misleading 200 + ruleset warning; operators
must fix enforcement availability and explicitly commit again.

On an appliance with a [reserved management path](management-reservation.md),
the submitted document must keep the reserved interface's `device` binding and
set `dataplane.enforcement: true`. Copy the binding from `GET /config`.
Otherwise staging is rejected with HTTP 400 and running remains unchanged.

`POST /config/confirm` only cancels the pending rollback deadline; its
`committed` header acknowledges confirmation, not a new runtime apply.
Factory reset also uses the strict apply path, but is destructive and does not
restore wiped users/config/audit data if its runtime apply fails.

## Event Retention and Page Limits

`GET /api/v1/events?limit=N` returns at most `N` events (default 500, maximum
5000), but **not necessarily the globally newest N**. Each runtime store
keeps a separate count-bounded bank of its latest 1024 real
`firewall.rule.hit` events whose `attributes.action` is exactly `DENY`.
Later DENYs evict older bank entries; ordinary telemetry does not. There is
no age expiry. The bank survives configuration rebuilds, not process restarts,
and is not a guarantee of a fixed number of hours under DENY floods.

Both the engine's `/internal/events` listing and the management API select
DENYs first, newest-first if they exceed the limit. Management merges engine
and service candidates before applying the same rule. Remaining slots contain
the newest other events. Results are deduplicated by event ID and then sorted
newest-first by timestamp, with descending ID breaking ties. Original IDs,
timestamps and network tuples do not change.

An unreachable-engine telemetry-error row always reserves a slot, even at
`limit=1`. Small pages can therefore consist entirely of DENYs or the error;
old evidence can displace newer ordinary telemetry. This selection applies
to all protocols, including Modbus and DNP3, not only IEC104.

`GET /api/v1/events/{id}` can find retained DENYs after the general ring has
wrapped. `/api/v1/flows` still rolls up only the general event ring; prolonged
DENY retention does not resurrect old flow groups.

## Forwarding Health and Commit Warnings

Unauthenticated `GET /api/v1/health` includes `ipv4Forwarding`, which is
`enabled`, `disabled`, or `unknown`. The value is read from
`/proc/sys/net/ipv4/ip_forward` by the engine in its network namespace;
`unknown` means the sysctl could not be read or the management API could not
reach the engine.

`managementBinding.state` is `configured`, `unbound-appliance`, or `unknown`.
`unbound-appliance` means management access is granted only on logical
interfaces that have no existing device. The management listeners in
`recoveryPorts` then accept connections on every existing NIC except those
whose access is explicitly disabled, so an unbound appliance never locks out
management. Bind the interfaces to clear this state.

When a commit applies a configuration spanning multiple zone-assigned
interface devices and forwarding is disabled, the response includes the
`X-Containd-Warnings` header:

```text
ipv4 forwarding is disabled (net.ipv4.ip_forward=0); routed traffic will not pass
```

Warnings are returned as repeated `X-Containd-Warnings` header values when
there is more than one.

## IEC 104 Pressure Diagnostics

`GET /api/v1/diagnostics/iec104` is available to authenticated readers. It proxies
`GET /internal/diagnostics/iec104` on the engine and returns HTTP 503 with
`{"error":"engine IEC104 diagnostics unavailable"}` if the engine is unreachable
or cannot supply diagnostics. It never substitutes zeros for an unavailable engine.

The response contains `heldPackets`, `heldBytes`, `oldestPendingSeconds`,
`activeSessions`, `trackedSessions`, fixed `limits`, `aborts` by reason,
`resetWorkerRejections`, `verdictFailures` and `injectorFailures`. Totals last for
the engine process lifetime. `trackedSessions` includes closed sessions and tombstones, whereas
`activeSessions` counts live incarnations and replacement handshakes. Verdict
failures cover the shared inline pipeline (excluding intentional queue closure).
See [IEC 104 holdback diagnostics](ics-dpi.md#iec-104-holdback-diagnostics) for
bounds and counting semantics; the OpenAPI schema lists every field and reason.

## Environment Variables

The following environment variables control runtime behavior. They are read at startup and (where noted) on `SIGHUP` reload.

### Listeners

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTAIND_MGMT_HTTP_ADDR` | `:8080` | HTTP listen address inside the container |
| `CONTAIND_MGMT_HTTPS_ADDR` | `:8443` | HTTPS listen address inside the container |
| `CONTAIND_SSH_ADDR` | `:2222` | SSH console listen address |
| `CONTAIND_ENGINE_ADDR` | `:8081` | Dataplane engine listen address |
| `CONTAIND_ENGINE_URL` | *(auto in combined mode)* | URL the management plane uses to reach the engine. In combined `all` mode, containd defaults this to `http://127.0.0.1:8081` when unset. |

### Persistence

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTAIND_CONFIG_DB` | `/data/config.db` | Path to the configuration SQLite database |
| `CONTAIND_AUDIT_DB` | `/data/audit.db` | Path to the audit log SQLite database |
| `CONTAIND_USERS_DB` | `/data/users.db` | Path to the users SQLite database |

### Authentication & Security

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTAIND_LAB_MODE` | `0` | Enable lab/dev defaults (`1` to enable). When disabled (default), enforces a strong JWT secret. |
| `CONTAIND_JWT_SECRET` | *(generated by starter scripts / required in real deployments)* | HMAC secret for JWT signing. **Must** be set to a unique value when `LAB_MODE=0`. Generate with `openssl rand -hex 32`. |
| `CONTAIND_COOKIE_SECURE` | `0` | Force the `Secure` flag on session cookies. Set to `1` when serving behind TLS. |
| `CONTAIND_TRUSTED_PROXIES` | *(empty)* | Comma-separated CIDRs/IPs of reverse proxies trusted for `X-Forwarded-For` headers. |
| `CONTAIND_ALLOWED_ORIGINS` | *(empty)* | Optional comma-separated browser origins allowed to embed or call the appliance cross-origin. Cookie-authenticated browser writes from other origins are denied unless listed here. |
| `CONTAIND_DEFAULT_ADMIN_USERNAME` | `containd` | Username for the initial admin account (provisioned on first run). |
| `CONTAIND_DEFAULT_ADMIN_PASSWORD` | `containd` | Password for the initial admin account. |

### SSH

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTAIND_SSH_AUTH_KEYS_DIR` | `/data/ssh/authorized_keys.d` | Directory for SSH authorized-key files |
| `CONTAIND_SSH_HOST_KEY` | `/data/ssh/host_key` | Path to the SSH host key |
| `CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY` | *(empty)* | Optional `authorized_keys` line to seed on first boot |
| `CONTAIND_SSH_BOOTSTRAP_ADMIN_USER` | `containd` | User associated with the bootstrap SSH key |

### Dataplane

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTAIND_CAPTURE_IFACES` | *(empty)* | Comma-separated list of interfaces to capture on |
| `CONTAIND_ENFORCE_ENABLED` | `0` | Enable nftables enforcement (`1` to enable). The published starter and dev compose files override this to `1` by default. |
| `CONTAIND_DPI_MOCK` | `0` | Enable synthetic DPI event generation for testing (`1` to enable) |

### DPI Configuration (Staged)

DPI mode and per-protocol settings are staged via the API or UI, not environment variables. Use `POST /api/v1/dataplane`, then commit, with:

- `dpiMode` -- `"learn"` (passive observation) or `"enforce"` (active policy enforcement)
- `dpiIcsProtocols` -- map of protocol name to boolean (e.g., `{"modbus": true, "dnp3": true, "cip": false}`)

See [ICS DPI](ics-dpi.md) for details.
