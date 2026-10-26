# API Reference

containd exposes a REST API under `/api/v1`.

## Authentication

Normal deployments use session-backed JWTs from `POST /auth/login`.
Send `Authorization: Bearer <token>` or the `containd_token` cookie set by login.
Sessions have a 30-minute idle timeout and a 4-hour maximum lifetime.
Logout revokes the session and clears the cookie. Cookie-authenticated browser
writes require a same-origin request or an explicitly allowed origin.

Lab mode (`CONTAIND_LAB_MODE=1`) still requires a token, but grants admin
privileges without normal session enforcement. If a JWT secret is configured,
the token must be a valid signed JWT; without one, any nonempty token is accepted.
Do not expose lab mode to untrusted clients.

Static bearer authentication is a fallback when the user store or JWT secret
is unavailable: `CONTAIND_ADMIN_TOKEN` grants admin access and
`CONTAIND_AUDITOR_TOKEN` grants read-only access. These tokens do not replace
session authentication in a normally configured appliance. Production startup
requires a nonempty, non-example JWT secret.

When optional local-account MFA is enabled, `POST /auth/login` returns an MFA challenge instead of a session token, and `POST /auth/login/mfa` completes the login with a TOTP code.

Admins can also require MFA for specific local accounts. When MFA is required for a user who has not enrolled yet, containd grants a 7-day grace period during which the user can still log in with a password and complete MFA setup. After that grace period expires, the user is restricted to account, logout, and MFA-enrollment endpoints until MFA is enabled.

## OpenAPI Specification

A machine-readable OpenAPI 3.0 specification is maintained at [`docs/openapi.yaml`](https://github.com/tonylturner/containd/blob/main/docs/openapi.yaml). You can load this file into any OpenAPI-compatible viewer (Swagger UI, Redocly, Stoplight, etc.) for interactive exploration.

The specification is the canonical endpoint and schema reference.
`TestOpenAPIRoutes` compares every registered `/api/v1` method and path against
it in both directions, including optional identity routes and delegated audit
registration. Optional routes require their corresponding server integration.
The non-versioned Prometheus `/metrics` endpoint is outside this API base.

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

For confirmed commits, send `POST /config/commit_confirmed` with
`{"ttl_seconds": 60}`, then `POST /config/confirm` before the timer expires.
Otherwise the prior running configuration and IDS bank are restored.
See [Config Format](config-format.md) for the configuration lifecycle and JSON.

Successful staged edits return `X-Containd-Config: staged`. Successful commit,
commit-confirmed, confirm and rollback return `X-Containd-Config: committed`.
Operational, read, preview-only and failed responses carry neither header value.

## Events: Filtered Queries and Legacy Lists

Use `GET /api/v1/events?query=1` for an `EventPage` envelope containing `events`,
optional `nextCursor`, `historyTruncated`, and optional `engineError`.
Filters (`id`, `session`, `flow`, `apdu`, `kind`, `protocol`, `decision`,
`verdict`, `since`, `category`, `detections`) or `cursor` also select this mode.
Filters apply **before** the limit, with matches sorted newest-first by timestamp
and ID, without evidence priority. Filters combine with AND; comma-separated
`kind` prefixes combine with OR. `since` is inclusive RFC3339.

Send `nextCursor` as `cursor` with the same filters to fetch older matches.
Pagination searches retained memory, not durable history, and is not a snapshot:
inserts and eviction can change later pages. An absent cursor does not prove
complete history. `historyTruncated` is conservative; `engineError` must not be
treated as a successful empty search. See the OpenAPI event operation for the
complete query contract and retention bounds.

### Legacy only-limit callers

`GET /api/v1/events?limit=N` returns at most `N` events (default 500, maximum
5000) as a bare array, but **not necessarily the globally newest N**. Each runtime store
keeps a separate count-bounded bank of its latest 1024 real
`firewall.rule.hit` events whose `attributes.action` is exactly `DENY`.
Later DENYs evict older bank entries; ordinary telemetry does not. There is
no age expiry. The bank survives configuration rebuilds, not process restarts,
and is not a guarantee of a fixed number of hours under DENY floods.

Both the engine's `/internal/events` listing and the management API select
DENYs and retained IEC104 incident outcomes before ordinary telemetry.
Management merges engine
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

## Binary Runtime Environment

These are binary environment names, not Compose interpolation inputs.
Set them before starting the process; `SIGHUP` does not reload configuration.
Listener defaults below apply when neither an environment override nor a saved
listener setting supplies a value.

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTAIND_MGMT_ADDR` | `:8080` | Management HTTP listen address |
| `CONTAIND_MGMT_HTTPS_ADDR` | `:8443` | Management HTTPS listen address |
| `CONTAIND_SSH_ADDR` | `:2222` | SSH console listen address |
| `CONTAIND_ENGINE_ADDR` | `127.0.0.1:8081` in `all`; `:8081` in `engine` | Engine API listen address |
| `CONTAIND_ENGINE_URL` | Local engine URL in `all` | Management-to-engine URL; set explicitly for split processes |
| `CONTAIND_CONFIG_DB` | `data/config.db` | Configuration SQLite database |
| `CONTAIND_AUDIT_DB` | `data/audit.db` | Audit SQLite database |
| `CONTAIND_USERS_DB` | `data/users.db` | Users SQLite database |
| `CONTAIND_LAB_MODE` | Disabled | Lab authentication described above |
| `CONTAIND_JWT_SECRET` | Unset | Set a unique secret, e.g. `openssl rand -hex 32` |
| `CONTAIND_COOKIE_SECURE` | Automatic | Unset: Secure on HTTPS requests. `1` forces Secure; `0` disables it. Set `1` behind a TLS-terminating proxy. |
| `CONTAIND_TRUSTED_PROXIES` | `127.0.0.1,::1` | Comma-separated trusted proxy IPs/CIDRs for forwarded client addresses |
| `CONTAIND_ALLOWED_ORIGINS` | *(empty)* | Optional comma-separated browser origins allowed to embed or call the appliance cross-origin. Cookie-authenticated browser writes from other origins are denied unless listed here. |

Relative database paths are relative to the process working directory.
The engine API is **unauthenticated**. Restrict it to the management process or
a trusted private network; never publish the split-mode listener to untrusted
clients.

### Compose `.env` Inputs

Compose reads `.env` to interpolate deployment settings. In the published
Compose file, `CONTAIND_MGMT_HTTP_ADDR` supplies the container's
`CONTAIND_MGMT_ADDR`; the binary does not read `CONTAIND_MGMT_HTTP_ADDR`.
Compose supplies absolute `/data/*.db` paths on its persistent mount, unlike
the binary's relative defaults. Compose runs combined `all` mode; split mode
uses the `engine` and `mgmt` subcommands.

Use [Docker Compose](docker-compose.md) for deployment inputs and
[Services](services.md) for SSH and service configuration.

### DPI Configuration (Staged)

DPI mode and per-protocol settings are staged via the API or UI. Use
`GET /api/v1/dataplane`, edit the returned settings, then `POST /api/v1/dataplane`
and commit. POST replaces the settings rather than merging them. Fields include:

- `dpiMode` -- `"learn"` (passive observation) or `"enforce"` (active policy enforcement)
- `dpiIcsProtocols` -- map of protocol name to boolean (e.g., `{"modbus": true, "dnp3": true, "cip": false}`)

See [ICS DPI](ics-dpi.md) for details.
