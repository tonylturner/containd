# API Reference

containd exposes a REST API under `/api/v1`.
API paths below are relative to that base unless they include `/api/v1` or explicitly
name an engine or metrics endpoint.

## Authentication

Normal deployments use session-backed JWTs from `POST /auth/login`.
Send `Authorization: Bearer <token>` or the `containd_token` cookie set by login.
Sessions have a 30-minute idle timeout and a 4-hour maximum lifetime.
Logout revokes the session and clears the cookie. Cookie-authenticated browser
writes require a same-origin request or an explicitly allowed origin.

Lab mode (`CONTAIND_LAB_MODE=1`) still requires a token, but grants admin
privileges without normal session enforcement. If a JWT secret is configured,
the token must be an HS256 JWT signed with it and carry `exp` (30 seconds of
leeway); no session or `jti` is required. Without a secret, any nonempty token
is accepted.
`GET /auth/me` reports the effective `admin` role and the subject's local-account
profile, regardless of that account's stored role. A subject that does not name
a local account uses the configured bootstrap profile. Login, session, profile
update and dashboard caller profiles likewise report the effective role;
user-management endpoints still report stored account roles.
Factory reset does not revoke lab tokens, even with a JWT secret configured.
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
it in both directions, including delegated audit registration. Optional
routes require their corresponding server integration.
The non-versioned Prometheus `/metrics` endpoint is outside this API base.

## Monitoring Availability

Flows, protocol/top-talker statistics, anomalies, learner evidence and suggestion
generation/staging, signatures and matches, interface runtime state and simulation
return HTTP `503` with an `ErrorResponse` (`{"error":"engine … unavailable"}`)
when the required engine capability is missing or its call fails. The same
convention applies to anomaly clears, learner dataset deletion, signature writes
and simulation control: unavailable operations never report a successful clear or change.
A reachable backend with no observations still returns `200` with an empty
list (learner pages use `{items: [], nextCursor?}`); a reachable stopped simulation
returns `200` with `running: false`.
Retry unavailable requests rather than interpreting them as empty or stopped.

## Security Conduits

`GET /security/conduits` returns an array of running zone-to-zone policy
summaries. Each object contains explicit `from` and `to` zone names alongside
`state`, `ids`, `proto`, `traffic`, `rules`, `gaps`, `mitre` and the security
control flags documented in OpenAPI. Every ordered pair of distinct zones is
included, in configured zone order (source-major, then destination).
With fewer than two zones, the response is `[]`.

Zone names are exact, case-sensitive identities and may contain arrows or other
punctuation. Use the `from` and `to` fields directly; do not split a joined name.
Clients expecting the former map keyed by joined zone names must switch to
the array response; the map format is not supported.

## Evidence Status

`GET /api/v1/evidence/status` is authenticated, including for view-role readers.
It returns `audit` (local persistence state, failed-write count since process
start, optional failure/success times and sanitized error) and `forwarding`
(per-destination/source state, decimal-string `sentThrough`, retained `backlog`,
known `lost`, optional error and success time). No collectors is a valid empty
forwarding list, not a reason to omit audit persistence. `GET /audit` stays a bare
array of records with numeric audit IDs.

States are `ok`, `degraded`, `recovered` (history retained), or `unknown` (cannot
verify). Unauthenticated `GET /health` exposes only `evidence: {state}`, taking
the worst of audit and forwarding (degraded > unknown > recovered > ok), without
errors or destinations. HTTP 200 remains liveness. Audit write failure does not
block an operation. UI banners and `show audit --status` expose this independently
of visiting Syslog or configuring collectors.

`GET /services/status` includes independent `syslog.events` progress for every
telemetry destination/source: backlog, sent, failed, lost and continuity gaps,
with source epoch and exact decimal-string offset. `syslog.audit` remains the
separate durable audit forwarding view. See [Logging and Evidence](logging-evidence.md)
for retry, restart, new-destination and loss semantics.

Telemetry event `id` fields are decimal JSON strings end to end, including
`GET /events`, `GET /events/{id}`, query pages, preview samples and syslog JSON.
Send the same exact decimal string in detail paths or the `id` query parameter;
never round it through a JavaScript number. Audit record IDs remain numeric.

## Staged Configuration

Full-document POSTs to `/config`, `/config/candidate`, `/config/validate` and
`/config/import` require exact, case-sensitive top-level JSON names and reject
unknown or duplicate keys with HTTP 400. For example, `dataPlane` is rejected
with `unknown top-level key "dataPlane" (did you mean "dataplane"?)` in the
response's `detail`. API callers must send `dataplane` and `schema_version`;
nested-section compatibility is unchanged. Only `/config/import` accepts and
discards the retired `export` key from schemas `0.1.0`–`0.1.7`, with a missing
schema treated as `0.1.0`. Newer schemas with `export` are rejected. See
[backup and restore](config-format.md#configuration-lifecycle).

All persisted configuration edits stage into one shared candidate, including
object CRUD, identity bindings (`/identities`), service settings, IDS rules,
saved PCAP settings, `POST /config` and `POST /config/import`. Import replaces the candidate, never running.
Editable lists and settings read candidate desired state. Staging does not apply
anything to the engine or services; read-only discovery/validation is permitted.
Use `GET /config/diff` to review, then `POST /config/commit` or
`POST /config/commit_confirmed` to promote and apply. Running configuration and
its IDS bank are promoted and rolled back together. Plain commit cancels an
outstanding confirmed-commit timer and replaces its rollback baseline.

Ordinary edits leave the stored IDS rule bank untouched, so staging settings
stays inexpensive even with a large bank. Omitting `ids.rules` from a config
replacement retains the candidate bank; an explicit `[]` clears it. Full
exports and backups include rules; imports can replace them. `GET /config/diff`
compares running and candidate from one consistent store read. Unreferenced
rule-bank generations are reclaimed after edits and once runtime recovery
releases its saved snapshots. The Config page uses bounded, linear-memory line
diffs; very large changed sections display as replacements.

`GET /config`, `GET /config/export`, config backups, `GET /ids/export` and
`GET /ids/backup` read running. IDS import and restore stage desired rules.
Operational commands (blocks, reconcile, credentials, definition updates and
capture start/stop) remain immediate. `/pcap/start` uses its request body, or
running PCAP settings when absent; neither start nor stop persists settings.
CLI configuration commands report `staged; run "commit" to apply`.

For confirmed commits, send `POST /config/commit_confirmed` with
`{"ttl_seconds": 60}`, then `POST /config/confirm` before the timer expires.
Omitted or nonpositive TTLs use 60 seconds; duration overflow is rejected
before promotion. Expiry restores the prior running configuration and IDS bank
and requests runtime replay. Replay failures are retried and exposed in health,
not treated as a successful runtime apply.
See [Config Format](config-format.md) for the configuration lifecycle and JSON.

Successful staged edits return `X-Containd-Config: staged`. Successful commit,
commit-confirmed, confirm and rollback return `X-Containd-Config: committed`.
Operational, read and preview-only responses carry neither header value.
Failed responses also omit them. One exception is `POST /learn/apply`:
if candidate persistence succeeds but receipt completion fails, HTTP `503`
still carries `X-Containd-Config: staged`; the header does not mean the
entire request completed.
Configuration reads also return `X-Containd-Revision`; successful configuration
writes return the revision produced by that write, alongside the staged or
committed header. The revision is header-only, including on `/config/diff`.
Unauthenticated `/health` and all error responses omit the revision header.
A learner HTTP 503 reporting durable staging has no revision header: re-read the
candidate and review it before retrying the receipt.

`POST /interfaces/reconcile` and `POST /routing/reconcile` are runtime operations,
not configuration writers. They ignore `X-Containd-If-Revision` and return no
`X-Containd-Revision`. Reconcile leaves unfinished UI edits based on their original
revision; a later stale save requires conflict review rather than silently
overwriting another operator's changes.

## Orchestrator Client Contract

Every configuration writer requires `X-Containd-If-Revision` with the revision
of the snapshot it is based on. This includes full documents, section edits,
imports, IDS uploads, learner staging, commits, confirmation, rollback and
factory reset. There are no client or lab-mode exemptions. The ICS template
apply route with `preview: true` needs no revision header and ignores one if
sent; preview does not compare or change configuration state.

The revision covers running, candidate (including absence), previous,
confirmed-commit state and IDS bank references together. Treat it as an opaque
string, never a number or a document field. It has the form
`<16 lowercase hex characters>.<positive decimal counter>`, at most 64 bytes.
Unrelated simultaneous edits intentionally conflict. Restarts preserve it;
reset, rollback and apply compensation never restore an old revision.

Integrations that push a whole policy use these steps (paths are relative to
`/api/v1`):

1. `GET /config/candidate` and retain its `X-Containd-Revision` with the document.
2. `POST /config/candidate` with the full document and
   `X-Containd-If-Revision: <read revision>`. A non-2xx means staging failed;
   report the error. Staging alone never activates policy.
3. Review `GET /config/diff` and retain that response's revision with the diff.
   `POST /config/commit` with that reviewed revision. A 200 with
   `X-Containd-Config: committed` means the reviewed candidate was applied.
   An automated stage-then-commit sequence can send the exact revision returned
   by its stage; never fetch a later revision merely to authorize an old edit.
   With `dataplane.enforcement: true`, nft installation failures, including
   missing `NET_ADMIN`, fail the request rather than becoming warnings. Keep
   enforcement enabled for a firewall.
4. Optionally compare `GET /config` with the submitted running document
   (secrets are redacted and the IDS rule bank is omitted; `GET /config/export`
   includes the running IDS rules), and check `GET /health` for continuing
   runtime health.

Missing preconditions return HTTP **428** with `code: config_revision_required`.
Malformed preconditions (including `*`, quoted tokens and multiple values)
return **400** with `code: config_revision_malformed`, before body decoding.
Authentication and authorization run first. A stale valid precondition returns
**412**, without changing configuration, banks, timers or runtime policy:

```json
{"error":"configuration changed since it was read","code":"config_revision_mismatch","currentRevision":"0123456789abcdef.42"}
```

Keep the draft on 412. Re-read and review the changed state before deliberately
resubmitting; never automatically retry an old edit with `currentRevision`.
Independent semantic conflicts still use 409. A rejected VPN upload removes its
new file. Learner staging releases its engine reservation on rejection; release
uncertainty remains 503. If a learner 503 reports durable staging, retain the
receipt, re-read/review the candidate, and resubmit that same receipt with the
reviewed revision; the original precondition remains stale.

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
- `degraded`: a ruleset is in force, but the last apply failed and left the
  previous ruleset in force, or the schedule planner is degraded: a refill of
  the schedule time sets is failing, or their horizon ends within an hour.
  `schedulePlanner` in `GET /api/v1/dataplane/ruleset/status` (any
  authenticated user) and `engineStatus.schedulePlanner` in the admin-only
  `GET /api/v1/dataplane/ruleset` show the
  planner's last refill, horizon end and last error.
- `disabled`: `dataplane.enforcement: false` intentionally selects the supported
  in-memory-only mode; a successful commit does not install nft rules.
- `unavailable`: the ruleset apply failed with no ruleset in force, no ruleset
  has been applied while enforcement is enabled, or a persisted replay/recovery
  fault makes runtime synchronization uncertain (including a failed disable
  operation).
- `unknown`: the configuration/fault or engine state could not be read within
  the observation budget. Health waits through brief store contention, but it
  never waits past that shared budget or exposes an unapplied document. Enforcement
  and management binding report `unknown` if the store remains busy until the
  budget expires.

A persisted replay/recovery fault survives management restarts until a
successful apply and takes precedence over configured mode. Its generic
`reason` does not expose policy diagnostics without authentication; the commit
response carries details. There is no separate config-apply-error field.
`icsEnforcement` summarizes the applied ICS rule coverage with `state` and the
counts `enforcing`, `partial`, `notEnforcing` and `monitoring`; it names no rule
or exclusion. `state` is `none` without ICS rules, the worst state among
enforce-mode rules, `monitoring` when every ICS rule is in monitor mode, or
`unknown` when the engine cannot be read. `enforcement` stays the nftables-level
state. See [ICS rule coverage](dataplane-enforcement.md#ics-rule-coverage).
The existing `iec104Enforcement` object is unchanged: only `active`, `healthy`
and `reason`, describing IEC104 queue/reset health independently. It also turns unhealthy, with `active`
false, when the engine fails to reset an ICS connection it picked up mid-stream
while an enforce rule of another ICS protocol is loaded. An inactive
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
the live firewall. A client that treats a staged import as successful activation
can leave its requested policy unapplied. Fix enforcement availability and
explicitly commit again.

On an appliance with a [reserved management path](management-reservation.md),
the submitted document must keep the reserved interface's `device` binding and
set `dataplane.enforcement: true`. Copy the binding from `GET /config`.
Otherwise staging is rejected with HTTP 400 and running remains unchanged.

`GET /config/diff` includes `pendingConfirm: {"deadline":"<RFC3339 UTC>"}`
or `pendingConfirm: null`, read in the same snapshot as the documents and
revision. This is server state, including after navigation or a restart.

`POST /config/confirm` only cancels the pending rollback deadline; its
`committed` header acknowledges confirmation, not a new runtime apply. When
nothing is pending it returns the current revision without invalidating drafts.

### Factory reset

`POST /system/factory-reset` requires admin access and `{"confirm":"NUCLEAR"}`.
It validates the appliance defaults before changing any store, then replaces
configuration through the same atomic restore/reapply path as commit. If runtime
apply fails, HTTP 500 reports `error`, `detail`, `restored` and `reapplied`, plus
`restoreError`, `reapplyError` or `healthError` when those recovery steps fail:

```json
{"error":"configuration apply failed","detail":"ruleset: nft apply failed","restored":true,"reapplied":true}
```

Successful recovery preserves running, candidate, previous, pending-confirmed
state and the IDS bank. Users, credentials, MFA, sessions and existing audit
records are not wiped on an apply failure; the reset-intent audit record remains.
A failed recovery is explicitly reported and leaves runtime health unavailable.

Only after runtime apply succeeds does reset clear the engine's temporary
blocks and connection revocations, which the defaults do not replace, and
replace users and sessions with the default admin in one users-database
transaction, then clear audit history and the browser auth cookie. A user-reset failure rolls back the users and sessions
to their prior state and returns HTTP 500. It does not undo the successfully
applied configuration: the config and users databases do not share a
transaction. HTTP 200 returns `status: "reset"` and `loggedOut: true`, indicating
cookie clearing and client logout, not revocation of lab tokens. To log in again,
use the default credentials. Configuration history, pending rollback and the old
IDS bank are replaced, not retained for rollback.

The response includes `warnings` and the `X-Containd-Warnings` header when an
auxiliary apply fails, including engine-side service configuration, or when
the engine cannot clear its blocks (a `dynamic blocks:` warning: they remain
in force until they expire). HTTP 200
means the reset was applied, not that every subsystem converged. With warnings,
`message` reports incomplete convergence rather than completion; inspect the
warnings and runtime health before continuing. Mandatory daemon, dataplane or
ruleset failures still use the failure/recovery response above.

Outside lab mode, session-backed web/API tokens are revoked. Lab mode does not
look up session records: signed, unexpired tokens remain valid after reset even
with a JWT secret configured. Without a secret, lab mode still accepts any
nonempty token by design. The reset message explicitly reports that lab tokens
remain valid. SSH connections are closed.
An initiating appliance-console session prints its result and warnings before
disconnecting; Linux-shell connections are closed along with other sessions.
The reserved management path is retained, and lab mode keeps the documented
`containd` / `containd` credential.

### Reload running configuration (SIGHUP)

Send `SIGHUP` to `containd mgmt` or `containd all` to load **running**, not
candidate, from the configuration store and replay the existing apply sequence:

- Control-plane services: syslog, DNS, NTP, proxies, VPN and AV/ICAP settings.
- Engine interfaces, routing and service settings, including DHCP and WireGuard.
- Dataplane capture/inspection/enforcement settings, compiled firewall/NAT/IDS
  policy and saved PCAP configuration.

This repairs runtime drift; it does not commit candidate edits or change
configuration history. Invalid configuration fails preflight. A failed replay
retains the stored running configuration and records a runtime-health fault;
already-replayed subsystems are not transactionally rolled back. The process
logs the result and warnings and writes a `config.reload` audit record. Retry
after resolving the reported failure. Auxiliary apply failures remain warnings,
as with commit.

Environment variables and command-line flags are never reloaded. Management
HTTP/HTTPS listeners, TLS source paths, HTTP middleware, SSH listen address/banner/shell
mode and other startup-only system settings require a restart. SSH authentication
policy and host-key rotation already read their live running settings.
Engine-only mode logs that configuration reload is performed through management;
signal the management process to replay into a split engine.

The bound HTTPS listener reloads a validated identity without restart when its
contents change. See [Management HTTPS identity](config-format.md#management-https-identity)
for atomic bundle uploads, read-only external paths and rotation status.

`GET /api/v1/system/tls` always includes the boolean `managed`. It describes
the identity management next starts with, using the saved configuration and
this process's environment, just like `certFile` and `keyFile`; it does not
describe the bound listener's mode. `true` permits managed certificate uploads;
`false` selects external read-only credentials and certificate upload returns
HTTP 409. This is an identity-mode policy, not a guarantee that an upload will
pass validation or filesystem checks. Do not infer mode from file paths:
explicitly setting both source paths to `/data/tls/server.pem` is external
mode, although its reported paths match the managed bundle.

## Events: Filtered Queries and Legacy Lists

Use `GET /api/v1/events?query=1` for an `EventPage` envelope containing `events`,
optional `nextCursor`, `historyTruncated`, and optional `engineError`.
Filters (`id`, `ruleId`, `mode`, `session`, `flow`, `apdu`, `kind`, `protocol`,
`decision`, `verdict`, `since`, `category`, `detections`) or `cursor` also select this mode.
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
`firewall.rule.hit` events whose `attributes.action` is exactly `DENY` or
`RESET`.
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

## Content Identification Results

`GET /api/v1/events?query=1&kind=identification` returns identification events
with `proto: "identify"` and `kind: "identification"`, one per captured
connection incarnation. `attributes` contains:

- `protocol`, `identification_state` (`confirmed`, `reject`, or
  `identification_incomplete`), `reason`, optional `identification_coverage`
  (present only when identification ended on a coverage limit) and
  `identification_candidates`;
- `expected` (two endpoint protocol expectations, empty string for none),
  `service_transport`, `service_port`, `mismatch`;
- `binding` (`observation`, `legacy`, or `none`),
  `outside_rule_port_scope` (boolean, or `"unknown"` without a rule snapshot),
  `profile_version` and `syn_coverage` (two endpoint booleans).

Passive decoder events carry `observation_only: true` and
`binding_source: "observation"`. They are evidence, not verdicts. The Events
page marks them **Observation only**.

Offline and live suggestion generation excludes their entire connection
incarnation, including port-decoded events emitted before content confirmation.
Confirmed content/port mismatches also exclude the connection even if no passive
decoder emits an event. Generate exposes these exclusions as
`withheld.observation_binding`; suggestion limitations retain the exclusion.
Historical datasets lacking retained binding authority are withheld as
`missing_authority`. Reimporting the same capture after an adapter-normalization
change creates a separate dataset under the current normalization. Old datasets
remain readable and fail closed; unchanged normalization and decoding authorities
reuse the existing dataset without extending retention.

`GET /api/v1/flows` includes an optional `identification` object with these
attributes. `application` is the confirmed bound protocol when available,
otherwise the legacy application's decoder protocol. Utility markers do not
set it. Binding summaries survive eviction of their original event while
other events of the flow remain retained; they do not resurrect expired flows.

`POST /api/v1/pcap/analyze` (multipart `file`) and
`POST /api/v1/pcap/analyze/{name}` import a sealed engine-owned dataset and return
`{dataset, stats}`. No profiles or rules are returned. Uploads must be classic
PCAP (not PCAPng), at most 64 MiB. The same response shape is used by the engine's
internal import routes.

`stats.identifications` is an array of
`{key, flowId, srcIp, dstIp, srcPort, dstPort, attributes}`: `key` is a run-qualified
offline incarnation and `attributes` uses the spellings above. Captured SYN roles
are used when available, otherwise the flow's orientation hint.
`stats.events` includes identification and passive decoder events. Nonstandard
services remain observation-only. `stats.truncated` indicates a cut-short packet
or partial final record; `stats.displayTruncated` means only the display sample
was capped. Check `dataset.gaps` separately for collection and admission loss.
Recorded loss excludes every connection it could have touched from generation
and direct certification, with durable `collection_loss` withheld counts.
Known-connection loss excludes that incarnation. Coordinate-scoped loss excludes
all matching wire connections in either direction, across every incarnation:
with ports, the five-tuple; without ports, the host pair and transport protocol.
There is no observation-time bound: the first and last retained messages do not
prove when a connection opened or closed. Missing scope, including legacy
unlocalized gaps and timestamp-only losses, excludes the entire dataset.
Dataset `losses` retains each code with `connectionId` and/or `scope` (source and
destination endpoints, `transport`, and `ports`, which indicates whether ports
are authoritative), plus `captureHook` when known (`nfqueue` or `afpacket`).
Historical `start`/`end` fields remain readable but cannot
prove a connection disjoint. `gaps` retains certification-related summary codes.

Live observation `authority.aliases` retains the verified conntrack `original`
and `reply` wire tuples, even when only requests or only responses were retained.
Scope matches either alias across every incarnation; NAT reply tuples need not
be the endpoint reversal of the original. A known `connectionId` adds exclusion,
never replaces or narrows a coordinate scope. Live `authority.captureHook` records
receive-time capture provenance, independently of correlation success.
When both parent and loss are from the NFQUEUE forward hook (`nfqueue`), wire-only
matching is sufficient: both directions cross the same post-DNAT/pre-SNAT face.
Unrelated-host truncation therefore preserves NFQUEUE suggestions without
inventing NAT authority. Same-tuple loss still excludes every matching incarnation;
missing ports widen to host pair/transport. Other live parents need a complete
verified alias pair to prove same-transport endpoint disjointness, including
AF_PACKET (`afpacket`) lookup failures and cases with missing capture authority.
PCAP remains wire-coordinate evidence and never invents NAT mapping authority.
Full ports preserve unrelated verified mappings; host-pair loss can exclude
several mappings sharing translated hosts.

Loss scopes depend on the available authority:

| Code | Scope |
| --- | --- |
| `capture_loss` | Live transport overflow is retained synchronously at admission, even if Stop, deadline or policy change precedes worker processing. Overflow and IP truncation use wire five-tuple scope when ports are captured, otherwise host-pair/transport scope, matched against both verified NAT aliases or the common NFQUEUE forward-hook face. An already-indexed incarnation is retained as additional authority without waiting for a worker. |
| `capture_truncated` | Offline cut record or IP-length truncation: wire five-tuple when ports are captured, otherwise host-pair/transport. Missing IP coordinates, an unreadable EtherType or a header-less final record excludes the dataset. Opaque IPv6 extension chains remain conservative, not unrelated. |
| `watch_collection_loss`, `budget_exceeded` | Rejected decoded batch or parent: known connection incarnation; missing identity excludes the dataset, never just an observation-time interval. |
| `watch_restart`, `policy_changed` | Dataset-wide: wall-clock watch bounds cannot delimit packet timestamps after clock skew or capture lag. |
| `watch_storage_loss`, `import_failed`, `ingest_failed`, `interrupted_import`, `collection_loss` | Dataset-wide, including collector initialization/storage failure, legacy unlocalized gaps and exhausted loss-localization capacity. Failed automatic stops retry with their retained loss authority. |
| `outcome_loss`, `capture_unrelated` | Counted in `losses`, not `gaps`, without excluding certification inputs. Decision/delivery annotations, cut frames with a readable non-IP EtherType (including VLAN tags), and known non-TCP/UDP IP protocols cannot carry learner parents. |

A dataset retains at most 1,024 loss entries. Beyond that bound, localization
collapses to one dataset-wide `collection_loss`, rather than dropping exclusions.
Malformed but fully captured traffic is not a capture-loss signal.

See [Content identification](ics-dpi.md#content-identification) for protocol,
capture-mode, timing and coverage limits.

## Learner Evidence and Staging

All paths below are relative to `/api/v1`. Reads are available to viewers;
imports and all learner mutations require admin. The `/pcap` UI combines imported
captures and explicit live-watch datasets; it never commits policy.

| Request | Purpose / body |
| --- | --- |
| `GET /learn/datasets` | Dataset page |
| `GET /learn/datasets/{id}` | Dataset fingerprints, statistics, expiry and gaps |
| `GET /learn/datasets/{id}/observations` | Normalized parents with service/coordinate authority and quality |
| `DELETE /learn/datasets/{id}` | Delete evidence and invalidate dependent suggestions |
| `POST /learn/watches` | Explicit start: `{"durationSeconds":3600}`; omitted/0 means 1 hour, maximum 86400 seconds, one active watch |
| `GET /learn/watches` / `GET /learn/watches/{id}` | Watch page / status (never starts collection) |
| `POST /learn/watches/{id}/stop` | Stop collection and seal its dataset |
| `POST /learn/generate` | `{"datasetId":"<sealed-dataset>"}` → suggestion ID/revision pairs and withheld-reason counts |
| `GET /learn/suggestions?datasetId=<id>` | Filtered suggestion page |
| `GET /learn/suggestions/{id}` | Immutable rules, frozen replay proof, limitations, review and workflow revision |
| `POST /learn/suggestions/{id}/review` | `{"selection":{"id":"<id>","revision":2},"approve":true,"coordinateApproved":true}` |
| `GET /learn/counters` | Durable store-wide admission/loss/eviction/expiry and withheld totals |
| `POST /learn/apply` | Atomic selected staging, described below |

List pages use `{items, nextCursor?}` with optional `cursor` and `limit` (1–200,
default 200). Follow `nextCursor` until absent; an empty page has `items: []`.
Dataset deletion/expiry/eviction invalidates dependent proof. Retention and
protocol withholding limits are described in [Learning](ics-dpi.md#learning).

Selection is not review. IEC 104 always requires explicit admin review; a wire
suggestion also needs coordinate approval after checking pre-NAT capture scope
against deployment. A successful review increments the revision; use the returned
revision for staging. Every proposed rule is an explicit monitor ALLOW. CIP has
observations but no actionable suggestions.

Stage exactly the chosen immutable revisions with one request:

```json
{
  "requestId": "operator-batch-1",
  "selections": [{"id": "<suggestion-id>", "revision": 3}]
}
```

`POST /learn/apply` reloads certified content and atomically stages all selected
rules in candidate config. It accepts at most 128 unique selections / 128 total
rules, not arbitrary rule JSON. Success returns `{requestId, selections,
"staged":true}` and `X-Containd-Config: staged`; it does not activate policy.
Stale/conflicting/uncertified/review-required requests return `409` with the server
reason and no partial batch. Expired evidence returns `410`; unavailable evidence
returns `503`. Refresh suggestions after a refusal. If persistence succeeded but
completion failed, the candidate may already be staged: retry the same request ID
and exact ordered selections, never silently regenerate or use a new receipt.
After a proof-version upgrade, a frozen retry can reconcile only byte-identical
rules already in candidate; it cannot introduce missing rules, even from a
completed receipt. Regenerate under the current generator to stage new rules.

Use the normal candidate diff and commit workflow to apply monitor rules. To
allow traffic with a learned rule, explicitly change its candidate mode to enforce
and commit. A staged learner status is a receipt, not live activation telemetry.
Legacy `learned-*` overlap warnings never delete existing policy.

**Removed contracts:** `GET /learn/profiles` and bulk `DELETE /learn` are gone.
`POST /learn/generate` now takes a sealed dataset ID; `POST /learn/apply` no longer
regenerates/applies all observations. The internal profile and bulk-rule routes
are also removed. PCAP analysis no longer returns profiles, event summaries or
rules. Use datasets, suggestions, review and atomic selected staging instead.

## Rule Counters and Flow Tags

`GET /api/v1/firewall/counters` returns the kernel counters of the applied
ruleset: `snapshotVersion`, `since` (the apply time; every apply restarts the
counters at zero) and `rules`, one entry per firewall rule in configuration
order with `ruleId`, `action`, `packets`, `bytes` and, for `RATE_LIMIT` rules,
`excessDrops`. Logging need not be on. A failed apply leaves the installed
ruleset in force, and the counters keep reporting it. When enforcement is off,
nothing is applied yet or nftables cannot be read, the response is HTTP 502
with the reason; HTTP 503 means no live engine.

Flows that `TAG` rules match carry their labels as a sorted `tags` array in
event `attributes`, and each item of `GET /api/v1/conntrack` carries `tags`,
derived from the connection's original tuple under the running ruleset.
Kernel-logged `firewall.rule.hit` events (`via: nflog`) carry the labels of
their connection under the applied ruleset: the packet is oriented on the side
that opened the connection by its conntrack direction, so a logged reply gets
the same labels as its request. Their `flowId` names the packet's direction of
the connection, as engine flow events do. Each item of `GET /api/v1/flows`
carries `tags`, the sorted labels its events carry.

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
In combined `all` mode, the management `/metrics` serves these dataplane series
from the shared process registry. For split `engine`/`mgmt` processes, scrape the
engine listener's `/metrics` instead.

## Binary Runtime Environment

These are binary environment names, not Compose interpolation inputs.
Set them before starting the process; changing environment variables or flags
requires a restart. `SIGHUP` only reapplies the stored running configuration
described [above](#reload-running-configuration-sighup).
Listener defaults below apply when neither an environment override nor a saved
listener setting supplies a value.

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTAIND_MGMT_ADDR` | `:8080` | Management HTTP listen address |
| `CONTAIND_MGMT_HTTPS_ADDR` | `:8443` | Management HTTPS listen address |
| `CONTAIND_SSH_ADDR` | `:2222` | SSH console listen address |
| `CONTAIND_ENGINE_ADDR` | `127.0.0.1:8081` in `all`; required in `engine` | Engine API listen address. In `engine` mode, the engine's address on the management network (loopback only with a reserved management path) |
| `CONTAIND_ENGINE_URL` | Derived engine URL in `all` | HTTP for numeric loopback listeners, HTTPS otherwise; set an HTTPS origin explicitly for remote split processes |
| `CONTAIND_ENGINE_SECRET` | Unset | Dedicated shared 64-hex secret required for every non-loopback listener and HTTPS client; generate with `openssl rand -hex 32` |
| `CONTAIND_CONFIG_DB` | `data/config.db` | Configuration SQLite database |
| `CONTAIND_AUDIT_DB` | `data/audit.db` | Audit SQLite database |
| `CONTAIND_USERS_DB` | `data/users.db` | Users SQLite database |
| `CONTAIND_LAB_MODE` | Disabled | Lab authentication described above |
| `CONTAIND_JWT_SECRET` | Unset | Set a unique secret, e.g. `openssl rand -hex 32` |
| `CONTAIND_COOKIE_SECURE` | Automatic | Unset: Secure on HTTPS requests. `1` forces Secure; `0` disables it. Set `1` behind a TLS-terminating proxy. |
| `CONTAIND_TRUSTED_PROXIES` | `127.0.0.1,::1` | Comma-separated trusted proxy IPs/CIDRs for forwarded client addresses |
| `CONTAIND_ALLOWED_ORIGINS` | *(empty)* | Optional comma-separated browser origins allowed to embed or call the appliance cross-origin. Cookie-authenticated browser writes from other origins are denied unless listed here. |

Relative database paths are relative to the process working directory.
The engine API uses credential-free HTTP only on numeric loopback listeners.
Every non-loopback listener requires TLS 1.3 mutual authentication, including
probes and metrics. While enforcing, admission remains limited to loopback and
the bound address's interface. Keep its network private. See
[engine transport, credential export and rotation](docker-compose.md#engine-secret-and-rotation).

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

- `dpiMode` -- `"monitor"` (passive observation) or `"enforce"` (active policy
  enforcement), or empty (defaults to monitor); any other value is rejected.
  ICS rules that resolve to enforce need a nonzero `nfqueueGroup`.
- `dpiIcsProtocols` -- map of protocol name to boolean (e.g., `{"modbus": true, "dnp3": true, "cip": false}`)

See [DPI modes](ics-dpi.md#dpi-modes) for rule inheritance,
`GET /api/v1/firewall/shadow-counters`, migration and downgrade behavior.
Event queries accept `ruleId` and `mode`; use
`kind=ics.decision&ruleId=<id>&mode=monitor` for shadow evidence.


### Passive inventory

All inventory reads require management authentication:

| Method | Path | Result |
|---|---|---|
| GET | `/api/v1/inventory` | Retained Modbus/DNP3/CIP observations, one per IP, protocol and role, sorted by IP |
| GET | `/api/v1/inventory/{ip}` | All observations for an IP, sorted by protocol and role; 404 if none |
| GET | `/api/v1/inventory/iec104` | IEC 104 endpoint pairs, CAs, points, command counts, fixed limits and overflow totals |
| DELETE | `/api/v1/inventory` | Admin-only clear of both inventories and overflow counters |

An unavailable engine returns **503** with `{"error":"engine inventory unavailable"}`
for these operations, never a fabricated empty list. A reachable empty inventory
returns `[]` for the legacy list and `pairs: []` in the IEC 104 snapshot. The
engine feeds the IEC section from decoded traffic. Accepted command counts are
credited only in inline enforce mode, after the decision allowed the command and
every packet that carried it completed an Accept verdict; monitor mode records
attempts and points only. The read model does not generate policy.

The IEC response has this shape (a populated observation example):

```json
{
  "pairs": [{
    "controlling": "192.0.2.10:50000", "controlled": "192.0.2.20:2404",
    "firstSeen": "2026-10-26T12:00:00Z", "lastSeen": "2026-10-26T12:01:00Z",
    "attemptedCommands": 2, "acceptedCommands": 1,
    "cas": [{
      "ca": 1, "firstSeen": "2026-10-26T12:00:00Z", "lastSeen": "2026-10-26T12:01:00Z",
      "attemptedCommands": 2, "acceptedCommands": 1,
      "points": [{"ioa": 100, "typeId": 45, "firstSeen": "2026-10-26T12:00:00Z", "lastSeen": "2026-10-26T12:01:00Z"}]
    }]
  }],
  "limits": {"pairs": 128, "casPerPair": 32, "pointsPerCA": 256, "assets": 1024, "peersPerAsset": 128, "stationAddressesPerAsset": 256, "maxIdleSeconds": 86400},
  "overflow": {"observations": 0, "pairs": 0, "cas": 0, "points": 0, "assets": 0, "peers": 0, "stationAddresses": 0, "outcomes": 0}
}
```

Pair identity includes both endpoint ports; reconnects using different client
ports are separate pairs. Point identity is `(IOA, typeId)` within a CA. Times
are first/last observations, not delivery times. Attempted counts decoded
control-direction command APDUs (type IDs 45–51 and 58–64); accepted additionally
requires successful delivery verdicts for all carrying packets. A pending or
failed command is not accepted. Pair totals may exceed the sum of retained CA
totals after CA eviction. Counts do not represent lifetime traffic.

Entries use least-recently-observed eviction and 24-hour idle expiry. Overflow
counts capacity evictions or truncated observations, not unique devices;
`observations` counts observations dropped on inventory lock contention;
`outcomes` counts final outcomes dropped on contention or for expired/evicted
observations. Input calls never wait for readers or other writers.
Counters survive evictions and reset on clear/restart. Reads do not extend
retention. The internal engine read is
`GET /internal/inventory?section=iec104`; it uses the existing inventory handler.
See [ICS DPI](ics-dpi.md#passive-iec-104-inventory) for UI and retention details
and [OpenAPI](#openapi-specification) for the complete response schemas.
