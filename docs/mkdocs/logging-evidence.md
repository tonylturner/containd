# Logging and Intrusion Evidence

## Evidence sources and storage

- Administrative audit records persist in SQLite. `CONTAIND_AUDIT_DB` defaults
  to `data/audit.db` for the binary; the container deployment uses `/data/audit.db`.
- Firewall, DPI, IDS, AV, proxy, and service events are exposed through
  `GET /api/v1/events`. Engine event history is bounded and in memory, not an
  audit database or a durable delivery queue.
- Management and engine application logs go to stdout. Embedded service managers
  also configure JSON files under `/data/logs/`: `proxy.log`, `dns.log`, `ntp.log`,
  `dhcp.log`, `vpn.log`, `av.log`, and `syslog-forwarder.log`. These file sinks
  depend on a writable directory; generic `NewService` application loggers do not
  configure a file path. `CONTAIND_LOG_FILE=0` disables configured file sinks.
- `GET /metrics` exposes Prometheus metrics, not a replacement for event evidence.

File rotation defaults are **20 MB per file, 5 backups, and 7 days**. These are
library defaults for configured files, not a guarantee of complete retention.
`CONTAIND_LOG_LEVEL` and `CONTAIND_LOG_LEVEL_<SERVICE>` control application log
levels. CLI queries include `show audit` and `show events`; see
[API Reference](api-reference.md) for wire contracts.

## Account and credential audit records

Every account and credential change writes an audit record with its actor and
source (`api` or `ssh`). Refused logins and own password changes with a wrong
current password are recorded with result `denied`.

| Action | Change |
| ------ | ------ |
| `auth.login` | Web/API logins, wrong passwords and wrong TOTP codes |
| `ssh.login`, `ssh.logout` | SSH logins and logouts, wrong TOTP codes and logins refused after the MFA enrollment grace period |
| `auth.user.create`, `auth.user.update`, `auth.user.delete` | User creation, profile or role change, and deletion |
| `auth.profile.update` | A user's change to their own profile |
| `auth.password.change` | A user's own password change, on the web/API, the SSH menu or wizard, or at a forced SSH login change |
| `auth.password.set_admin` | An admin setting another account's password |
| `auth.mfa.*` | MFA enable, disable, requirement, grace and admin reset |
| `ssh.authorized_key.add` | SSH key enrollment in the setup wizard, with the key fingerprint |
| `system.tls.cert.set`, `system.tls.trusted_ca.set` | Management TLS certificate and additional CA bundle replacement |

## Off-box forwarding

Two working syslog paths are distinct:

- **Service event forwarder**: `services.syslog.forwarders` sends polled engine
  and service telemetry over UDP or TCP. `services.syslog.format` selects JSON or
  RFC5424 output. Retries/backoff and status counters expose failures; this is
  best-effort forwarding, not a durable acknowledged stream. Bounded polling,
  mixed event-source IDs, and failures can leave gaps. Audit database rows are
  not automatically part of this telemetry feed.
- **Application logger sink**: `CONTAIND_LOG_SYSLOG_ADDR` and
  `CONTAIND_LOG_SYSLOG_PROTO` add a remote sink to shared structured loggers.
  The default protocol is UDP; TCP and Unix sockets are also supported. These
  logs are not the complete DPI event stream. Verify reception at the collector.

The top-level `export` configuration and `pkg/dp/export` CEF/JSON/Syslog library
are **not wired into the runtime**. Setting that configuration does not export
DPI events to a SIEM or to a file/UDP/TCP target. Do not use it as an evidence
preservation mechanism. Use the working syslog paths for their documented
sources and retrieve event queries explicitly for other evidence.

## Retention checklist

1. Choose an external collector and retention period; test delivery and inspect
   forwarder status rather than assuming an empty collector means no activity.
2. Preserve audit databases and configuration backups through upgrades.
3. Retrieve relevant event pages before process restarts, bounded-cache eviction,
   or destructive lab resets. Pagination cannot recover already lost events.
4. Review authentication, config commits, and service failures alongside packet
   evidence. Metrics can reveal health regressions but cannot reconstruct events.

## Bounded IEC 104 incident evidence

In addition to the configurable general ring (4096 rows by default) and the
independent 1024-row firewall DENY bank, each event store protects **128 IEC
incident sessions, at most 32 rows per session** (4096 additional event slots).
The retained-bank bound is general capacity + 5120 event slots (9216 by
default); the unchanged optional spill queue holds up to 1024 further rows.
Maps and ordering indexes
are bounded by 128 sessions. Payload size follows the producer's event bounds;
this is a row/reference bound, not a fixed byte-size allocation.

Protected evidence includes `ics.decision` deny/would_drop, `ics.verdict`
(including dropped/drop_failed), and `ics.session` aborted/reset_sent/reset_failed/
enforce_unhealthy. Sessionless unhealthy outcomes share one bounded bundle.
Decoded attempts for implicated `apdu_id`/`apdu_ids`/`trigger_apdu_id` are copied
from the general ring when the incident arrives, or retained when recorded after
the decision. Routine allowed GI/monitor objects do not enter this bank. Event
IDs and payloads are preserved and query results deduplicate by ID. Flow rollups
and the general ring are unchanged.

Overflow evicts the oldest-created incident bundle as a whole; a session with
more than 32 evidence rows loses its oldest retained rows. The firewall bank
still evicts only on DENY overflow. No age expiry or durable retention applies;
configuration rebuilds preserve stores, process restarts do not. Already-evicted
decoded context cannot be recovered. Small priority-selected pages can omit
context: narrow by session and use a sufficiently large page. Retrieve and
preserve evidence off-box before eviction or restart; the built-in cache and best-effort syslog forwarding cannot promise a complete, durable
session history.


## Search a session before applying the page limit

`GET /api/v1/events?session=<session_id>&limit=500` searches **all retained**
engine evidence and service rows before limiting. It returns:

```json
{"events": [], "historyTruncated": true, "nextCursor": "opaque-older-bound"}
```

`nextCursor` is omitted when there are no older retained matches. Send it as
`cursor` with the same filters for the next older page. Query pages sort by
(timestamp, ID), newest first, with no DENY priority. Filters combine with AND:

- `id`: exact event ID (also used by event-detail lookup before limiting)
- `session`: exact IEC `attributes.session_id`
- `flow`: exact `flowId` or `session_id` (both wire directions of that incarnation)
- `apdu`: exact `apdu_id`, `trigger_apdu_id`, or member of `apdu_ids`
- `kind`: case-sensitive prefix; comma-separated prefixes combine with OR
- `protocol`: case-insensitive `proto` equality
- `decision`: case-insensitive `attributes.decision` equality
- `verdict`: case-insensitive `attributes.outcome` or `attributes.action` equality
- `since`: inclusive RFC3339 timestamp, optional fractional seconds
- `cursor`: opaque exclusive upper bound on (timestamp, ID)

Limits are 1–5000 (default 500); invalid limits/bounds return 400. `query=1`
requests a chronological query page without narrowing. With no query/filter
parameters, `?limit=N` still returns the legacy **bare event array**, with
evidence-priority selection.
The engine endpoint `/internal/events` and management client share this contract.

`historyTruncated` conservatively warns of possible gaps: any general or protected
bank overflow sets it for the current store lifetime. Service event stores expose
no overflow metadata, so merged service history is conservatively marked too.
It is not a per-session loss counter; false does not certify evidence from a
previous process lifetime. Pagination is not a snapshot, cannot recover evicted
rows or read spill files, and cannot prove that an empty query is a complete
incident record. Engine failures are carried separately as `engineError`, even
when no rows match; the Events page and CLI display this warning.

The Events page sends its filters to the server, including session/flow deep links:
`/events/?filter=iec104&session=<session_id>` or `/events/?flow=<flowId>`.
Use **Pause**, then **Load older evidence** to retain the current page while
fetching older matches. Live polling/Refresh starts a fresh newest page.

CLI examples (prefix flags with two hyphens):

```text
show events --session <session_id> --protocol iec104 --limit 100
show events --flow <flowId> --kind ics. --since 2026-01-01T00:00:00Z
show events --session <session_id> --decision deny
show events --session <session_id> --verdict drop_failed
show events --session <session_id> --cursor <nextCursor>
show events --query --limit 100
```

The CLI prints a next cursor and gap/engine warnings when present. Decision and
outcome filters intentionally narrow evidence: omit them to inspect the whole
retained session chain (decoded attempt → deny → drop → abort/reset). A decoded
command is an attempt, not an actuation; a policy allow is not delivery proof.
