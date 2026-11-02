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
`CONTAIND_LOG_LEVEL` and `CONTAIND_LOG_LEVEL_<SERVICE>` set levels for loggers
without an explicit level. The embedded service managers explicitly use `info`,
so these variables do not override their levels. CLI queries include
`show audit` and `show events`; see
[API Reference](api-reference.md) for wire contracts.

## Collect and review learner evidence

**PCAP Analysis** (`/pcap/`) offers **Import capture** and **Watch live** tabs.
Import capture contains Upload & Analyze PCAP and Existing PCAP Files; Watch live
contains duration, Start watch, watch status, Stop watch and pagination. An active
watch or unavailable watch status remains indicated when viewing Import capture.
Abnormal stops (including restart, budget and policy change) also show their
cause there, with an **Inspect watch** link that opens and focuses the affected
watch. Ordinary operator and deadline stops remain in watch history without an
extra warning.
Switching tabs does not start, stop or discard a collection.
The selected collection tab is underlined as well as highlighted.

The learner steps are explicit: **1 Collect → 2 Generate → 3 Review → 4 Stage**.
Steps explain action prerequisites. Once a dataset is open, all step navigation
remains available, including for viewers and expired evidence; only the actions
are permission- and eligibility-gated. Opening a step only navigates to its
controls: it does not generate, approve, select or stage anything. Expired datasets
cannot generate new suggestions; collect new evidence instead.

The selected Dataset review stays above the retained Evidence datasets list.
Collection details retains its full ID, checksums and reader/configuration
versions. Review uses a compact table with service descriptions, exact
address/service scope and **Checks passed**, **Needs review** or **Not eligible**;
these are bounded checks, not proof that traffic is safe. **Inspect suggestion**
expands approval controls, proposed rules and evidence. Checks on saved evidence
retains replay and boundary results, limitations, raw versions, digests and
counterexamples.
Collection gaps, failure causes, overlaps, expiry and selection restrictions stay
visible. Import statistics and content identifications remain available below.
Withheld reasons explain why a relation cannot be generated and what to check or
collect next; unknown codes remain visible as **Unrecognized reason (code)**.
Administrators can **Delete dataset** from Evidence datasets after confirmation.
Deletion is immediate, requires a sealed dataset and removes its observations and
dependent suggestions/proofs. Stop a collecting watch first. It does not remove
already staged rules or the original PCAP file, and requires no commit.
Missing, invalid or zero-value evidence timestamps display **Unknown**; this
does not change expiration checks or staging eligibility.
**Inspect service authority** and its pagination remain available during staging;
reading authority does not unlock mutation controls or dismiss a staging failure.

**Stage N selected** stays separate from approval and selection. IEC 104 review,
address/NAT approval where required, the 128-suggestion/128-rule cap, destination
diff review and atomic monitor-only staging remain required. A failed or
uncertain staging attempt retains its receipt when retry is permitted:
**Retry same staging request** sends the identical request. **Discard receipt**
does not undo any rules already saved. Staged rules are not activated until
Configuration review and commit. Store-wide counts and saved evidence limits
remain in their disclosures; they are not per-dataset completeness guarantees.

## Account and credential audit records

Account and credential changes attempt to persist an audit record with their actor
and source (`api` or `ssh`). Audit persistence failure does not block the operation;
check the persistence status below for missing evidence. Refused logins, own
password changes with a wrong current password and refused MFA changes are recorded with result `denied`.
Records never hold the password or code that was tried.

| Action | Change |
| ------ | ------ |
| `auth.login` | Web/API logins, wrong passwords and wrong or reused TOTP codes |
| `ssh.login`, `ssh.logout` | SSH logins and logouts. Refused: unknown or non-admin account, wrong password, unauthorized key (with its fingerprint), wrong or reused TOTP code, wrong current password at a forced change, and expired MFA enrollment grace |
| `auth.user.create`, `auth.user.update`, `auth.user.delete` | User creation, profile or role change, and deletion |
| `auth.profile.update` | A user's change to their own profile |
| `auth.password.change` | A user's own password change, on the web/API, the SSH menu or wizard, or at a forced SSH login change |
| `auth.password.set_admin` | An admin setting another account's password |
| `auth.mfa.*` | MFA enable, disable, requirement, grace and admin reset. Refused: a wrong code at enrollment, and a wrong password or a wrong or reused code when turning MFA off |
| `ssh.authorized_key.add` | SSH key enrollment in the setup wizard, with the key fingerprint |
| `system.tls.cert.set`, `system.tls.trusted_ca.set` | Management TLS certificate and additional CA bundle replacement |

Refused SSH keys are collected into one record per account when a connection
ends without logging in, since clients offer every key they hold. Failed
credentials count against the login limit for their client address and account:
10 failures within one minute, then 2 minutes blocked. Blocked attempts write no
record, so sustained bad-credential attempts against one account from one address
write about 5 records a minute. An expired MFA-enrollment grace refusal after
correct credentials is recorded without incrementing that limit. Each new account
name or address starts its own count. Lab mode writes no refused-SSH or
refused-MFA-change records.

## Off-box forwarding

Two working syslog paths are distinct:

- **Service syslog forwarder**: `services.syslog.forwarders` sends polled engine
  and service telemetry over UDP or TCP. `services.syslog.format` selects JSON or
  RFC5424 output. Retries/backoff and status counters expose failures; event
  forwarding is best effort with retries, not a durable acknowledged stream.
  Each source (engine, services, audit) has independent progress per destination;
  one failed collector does not suppress another collector or source. The same
  forwarders also carry audit records; see [Audit records over syslog](#audit-records-over-syslog).
- **Application logger sink**: `CONTAIND_LOG_SYSLOG_ADDR` and
  `CONTAIND_LOG_SYSLOG_PROTO` add a remote sink to shared structured loggers.
  The default protocol is UDP; TCP and Unix sockets are also supported. These
  logs are not the complete DPI event stream. Verify reception at the collector.
  If syslog initialization fails, application loggers keep stdout logging and
  report the failure once per logger initialization to stderr, even when the
  configured log level would suppress a warning.

### Audit records over syslog

Every syslog forwarder also sends the audit database's records, oldest first,
in the configured format:

```text
<109>1 2026-10-26T09:14:03Z fw1 containd - audit [audit@47450 id="42" actor="admin" source="api" action="config.commit" target="running" result="success" detail=""] admin config.commit running: success
{"kind":"audit","host":"fw1","id":43,"timestamp":"2026-10-26T09:14:09Z","actor":"eve","source":"api","action":"auth.login","target":"eve","result":"denied","detail":"invalid credentials"}
```

- RFC5424 messages use MSGID `audit`, facility 13 (log audit), severity notice
  for `success`, `ok` and `requested` results and warning otherwise. JSON
  messages carry `"kind":"audit"`. Event messages never use either marker.
- Detail is cut to 1024 bytes, target to 256 bytes and the other fields to 128
  bytes; a cut ends in `…`. Control characters are escaped, so a value cannot
  start a new line or message.
- Each forwarder keeps a cursor, the last audit ID it delivered, in the audit
  database. A forwarder is identified by protocol, address and port. Failed
  delivery keeps the cursor and the next flush retries, so records sent during
  a collector outage or before a restart are retried later. A batch holds at
  most `services.syslog.batchSize` records per forwarder and flush.
- Forwarding attempts are at least once: after a crash a collector can receive
  a record twice. Use `id` to deduplicate; IDs keep increasing, also across a factory
  reset. TCP delivery means the local TCP stack accepted the message; UDP has
  no delivery signal.
- A newly configured forwarder starts after the newest record and does not
  replay history. Removing a forwarder deletes its cursor. A factory reset
  wipes the records and rewinds the cursors, so records written afterwards are
  forwarded. Changing format alone retains progress.

`GET /api/v1/services/status` reports `syslog.audit`: `enabled`, `sent_total`,
`failed_total`, `last_error`, `last_flush`, total `backlog`, and per forwarder
`forwarder`, `last_id`, `backlog` (records not yet delivered), `last_error`
and `last_sent`. A growing backlog means delivery is falling behind.
`last_error` can indicate a transport or local database/cursor failure; it does
not by itself prove a collector failure. The CLI command `show syslog status`
prints the same fields.

### Telemetry retries and visible loss

New destinations start at each source's current tail: **no backfill**. Retained
telemetry is retried after transport failures. If a record leaves the bounded
source feed before delivery, it counts as `lost`; serialization drops also count.
The forwarding feed is append-ordered, separate from the priority incident banks
used for event browsing. Keeping an incident in the UI does not guarantee it
remains in the forwarding feed.

Engine and service telemetry progress is in memory. Management restart starts
fresh telemetry tails, not a durable replay. A source epoch change resumes from
its earliest retained records and records a continuity gap. Known pending losses
are counted, but activity across unobserved downtime cannot be counted exactly.
Do not interpret `lost: 0` as proof of uninterrupted history.

`GET /api/v1/services/status` reports `syslog.events`, one row per destination and
engine/service source: `backlog`, `sent`, `failed`, `lost`, `continuity_unknown`,
`epoch`, decimal-string `offset`, `last_error` and `last_success`. Syslog in the UI
and `show syslog status` display these counters. Failed attempts and loss remain
visible after delivery recovers. Audit forwarding has its separate durable
cursor and backlog, not a bounded telemetry-loss counter.

Telemetry event IDs are exact decimal **JSON strings**, including event lists,
detail, preview samples and syslog JSON. Preserve them as strings in consumers:
`"9223372036854775809"` and `"9223372036854775810"` are distinct IDs. Audit record
IDs remain numeric. RFC 5424 telemetry includes ID, source, epoch and offset in
escaped structured data. Local transport acceptance does not prove collector
receipt, including over TCP; verify reception off-box.

## Audit persistence and evidence health

`GET /api/v1/evidence/status` is available to authenticated readers, even with no
syslog collectors. `audit` reports local SQLite persistence: `state`, `failures`
since process start, optional `lastFailureAt`, `lastSuccessAt` and sanitized
`lastError`. `forwarding` reports per-destination/source state, decimal-string
`sentThrough`, retained `backlog`, known `lost`, and optional last error/success.
This is separate from the learner-evidence dataset API.

- `ok`: the observed path works, without recorded failure or loss.
- `degraded`: the most recent attempt failed.
- `recovered`: it works again after a failure or known loss; history still needs
  review. Recovery does not recreate missing records.
- `unknown`: observation is unavailable; completeness cannot be certified.

Unauthenticated `GET /api/v1/health` adds only `evidence: {state}` (no errors or
destinations), taking the worst state: degraded, unknown, recovered, then ok.
HTTP 200 remains liveness, not evidence completeness. The shell banner points to
Audit persistence and Syslog delivery when attention is needed. The Audit page
shows persistence separately from its records; an empty table is not proof that
no administrative actions occurred. `show audit --status` exposes persistence
and forwarding state in the CLI; `show audit` retains the bare record view.

Operations continue if an audit write fails. Neither a successful operation nor
recovered persistence certifies that its audit record was stored. Monitor the
status and preserve the database; there is no audit fail-closed mode.

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


## Triage in the web UI

The dashboard shows all four First-Run Checklist tasks, including completed
ones. Network Pulse, Zone Status, Service Health, Traffic, Event Stream and
System Health stay visible alongside attention and failure notices. Open
Monitoring for live investigation. The header holds the SIM toggle; simulation
controls act immediately, not on commit. CLI Console opens on demand below
the panels.

Events keeps timestamps, endpoints, activity and protection evidence visible.
Advanced event filters holds exact IDs, protocol, decision, outcome, time and
cursor bounds, and opens when a deep link fills them. Inspect event keeps
Message and session details, Event attributes (JSON), and the Event ID lookup
with Download event JSON. Retention warnings and failure causes always show.

The Alerts Protection outcome separates detection from would-block, deny
decisions, reported packet drops and reset failures. A deny decision alone does
not prove that a packet was dropped. Select a message with the pointer or
keyboard to open its full protocol, packet and reference detail; Close returns
to that message.

Flows are observed conversations; Sessions lists kernel connections. Inspect
flow shows exact IDs, Tags and First Seen. Inspect connection shows Mark, Tags,
Assured, TTL and Reply tuple (NAT). Session Kill stays immediate and keeps its
exact-connection or client-service scope, revocation interval and confirmation.

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
