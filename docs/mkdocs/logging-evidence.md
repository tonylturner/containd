# Logging and Intrusion Evidence

containd is meant to help operators understand what happened, not just enforce policy.

## Built-in Evidence Sources

Relevant built-in sources include:

- **audit log** for administrative and sensitive management actions
- **events** for firewall, DPI, IDS, AV, proxy, and service activity
- **service/runtime logs** from the management and service processes
- **syslog forwarding** and **event export** for off-box handling
- **Prometheus metrics** for operational monitoring and trend detection

## What containd Logs by Default

By default, the appliance records:

- administrative actions in the audit database (`CONTAIND_AUDIT_DB`, default `/data/audit.db`)
- runtime events exposed through `/api/v1/events`
- service and management logs on stdout, with optional rotating file logs under `/data/logs/`

Structured application logging uses the shared logging layer in [`pkg/common/logging`](https://github.com/tonylturner/containd/blob/main/pkg/common/logging/logging.go). Default file rotation settings are:

- 20 MB per file
- 5 backups
- 7 days retention

These defaults are for convenience, not a universal compliance statement.

## Key APIs and Outputs

- `GET /api/v1/audit` — administrative audit records
- `GET /api/v1/events` — normalized security and telemetry events
- `GET /metrics` — Prometheus metrics
- service-specific status and event surfaces in the System and Monitoring pages

For CLI users:

- `show audit`
- `show events`

## Off-box Forwarding

For stronger environments, containd should not be the only place logs live.

Recommended pattern:

1. Forward normalized events or syslog to an external collector.
2. Preserve config backups and the audit database during upgrades.
3. Export or snapshot relevant evidence before destructive lab resets.
4. Use metrics to detect health regressions even when you are not tailing logs directly.

Relevant controls already present:

- service syslog forwarders under `services.syslog`
- event export in CEF, JSON, and Syslog formats
- optional remote syslog sink for structured logs via `CONTAIND_LOG_SYSLOG_ADDR` and `CONTAIND_LOG_SYSLOG_PROTO`

## Recommended Lab Posture

For classroom and lab use, a good minimum posture is:

- keep audit logging enabled
- forward syslog/events when the lab design allows it
- preserve evidence for the duration of the exercise
- review audit and event timelines as part of the teaching workflow

This matters because containd is often used to teach secure operations. A lab that drops all evidence on the floor teaches the wrong habit.

## Recommended Production-style Posture

For more serious deployments or longer-lived labs:

- treat audit and event data as operational records
- forward evidence off-box
- preserve evidence through upgrades
- define your own retention period based on organizational needs
- review authentication, password change, MFA, config commit, and service failure events regularly

## Current Gaps and Limits

containd provides useful evidence surfaces, but operators still need to decide:

- where long-term retention lives
- which logs are authoritative in their environment
- whether external SIEM / log management is required

The project documents the built-in capabilities, but evidence handling policy remains an operator responsibility.

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
context: narrow by session and use a sufficiently large page. Export evidence
off-box for a complete, durable record; this bounded cache cannot promise an
unlimited session history.


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
parameters, `?limit=N` still returns the **bare event array** expected by
RangerDanger and other existing callers, with evidence-priority selection.
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
