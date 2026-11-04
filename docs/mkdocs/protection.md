# Runtime Protection

Configuration storage, policy installation and verified runtime protection are
distinct observations. Management stays reachable for repair when protection
is not ready. Routes below are relative to `/api/v1` and require authentication
unless explicitly stated otherwise.

Commit, commit-confirmed, rollback and factory reset success bodies include
`{status, runningRevision, applyId, protection}`. Reset also retains its logout,
message and warning fields. Confirm remains `{status:"confirmed"}`: it does not
apply runtime. `runningRevision` identifies committed running intent, including
its IDS bank, independently of whole-state CAS. Candidate edits and confirmation
do not change the protection target. Boot reconciliation and retries can use a
fresh `applyId` for the same running generation; rollback and compensation assign
fresh running generations even when restoring earlier content. All identities
are opaque equality-only tokens, not clocks or sortable versions.

Synchronous success means **Configuration committed**, not **Protecting**. Inspect:

- **Desired configuration** (`desiredRevision`): committed intent; null without a
  desired running document.
- **Policy installed** (`appliedRevision`): owner-proven installed policy; may be
  older than desired. This is not proof that every required owner converged.
- **Protecting now** (`protectingRevision`): desired generation verified now;
  null unless `ready` is true. Null means **Not verified**, never last-ever success.

`ready` requires matching boot, attempt, revision and owner acknowledgements for
all required operations, including verified teardown of disabled traffic services
(VPNs and proxies). Requirements come from original desired policy, not its
quarantined projection. DNS, NTP, syslog and DHCP faults remain visible and
retryable but never gate ready. Missing telemetry, supersession, recovery,
disabled enforcement, uncertain delivery, degraded rule-hit logging or schedule
degradation cannot certify clean readiness. Packet effects remain independent
engine observations; API transport success never infers them.

When scan selection is active, protection follows live AV readiness. Losing
clamd or ICAP removes `protecting` without a commit; recovery requires an EICAR
canary detection in every selected direction, not merely a successful connection
or ICAP `OPTIONS` response. NFLOG logging retries independently of NFQUEUE capture;
a queue not required by installed policy does not itself block protection.
Unavailable rule-hit logging means `degraded` and `ready: false`, even while nft
policy still enforces packets.

A policy-referenced zone with configured rows but no existing kernel device is
also degraded and not ready. Its reason names the zone and rows, for example
`zone lan has no attached interface: lan1`. Rows attach only to identically named
devices; missing parents/members defer VLAN/bridge creation. This is live state,
not a delivery failure: other rows continue, no rollback occurs, and attachment
reconciliation clears the fault when a device appears. A link that exists but is
down is distinct from a missing device; failed discovery is unknown, not missing.

- `GET /dataplane/protection` (any authenticated user) returns the aggregate
  `state`, `ready`, the three nullable revisions and `subsystems` (always an array),
  alongside engine-observed `bootId`, `applyId`, `installedApplyId`,
  `runningRevision`, `mode`, nullable `installed` acknowledgement, `observedAt`,
  `components`, `effects` and `retryable`. Raw IDs stay empty when unknown; they
  are never filled with a planned attempt. Top-level `retryable` describes the
  raw engine, not outstanding service work.
- Each subsystem has `name`, `owner` (`engine` or `management`), `desiredRevision`,
  `operation` (`apply`, `stop`, or empty when unknown), `state`
  (`pending`, `ready`, `failed`, `off`, `unknown`), nullable `acknowledged` and
  `fault`, `reason`, `attempt`, nullable `nextRetryAt`, `observedAt`, `retryable`
  and server-derived `required`. Trust also reports `desiredTrustRevision` when
  known. Acknowledgements bind `bootId`, `applyId`, `runningRevision`, `mode`,
  `operation` and, for trust, `trustRevision`. Faults contain sanitized `kind`
  (`config`, `render`, `delivery`, `unknown`) and `reason`. Config/render faults
  require input repair; ordinary delivery faults retry automatically.
- Components retain `name`, `required`, `state`, `reason`, `since`, and optional
  bounded `attempt`/`maxAttempts`. Effects retain `traffic` and `effect`
  (`normal`, `fail_closed_drop`, `not_inspected`, `unknown`). HTTP 200 means an
  observation was collected, including not-ready/unknown results. Collection
  failure, including an unavailable engine, returns 502 with an unknown,
  not-ready aggregate. A missing runtime coordinator returns 503.
- `POST /dataplane/protection/retry` (admin) requires exactly
  `{bootId, applyId, desiredRevision}` from the inspected authenticated status.
  Each token is 1–64 ASCII letters, digits, `_` or `-`. Unknown fields, extra
  JSON and missing/invalid tokens return 400. Current targets return 202
  `{status:"retrying",applyId,desiredRevision}`; acceptance coalesces work, does
  not wait for an engine round trip and is not completion. Stale or uncertain
  targets return 409 with `code: protection_superseded`: refresh, do not silently
  retry a different target. Other retry failures return 502; a missing coordinator
  returns 503. Authentication/role failures remain 401/403. The action is audited
  as `dataplane.protection.retry`. No CAS header is required or acknowledged.
  Retries target outstanding owners, preserving healthy AV, WireGuard and DHCP;
  the raw engine `retryable` bit does not determine whether service work exists.

`/health` remains unauthenticated HTTP 200. Its `protection` object contains only
`{state, applyId}`, never revision-ledger or owner-fault details. It is
liveness/enforcement telemetry, not the authenticated readiness certificate.
`enforcement` maps `protecting` to `enforcing`, `pending`/`failed` to `unavailable` with fixed reasons
"protection pending"/"protection failed", `degraded` to `degraded` with reason
"rule-hit logging unavailable; nft policy enforcing", `disabled` to `disabled`,
and unreadable or stale observations to `unknown`. Persisted apply faults and
management recovery still override protection; schedule planner degradation
still overrides enforcing. Neither raw kernel errors nor private policy text
appear in health reasons. Topology and firewall/ICS indicators retain the health
reason when a health-only override applies while datapath protection is healthy,
rather than explaining a degraded state as "Protecting".
