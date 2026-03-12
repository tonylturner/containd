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
