# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- While enforcing, the unauthenticated engine API is admitted only from
  loopback and, when `CONTAIND_ENGINE_ADDR` names one address, on that
  address's interface. TCP 8081 is no longer accepted on every interface.
- Firewall rules with identity or schedule predicates no longer compile to
  always-on rules. A predicate that cannot be evaluated resolves toward denial:
  such an ALLOW rule is inactive and such a DENY rule always applies. Schedules
  still apply to ICS rules inspected through NFQUEUE. The maintenance-window
  template's scheduled allows are inactive. Affected rules are listed as
  warnings in the engine ruleset status, in `GET /api/v1/dataplane/ruleset`
  (`warnings` and `engineStatus.warnings`) and in the firewall page's ruleset
  preview. The rule impact preview and the userspace evaluator decide these
  rules the same way, and the evaluator admits by default only when the
  firewall default action is exactly `ALLOW`.
- New and factory-reset configurations no longer include the `allow-mgmt-ui`
  firewall rule. It never governed management access, but it allowed any
  forwarded traffic to tcp/8080. Existing configurations keep it; delete it
  unless you need forwarded tcp/8080 from every zone.
- The SSH console no longer echoes new passwords. The menu reset and the
  setup wizard ask twice and refuse a mismatch.
- The web console's internal API calls over HTTPS verify the management
  certificate and pin it, instead of skipping verification. The console never
  falls back to the request's Host header and refuses redirects.
- Release SBOMs are signed CycloneDX attestations bound to each image digest,
  and promotion verifies them. The management SBOM includes the UI's production
  npm packages. A manual release run can no longer move `:latest` to an older
  version.
- Bind the unauthenticated engine API to `127.0.0.1:8081` by default in combined
  mode and starter/dev Compose; explicit `CONTAIND_ENGINE_ADDR` overrides still
  apply, and split engine mode retains `:8081`. Management derives its local
  engine URL from the same listener setting, including with a reservation.
- Update Next.js to 15.5.28 and PostCSS to 8.5.31, clearing the critical and
  high npm advisories in the UI build.
- Upgrade the UI to Tailwind CSS 4.3.3 with no visual change. `npm audit`
  now reports no vulnerabilities.
- A firewall rule scoped to `vpn:*`, `vpn:wireguard` or `vpn:openvpn` no
  longer matches every address when that VPN is not configured. A source or
  destination that resolves to no address now matches nothing, so the rule has
  no effect until the VPN is configured.
- With NFQUEUE, a Modbus or DNP3 connection covered by an enforce ICS rule is
  dropped and blocked for 10 minutes when its TCP stream cannot be inspected:
  conflicting or rewritten retransmitted bytes, framing the decoder rejects,
  reassembly limits, or a decoder fault. Before, inspection restarted at a
  later segment and a prohibited command could pass. An `ics.decision` event
  with reason `stream_error` or `decoder_panic` names the rule. Learn mode and
  IEC 104 are unchanged.
- Validation refuses a firewall rule that names an ICS protocol and is in
  effective enforce mode while `dataplane.nfqueueGroup` is 0. Without an
  inline path the first prohibited command reached the device while the UI
  showed "enforce". Set a queue, or set the rule's `ics.mode` to `learn`.
  Rules without an ICS protocol and a global `dpiMode: enforce` alone stay
  valid. `dataplane.dpiMode` accepts only `learn` or `enforce`.

### Added

- Syslog forwarders also send audit records, oldest first, as JSON
  (`"kind":"audit"`) or RFC 5424 (MSGID `audit`). Each forwarder keeps a
  cursor in the audit database, so records written during a collector outage
  or before a restart are delivered later; a new forwarder starts at the
  newest record. `GET /api/v1/services/status` reports the audit backlog and
  last error per forwarder under `syslog.audit`.
- The ruleset status reports schedule planner health (last refill, horizon
  end, last error). A failing refill, or a schedule horizon within an hour of
  its end, makes enforcement health `degraded`.
- Kernel-logged `firewall.rule.hit` events carry TAG labels and a
  per-direction `flowId`, and `/api/v1/flows` items carry `tags`.
- Web UI: RESET, RATE_LIMIT and TAG rule actions with rate limit and tag
  fields; rule identities and schedules; an Identity Bindings page; per-rule hit
  counters; connection tags on Sessions; unbound-identity and shadowed rule
  warnings; and boot recovery state with or without a management reservation.
- The engine image ships ClamAV, FreshClam and CA roots. The engine renders
  and supervises clamd and a single FreshClam schedule, reports live readiness
  and the definitions version, and validates custom definitions before
  activating them with a clamd reload. ICAP `useTls` uses verified TLS 1.2 or
  newer with no plaintext fallback.
- The Sessions page and `GET /api/v1/conntrack` show the kernel's real IPv4
  and IPv6 connections, including NAT reply tuples, and report an unavailable
  backend as an error instead of an empty list. Kill now works for TCP and UDP:
  it deletes the connection and refuses reconnects for a chosen interval
  (1–3600 s, default 60 s), for the exact connection or the client's service.
- DPI domain exclusions now work: a flow is excluded when its TLS SNI or an
  observed DNS answer for its server address matches an exact name or a
  `*.suffix`, decided at the first client payload. IEC 104 is never excluded
  by domain. Invalid domain values are rejected at commit.
- IEC 104 holdback-pressure diagnostics: a Diagnostics panel, a read-only
  `GET /api/v1/diagnostics/iec104` API and `containd_dp_iec104_*` Prometheus
  series show held packets and bytes, oldest pending age and sessions against
  the fixed limits, plus abort reasons and failure totals. They separate denied
  commands from queue pressure.
- Passive IEC 104 inventory: a read-only section on the Assets page and
  `GET /api/v1/inventory/iec104` list controlling and controlled station pairs,
  their common addresses, IOAs and type IDs, first and last seen, and command
  attempt and acceptance counts, fed from decoded traffic. A command counts as
  accepted only in inline enforce mode, after it was allowed and every packet
  carrying it completed an Accept verdict. Fixed caps, LRU eviction, 24-hour
  idle expiry and overflow counters bound it. It never feeds the learner or
  auto-ALLOW.
- Observational IEC 104 APCI alerts: I-frames outside STARTDT/STOPDT (one per
  stopped period), N(S)/N(R) gaps, backward steps or ACKs of unsent frames,
  and TESTFR act without con within t1. Alerts carry the session ID and show
  their evidence in Events and Alerts. They never change firewall decisions.
- The IEC 104 Linux smoke (`scripts/smoke-iec104.sh`) also checks live
  inventory counts, APCI alerts and settled holdback-pressure gauges against
  their Prometheus series.
- `show system ssh` reports the effective SSH password policy and where it
  comes from (saved setting, lab default, bootstrap or environment).
- SIGHUP reapplies the running configuration in management and combined mode,
  repairing runtime drift. Failures are logged, audited and shown in health.
  Environment variables and flags still need a restart.
- ICS rule coverage: each rule that names an ICS protocol reports `enforcing`,
  `partial`, `not_enforcing` or `monitoring`, with reasons (no inline path,
  enforcement off, DPI or decoder off, an unbound queue, overlapping or domain
  exclusions with their match counts). Any signed-in user can read it at
  `GET /api/v1/dataplane/ics-coverage`. The ruleset preview, the engine ruleset
  status and the rule preview carry it, and `/api/v1/health` gains a count-only
  `icsEnforcement` summary. The ICS page, the firewall rules table and the rule
  preview show coverage instead of a badge based on mode alone.

### Changed

- A failed ruleset apply no longer hides the ruleset still in force. The
  engine ruleset status keeps the installed revision and adds the failed
  snapshot and its error, rule counters keep working, and health reports
  `enforcement.state: degraded`.
- The Secure by Design page maps all seven CISA pledge goals again and credits
  the default design. Operator steps are deployment guidance. Its one known gap:
  SSH accepts the bootstrap password before the forced first-login change.
- `containd engine` has no default listener. Set `CONTAIND_ENGINE_ADDR` to the
  engine's address on the management network; loopback and wildcard
  listeners are refused at start, except loopback with a reserved management
  path. This also applies to the engine-only image.
- The Compose files no longer carry a commented engine-port mapping, and the
  smoke compose no longer publishes 18081. Call the engine API with
  `docker compose exec containd curl http://127.0.0.1:8081/...`.
- `dataplane.enforceTable` must start with a letter or underscore and be at most
  248 characters, which is what nftables can address, and must not be
  `containd_dhcp` or an nft keyword such as `table` or `inet`. Staging and the
  engine apply the same rule. Revocations now work with
  table names that contain upper case or hyphens.
- Staging rejects a ClamAV `updateSchedule` that is not a positive duration, a
  `timeoutSec` outside 0–300, a `maxSizeBytes` outside 0–100 MiB and a
  negative `blockTtlSeconds` or `cacheTtl`.
  `clamav.socketPath` is optional and defaults to `/run/clamav/clamd.sock`.
- The Compose files keep ClamAV databases in the `clamav-db` volume across
  container replacement.
- The engine is the only antivirus owner in split and combined deployments.
  Management's AV status, update and custom-definition routes delegate to the
  engine and return 503 when it is unreachable. A cron-style
  `clamav.updateSchedule` is rejected at apply instead of silently becoming 6h.
- The additional trusted CA bundle applies at runtime: it is sent to the
  engine on upload and on every apply, ICAP TLS and FreshClam trust it, and an
  upload the engine cannot apply returns 503.
- The forwarding smoke (`scripts/smoke-forward.sh`) proves each deny against a
  live listener, proves masquerade by the source address the server sees and
  requires the DNAT counter to rise. `scripts/smoke-forward-mutations.sh`
  shows it fails on an allow-all policy and on disabled masquerade.
- Lab mode refuses every password change, for every user, through the
  users store: web, admin, SSH menu and the setup wizard give the same reason.
- UI builds always regenerate the embedded documentation and fail if MkDocs
  cannot produce it; `CONTAIND_SKIP_DOCS=1` is only for builds that supply the
  docs separately. UI builds use Node.js 24.
- Commit, commit-confirmed and rollback now fail on every firewall ruleset or
  dataplane configuration apply error, including nft permission failures. The
  warning-only nft failure path is removed. Auxiliary infrastructure warnings
  remain best-effort; imports still stage only.
- Health reports general firewall state separately as `enforcement: {state,
  reason}` (`enforcing`, `disabled`, `unavailable` or `unknown`), including
  persisted replay/recovery failures. Protocol-specific `iec104Enforcement` is
  unchanged. Confirmed-commit TTLs that overflow a duration are rejected
  rather than promoting without a timer.
- Condensed the project overview and centralized contributor setup and verification;
  documented SSH authentication limits, the engine API trust boundary and the published advisory.
- Reorganized documentation navigation and standardized changelog categories and version links.
- Focus update and reserved-management documentation on operator behavior and
  limitations; consolidate VPN guidance under System Services.
- Pass `CONTAIND_ALLOWED_ORIGINS` through starter/dev Compose and remove the
  ineffective `CONTAIND_MODE` knob from Compose environment lists and the example
  environment file; select split modes with command overrides.
- An explicit SSH `allowPassword: false` now holds in lab mode, with an empty
  or unreadable key directory and over environment defaults. Staging or
  committing it is refused unless an admin has a usable authorized key, so the
  setting cannot lock out SSH management. Committed SSH authentication
  settings apply to new logins without a restart.
- Replace the deprecated `xterm` terminal packages with the maintained
  `@xterm/xterm` 6 and `@xterm/addon-fit` releases.

### Fixed

- A firewall rule naming a zone with no interfaces no longer makes nftables
  reject the whole ruleset; the rule matches nothing and the ruleset warnings
  name it (`zone`, with `zones`).
- IPv6 source and destination CIDRs in firewall rules are written as `ip6`
  matches, one line per address family for mixed rules, instead of an invalid
  `ip` match; identity sets and `RATE_LIMIT` meters follow the rule's
  families. A rule whose sources and destinations share no family is reported
  (`addressFamily`).
- `RATE_LIMIT` meters replies too, each direction of a flow in its own bucket.
- When an identity binding is removed or a schedule window ends, replies and
  server packets of ICS connections queued to the engine under a conditional
  `ALLOW` stop too.
- Interface names are validated before they reach nftables: an interface's
  device, the name of an interface without a device, and DHCP listen devices
  must be valid Linux interface names (1–15 bytes, no `/`, `:`, whitespace,
  control characters, `"`, `*` or `\`, not `.` or `..`).
- A commit, rollback or factory reset that fails during management recovery
  returns to recovery instead of reapplying the refused configuration.
- Without a reservation, stored management listeners that cannot be bound no
  longer stop management: it serves the default listeners in management
  recovery.
- Management recovery without a reservation restores the stored static
  addresses of management interfaces.
- Syslog forwarding no longer stops after a configuration commit through the
  API, and it starts at boot without needing another apply.
- Disabling an ICS filter removes it from the rule. Before, the UI sent an
  empty patch and reported success while the filter stayed. Clearing a rule's
  description, logging, zones or address lists in the editor now clears them.
- Service pages and topology no longer show simulated or random activity
  charts. Service series are evenly spaced per minute, with zeros for quiet
  minutes. The proxies page shows the Envoy and Nginx request rates it
  reports.
- Factory reset clears the engine's temporary blocks and connection
  revocations. A failed clear is reported as a `dynamic blocks:` warning.
- The rule impact preview returns `warnings`, and the firewall rule editor's
  Preview impact explains why an ALLOW rule with an identity or schedule
  matches nothing.
- Trusted CA upload shows the applied bundle revision, or the stored revision
  and why the engine did not apply it. `POST /api/v1/system/tls/trusted-ca`
  then returns 200 with `status: "stored"` and `warnings`; 503 now means only
  that the config store is unavailable.
- Committing a candidate that moves an interface to another device and gives
  its old device to another interface no longer fails with `duplicate
  interface device binding`. Commits and engine replay apply explicit
  interface bindings as staged and fill only unbound default interfaces.
- The ICS filter editor's impact preview works again: it uses the signed-in
  session, previews the whole rule and lists predicates that resolve toward
  denial.
- The services overview charts only series that services report, and no
  longer shows simulated trends or default antivirus settings when the engine
  is unreachable.
- When the engine runs as root, each ClamAV apply gives the persisted
  `clamav-db` volume's files to the image's clamav account, without following
  symbolic links.
- The services overview no longer shows a made-up antivirus trend.
- The engine no longer flushes the whole nftables ruleset on every apply and
  at boot. Docker's embedded DNS (so CLI `diag`, FreshClam and other name
  lookups), the DHCP redirect and any other table in the namespace now survive
  commits. The policy now lives in `inet <enforceTable>_policy` (default
  `inet containd_policy`) and is replaced atomically. Temporary blocks and
  connection revocations stay in `inet <enforceTable>` (default
  `inet containd`, so `block_flows` keeps its name) and survive commits. The
  first apply after an upgrade removes the older policy from `inet containd`
  and carries existing flow blocks over with their remaining timeout.
- Connection revocations never refuse access to the management listeners from
  the management interfaces or through the reserved management path.
- Disabling enforcement removes containd's nftables tables, and renaming
  `enforceTable` replaces them, so the kernel matches the reported state.
- The DHCP server's redirect applies when its table does not exist yet. Before,
  the DHCP server never started. Failures to remove the redirect are reported.
- Antivirus scanning reports what the scanner said: clamd replies are parsed in
  NUL mode, ICAP RESPMOD and OPTIONS follow RFC 3507, truncated or unknown
  replies are errors instead of clean, and `timeoutSec`/`maxSizeBytes` apply to
  both backends and reset correctly.
- The firewall admits essential ICMPv6 to the appliance (neighbor discovery,
  destination unreachable, packet too big, time exceeded, parameter problem),
  so IPv6 interfaces keep working with enforcement on.
- An omitted or empty firewall `defaultAction` means DENY everywhere. The
  security conduits view used to show such configs as unmodeled while the
  dataplane already dropped unmatched traffic.
- SSH console prompts no longer see an extra empty line from clients that send
  CR LF.
- A TLS certificate upload whose resolved path is outside `/data` now returns
  409 and names the path and the setting that chose it (environment variable,
  config field or default).
- The OpenAPI document lists every error status of the password routes and the
  TLS certificate upload.
- The nftables ruleset preview is compiled by the live engine with the
  candidate's table and queue settings, the management reservation and the IEC
  104 queue ownership sampled at request time, and states which envelope state
  it used. With enforcement disabled it says nothing would be applied. Without
  a reachable engine it returns an error instead of a default-compiler guess.
- Temporary flow blocks key on the transport protocol, so blocking a TCP flow
  no longer blocks UDP to the same port. The connections list keeps the
  engine's error detail when the backend fails.
- Factory reset brings the firewall and service daemons to the default
  configuration and reports any part that did not converge. It revokes web and
  API sessions (lab-mode tokens stay valid by design) and closes SSH sessions.
  The SSH console reports a failed reset instead of claiming success.
- Disabling DNS, the proxy or ClamAV waits, within a bound, for the daemon to
  exit; ClamAV is now stopped when disabled.
- DHCP `authoritative` is stored and applied; it defaults to off. Authoritative
  servers send DHCPNAK for a requested address that is not leasable on the
  served link; non-authoritative servers stay silent. Both modes adopt a free
  in-pool address that a client renews or reboots with after lease data is lost,
  so it is not handed out twice. Relayed requests and requests for another
  server are ignored.
- NTP status reports the polling interval chrony was configured with.
- Service reconfiguration can no longer be overwritten by a stale worker.
- Port forwards and masquerade compile from the configured zones: custom zone
  names work, disabled forwards emit nothing, and the ruleset never references
  an undeclared set.
- Commit and restart converge static routes and policy rules. Removed entries
  leave the kernel at every valid priority, and only containd-owned entries
  (protocol 98) are removed. Docker and management routes stay. A configured
  route that matches an existing one reuses it; one that differs only in next
  hop replaces it and restores it on removal (journal in
  `/data/routing-displaced.json`). `set outbound quickstart` works with the
  Docker-provided default route.
- The SSH setup wizard stops and reports a failed password change instead of
  auditing and announcing success.
- SSH host keys rotate on schedule on a long-running server; existing sessions
  keep their connection.
- Staging a configuration edit no longer copies the IDS rule bank. With a
  30,000-rule bank, an edit drops from about 180 ms and 200 MB of allocation to
  well under 1 ms. Banks are stored once per running, candidate and previous
  configuration; obsolete banks are reclaimed after commit, rollback and reset.
  The Config page diff uses bounded memory for large configurations.
- Monitoring APIs (flows, protocol and top-talker stats, anomalies, learning,
  signatures, interface state, simulation and inventory) return a JSON 503
  when the engine or capability is unavailable, instead of an empty list, a
  stopped simulation or a successful clear. Engine call failures that returned
  502 now return 503. The UI views and CLI `show` commands that use them show
  "unavailable" with a retry, distinct from empty. `show system` labels
  listener settings as saved configuration and shows the HSTS default.
- Discovered ICS assets, their peers and station addresses have fixed caps
  with counted overflow.
- Complete the management OpenAPI route reference and guard it against the
  registered router, including optional identity and audit endpoints.
- Document staged dataplane settings, session and lab authentication, filtered
  event queries, and binary environment names separately from Compose inputs.
- Failed runtime applies restore the pre-request running config and IDS bank,
  previous/pending state and candidate, then reapply the restored snapshot using
  an independent recovery context. JSON errors report restore/reapply outcomes;
  failed recovery is visible in health. Boot and expiry replay no longer treat
  nft failures as success.
- Factory reset replaces configuration through the same restore/reapply path as
  commit. A failed runtime apply restores the prior configuration and leaves
  users, sessions and audit history in place. After apply succeeds, users and
  sessions are replaced by the default admin in one transaction.
- Keep liveness responsive during commits and recovery with a deadline-bounded
  running metadata/fault snapshot and one shared observation timeout. Brief
  store contention does not hide real state; contention past the budget or
  unreadable state reports `unknown` without exposing an unapplied document.
- Correct Compose onboarding, secret initialization, data locations, interface
  binding and engine API exposure guidance; consolidate lab and WSL setup links.
- Correct CLI lab authentication and IEC 104 monitoring examples, service runtime
  ownership, and the importable configuration example; test its schema and validation.
- Correct DPI protocol coverage, supported rule predicates, learn-mode and PCAP
  behavior, IDS conversion, and the distinction between nftables enforcement and
  experimental eBPF code.
- Document working log sinks and unwired SIEM export, the unauthenticated engine
  API boundary, authentication limits, and published CSAF advisories; align runtime
  package provenance and image-verification examples with the release workflow.
- The dashboard shows only reported activity: no generated packets or made-up
  baselines. NTP, proxy, DHCP, VPN and DNS service status show "never" instead
  of a zero timestamp, and the DHCP error meter counts real failures.

### Removed

- The unused OpenNTPD fallback; chrony is the only NTP daemon the images ship.
- Removed the redundant documentation-directory landing page.
- Remove the incomplete host/systemd deployment guide; Docker Compose remains
  the documented appliance installation path.
- Refresh contributor testing, performance and code-boundary guidance and
  package navigation; remove the empty internal API placeholder.
- Clarify regression harness setup, isolation, endpoint image tags and
  cleanup behavior without changing script execution.

## [0.1.34] - 2026-10-26

### Security

- Upgrade the Go toolchain and both Docker builders to 1.26.10 to fix
  CVE-2026-111943 in `crypto/x509`.
- Update the pinned Wolfi base image so the runtime images ship the fixed
  `ca-certificates-bundle` (CVE-2026-111943) and brotli libraries
  (CVE-2026-111497).

### Changed

- IEC 104 diagnostics name the supported type set: unsupported types report
  `type N is not in the supported IEC 104 type set`, and the
  `IEC104-MALFORMED` / `IEC104-UNSUPPORTED` signature descriptions state the
  actual checks.

### Removed

- The Roadmap and Audit Baseline documentation pages. They held internal
  planning material; Secure by Design now lists the known security gaps
  directly.

### Fixed

- Allow IEC 104 reconnects on retained aborted or closed tuples when the
  session table is full, without exceeding the tracking limit.
- Bound IEC 104 learn-mode session tracking to the shared 4,096-entry
  table. Connections that cannot be tracked are accepted without stream
  inspection and reported as `ics.session` untracked/bound events.
  Enforce-mode midstream traffic can no longer bypass the table limit.
- Keep firewall rule patches as raw JSON until concrete rule validation,
  preserving nested schedule patches without deserializing to `interface{}`.
  Parse PCAP ports as checked unsigned 16-bit values and construct envelope
  gate callbacks outside the mutex's critical section.

## [0.1.33] - 2026-10-25

### Added

- Secure by Design now marks MFA and intrusion evidence as Partial and states the SSH
  and session-revocation caveats.

- Query retained events server-side by IEC session/APDU, flow, kind, protocol,
  decision/verdict and time/cursor bounds; Events deep links and CLI flags search
  before limiting. Filtered pages include cursor and gap/engine-error metadata;
  only-limit callers keep the bare-array API response.

- Protect bounded IEC 104 incident bundles (denied decisions, enforcement and
  abort/reset outcomes, and implicated decoded attempts) from routine telemetry.

- IEC 104 decodes single-point information: TypeID 1 (M_SP_NA_1) and
  TypeID 30 (M_SP_TB_1, with CP56Time2a). Both are monitor-class and match
  read-only IEC 104 rules.
- IEC 104 decodes step-position Types 5 and 32, including the signed VTI,
  transient flag, quality and CP56Time2a. It also decodes common monitor
  Types 7, 9, 11, 15, 21 and 33-37. Sequenced addressing is supported for
  untimed monitor Types 1, 3, 5, 7, 9, 11, 13, 15 and 21; timed monitor
  Types 30-37 require SQ=0.
- `set firewall ics-rule ... iec104` accepts `--type-ids`, `--classes`,
  `--ca`, `--ioa`, `--direction` and `--mode`. `show firewall ics-rules`
  shows the IEC fields.
- PCAP capture selects targets by zone (`zones`) and by logical or kernel
  interface name (`interfaces`). The engine resolves both, also when a
  config commit restarts capture. A logical interface uses its `Device`,
  or its `Name` when unset, only if that kernel device exists. Zones skip
  unbound members and reject a zone with no existing devices, naming the
  zone and unbound members. Explicit interfaces with missing devices are
  rejected. Start responses and status list kernel devices only.
  `filter.port` takes a TCP/UDP port or range.
- `/api/v1/health` reports `ipv4Forwarding` (`enabled`, `disabled` or
  `unknown`). A commit with forwarding disabled returns a warning, and the
  engine logs a warning when a blocked sysctl write leaves it at 0.

- Optional immutable management reservation with exact-peer HTTP/INPUT
  access, priority-1 reply pinning and visible recovery from VPN
  source-address takeovers.
- Keep RangerDanger's reserved management available across NIC renumbering
  and stored-config conflicts; expose recoverable boot faults, block unsafe
  replay, and share reservation-aware bootstrap/factory-reset defaults.
- Install fail-closed default-deny recovery enforcement for
  reserved-management boot faults, with verified recovery status in the API
  and Interfaces page.
- Expose management reservation and guard health.
- Add capture-backed IEC 104 decoder and fuzz regressions for segmented,
  coalesced, malformed and incomplete traffic, plus isolated
  management-access smoke coverage.
- Gate `:latest` promotion on signed, SBOM-attached stable tags whose
  commits are on `main`, with rebuild-free manual promotion after a later
  merge.

### Changed

Visible in API, events and logs:

- **Unknown firewall rule keys are rejected with HTTP 400.** The error names
  the key. Before, unknown keys were silently dropped.
- **Malformed rule selectors fail at save.** An unknown protocol, a port on a
  protocol without ports, or a malformed port is rejected by validation, not
  at nftables compile. Protocol names are stored in lower case.
- **Logged DENY events are retained apart from telemetry.** A separate bank
  keeps the newest 1024 `firewall.rule.hit` DENY events, so high-volume
  IEC 104 telemetry does not push them out. Event lists return retained
  DENYs first within `limit`, so they can displace newer telemetry rows.
- **PCAP start no longer saves its body.** A non-empty start body is the
  capture request for that start only; an empty body starts the committed
  PCAP settings. Saved PCAP settings (`POST /pcap/config`) stage until
  commit. With no engine connected, the start is queued. A body with no
  interface and no zone is rejected.
- Normal Modbus replies carry kind `response`; exceptions stay `exception`.
- Merged 0.1.32 (persistent Modbus/DNP3 inspection, reply orientation,
  port-less rules, Go 1.26.9). IEC 104 keeps failing closed: an unmatched
  IEC 104 reply inside an enforce envelope is still denied.

- **Configuration edits stage until commit.** Every persisted edit from the
  UI, API and CLI writes the candidate; only Commit or Commit-confirmed
  applies it. Commit and rollback cover the configuration and the IDS rule
  bank in one transaction. Paths, methods, bodies and status codes are
  unchanged; a success means "staged", not "active". Editable-object lists
  read the candidate; `GET /config`, export, health and status read running.
  Live operations (blocks, conntrack, capture start/stop, users, reset)
  stay immediate. RangerDanger's candidate→commit import is unaffected.
- **Mutation responses carry `X-Containd-Config: staged` or `committed`.**
  The UI and CLI use this header as their only classifier. The global
  commit bar refreshes on every staged edit; editors say "staged", and the
  CLI prints `staged; run "commit" to apply`.
- **IDS export is `GET`.** The `POST` route is removed.
- **DPI transport counters count each captured packet once.** Protocol and
  top-talker packet/byte counts are lower than before, where decoded objects
  and flow-end events multiplied them.
- **Re-import IDS rule files imported before 0.1.33.** Suricata/Snort and
  Sigma rules with unmapped constraints, and imported rules without
  executable content (including YARA), are kept as non-evaluable with notes
  and no longer alert. Re-importing applies the corrected field mapping.
- **Upgrade notes for RangerDanger and rollback.** RangerDanger 0.1.25 and
  earlier send `ics.functionCodes` and `ics.note` when applying a Modbus DPI
  plan; 0.1.32 ignored them (the rule allowed every function code) and 0.1.33
  rejects them with HTTP 400. Use RangerDanger 0.1.26 or later. The stored
  config schema moves to 0.1.7, which 0.1.32 cannot read: back up `/data`
  before upgrading and restore that backup to roll back. `POST /config/import`
  now stages; RangerDanger uses it only as a fallback when candidate→commit
  fails, and in neither version does that fallback change the live firewall.
  RangerDanger still reports that fallback as a success: 0.1.32 replaced the
  running config, while 0.1.33 keeps it and stages the import. Check the
  `X-Containd-Config: staged` response header and commit the candidate.
- **Malformed management listener addresses are rejected** at validation.
  A listener value must be `host:port` or `:port`.

### Fixed

- Interface autobind binds each logical interface independently. A subnet
  setting (`CONTAIND_<NAME>_SUBNET`) binds only when exactly one up NIC
  matches and never falls back to name, route or index guesses. Five- and
  seven-NIC appliances with `CONTAIND_MGMT_RESERVATION` now boot, including
  after NIC renumbering.
- Management access granted only on unbound logical interfaces no longer
  locks out the appliance. The management listeners stay reachable on every
  existing NIC whose access is not explicitly disabled, and `GET
  /api/v1/health` reports `managementBinding.state: unbound-appliance`.
- Static icon URLs now include the runtime `/containd/` base path when the UI
  is mounted under that prefix.
- Firewall and ICS rule previews run in the engine with its live zone mappings
  and runtime context builders. IEC 104 uses the decoder's shared `SafeRead`
  classification, so read-only rules match eligible forward and reverse traffic;
  envelope-level denials are not counted as candidate-rule matches.
- ICS policy views show the effective inherited mode, and saving an inherited
  filter no longer writes a rule-level `learn` override.
- Commit-confirmed expiry replays the rolled-back running configuration to the
  engine without requiring an engine restart. Service and VPN updates serialize
  persistence and runtime changes with replay.
- IDS updates, imports and restores return runtime apply errors and warnings
  instead of reporting silent success. Config commits, interface/routing updates
  and dataplane/PCAP changes serialize persistence with engine replay to prevent
  lost updates.
- Management replays the stored running config at boot and after an engine
  restart, detected by a random per-process engine `/health` `bootId`.
  Replays and commit applies are serialized to avoid stale rule pushes.
- AF_PACKET capture inspects ingress packets only. With NAT, the
  post-masquerade copy was decoded a second time and added inert block
  entries for the engine address.
- Flows first seen mid-stream are oriented by the known ICS service port, so
  replies get the correct policy context. Handshake evidence still wins.
- A policy apply that restarts the NFQUEUE capture resets the open IEC 104
  sessions again. The engine stopped its reset worker before queue shutdown
  had queued the resets, so a session could stall until the client's t1
  timeout.
- The UI no longer hides a page behind "Checking session..." while it
  re-checks a session it has already verified.
- Data-plane rebuilds preserve the process event ring and increasing event
  IDs, including logged denies and events from rebuilt IEC104 sessions.
- Restore S7 service decoding for standard COTP DT traffic and recognize
  CR/CC credit bits.
- Correct RDP X.224 Connection Confirm decoding and security negotiation
  visibility.
- Fix Suricata/Snort imports to match real HTTP, DNS and TLS decoder
  attributes; reject unexposed header-buffer predicates.
- Correct Sigma field and port aliases.
- Eliminate steady-state DPI accounting allocations and repeated decoder
  scans; keep protocol last-seen timestamps monotonic.
- Native PCAP captures keep running after their start request returns, stop
  cleanly on engine shutdown, and report worker exits in status. Before,
  a capture ended with its request and wrote only the file header.
- Preserve operational packet captures across unrelated configuration
  commits and rollbacks.
- Config review shows secret-only, IDS-bank and newly introduced section
  changes from the authoritative diff; IDS bank bodies appear as summaries.
- Config explorer shows correct IDS counts for running and staged banks.
- Live topology views read the running configuration; stale commit notices
  clear and staging writes one audit record.
- Preserve reserved HTTP management when optional listeners cannot bind;
  expose listener boot faults.
- Refuse unsafe resets and rollback targets without discarding staged work.
- Avoid SQLite-specific management boot-fault handling; a historical
  reservation fault no longer blocks replay after the reservation is removed.
- Correct ownership netlink subscriptions, watcher cancellation and
  concurrent interface/routing state updates.
- Preserve static, DHCP and WireGuard host addresses during CIDR conversion.
- Reuse the management guard receive buffer.
- Bind `:latest` signature verification to the exact release commit checked
  for `main` ancestry; reject malformed and reserved release versions before
  publishing images.

## [0.1.32] - 2026-10-09

### Fixed

- **Modbus/TCP and DNP3 DPI inspects every message on a persistent
  connection.** 0.1.31 passed no TCP sequence numbers to DPI and the Modbus and
  DNP3 decoders never consumed their bytes, so only the first PDU of a
  connection was decoded. A write sent after a read on the same connection
  bypassed `writeOnly` deny rules. Capture now carries the TCP sequence number
  (NFQUEUE, NFLOG and AF_PACKET), the reassembler orders and de-duplicates
  segments (each forwarded segment is captured on both interfaces), and the
  decoders emit one event per complete frame and keep only an incomplete tail.
- **Allowed ICS replies are no longer blocked.** Flow tracking treated every
  packet as the forward direction, so a reply was evaluated on the client's
  ephemeral port; under a default DENY policy in enforce mode the reply hit
  the default rule and the flow was blocked. Flows now know which side opened
  the connection, and reply DPI events are evaluated as opener to server on
  the server port. The default action applies only to requests from the
  opener: a message from the server (a response, an exception, a DNP3
  unsolicited response) is enforced only when a rule matches it, as in
  NFQUEUE mode.
- **Port-less TCP/UDP and ICMP rules compile to valid nftables.** A rule with
  protocol `tcp` or `udp` and no port, or protocol `icmp`, emitted a bare
  protocol token that nft rejects, so the apply failed with HTTP 400. They now
  compile to `meta l4proto <proto>`. A port on `icmp`, a port with no protocol
  and an unknown protocol name are rejected when the ruleset compiles.
- `scripts/smoke-dpi.sh` and `scripts/smoke-forward.sh` counted passes with
  `((x++))`, which exits 1 under `set -e` in Bash 5. The DPI smoke also covers
  a persistent Modbus connection (read, write, read) and fails on a short pass
  count.

### Security

- Go toolchain 1.25.13 → 1.26.9 (go.mod and both Docker builders). This
  clears CVE-2026-78667 (net/http Range header DoS) and CVE-2026-97031
  (crypto/tls ECH DoS), which have no 1.25 fix.
- golang.org/x/net v0.58.0 → v0.60.0 clears CVE-2026-78669 (HTTP/2 SETTINGS
  flood DoS). The bump also moves x/crypto, x/sys, x/text, x/sync and x/mod
  to their current releases.

### Changed

Visible in events and logs:

- Modbus and DNP3 produce one event per frame in each direction. 0.1.31
  repeated the first PDU's event and missed later ones.
- A denied write now produces two rule hits: one for the request and one for
  the echoed reply, which carries the same function code. Reply rule hits show
  the opener-to-server addresses and the server port.
- An ICS rule's `direction` follows the sender: every message from the server
  is a `response`. Modbus replies, which 0.1.31 treated as requests, now match
  `direction: response` rules and no longer match `direction: request` rules.
- Reply-direction events have a `flowId` that ends in `|1`.
- ICS rules scoped to a server port now also inspect replies. Before, replies
  were inspected only when IDS was on (the shipped default).
- Modbus/DNP3 `raw_hex` holds the frame's own bytes, not the whole buffered
  stream.
- IT decoders (TLS, HTTP and others) no longer receive the connection's first
  segment again on every packet. Their per-packet duplicate events stop, and
  later single-segment messages (for example keep-alive HTTP requests) become
  visible. Messages that span segments are still not parsed, as in 0.1.31.
- Captured payloads no longer include Ethernet padding.

## [0.1.31] - 2026-09-28

### Fixed

- **Management plane retries SQLite store opens at startup.** A transient
  `SQLITE_CANTOPEN` on a freshly created bind mount (seen once on Docker
  Desktop right after the data directory was wiped) killed the first boot with
  `failed to open users store`. The config, audit, and users stores now retry
  the open with bounded exponential backoff (6 attempts, 200ms doubling to a
  2s cap) and log each retry at warn; a persistent failure still exits fatal.
- **Config commits no longer leak the previous data-plane run.** Every commit
  rebuilt the engine and started a new capture run without stopping the old
  one, so afpacket/NFQUEUE consumers and the per-run metrics goroutine
  accumulated on each commit (31 leaked goroutines after 15 commits; in
  NFQUEUE mode every rebind failed against the still-bound consumer and burned
  its retries). `capture.Manager` now has a synchronous `Stop`, and the engine
  owns each run's context: `Reconfigure` cancels and stops the previous run
  before swapping state. Goroutine count is flat across 70+ commits.
- **Signal-driven shutdown exits 0.** SIGTERM/SIGINT logged
  `fatal error: context canceled` and exited 1, so orchestrators treated every
  graceful stop as a crash. The daemon now logs `shutdown complete` and exits 0;
  real run errors still exit 1.

### Changed

- GitHub Actions in the CI and release workflows are pinned to full commit
  SHAs (same majors, version noted in a trailing comment), clearing the
  semgrep mutable-action-tag findings.
- `golangci-lint` now enforces `gofmt`; the tree was reformatted in one
  formatting-only commit.
- CI runs the curated Semgrep scan (`scripts/semgrep-verify.sh`, pinned
  semgrep 1.178.0) as a gate alongside go, lint-go, docs, ui, and docker.

## [0.1.30] - 2026-09-25

### Fixed

- **NFLOG group is released before reconfiguration rebinds.** Every config
  commit rebuilds the data-plane engine, and the new engine bound NFLOG
  group 100 while the previous consumer's socket was still open, so the
  bind failed with `operation not permitted`, the engine emitted
  `service.nflog.unavailable` once, and L4 log rules went silent until a
  restart. `StartNFLog` now returns a stop function that cancels the
  receive loop and closes the netlink socket synchronously, `Reconfigure`
  calls it before swapping state, and `Start`/`Reconfigure` are serialized
  so a commit that lands while the previous start is still binding cannot
  interleave. NFLOG registration failures are also reported through the
  process logger at error level instead of only the event stream.

- **Config commits no longer deadlock when the candidate is missing.**
  `Commit` and `CommitConfirmed` held the store lock and then called
  `LoadCandidate`, which re-acquired the same non-reentrant lock to seed a
  missing candidate from running. The second commit after any successful
  commit therefore hung forever, and every later config request queued
  behind it. Commits now load or seed the candidate while already holding
  the lock.

- **DNP3 Direct Operate IDS signature missed FC 6 (No-Ack).** The
  built-in `IDS-DNP3-003` rule was titled "Direct Operate No Ack" but
  matched `function_code == 5` only — FC 5 is Direct Operate (with ack),
  FC 6 is the actual No-Ack variant. An attacker using Direct Operate No
  Ack (FC 6), the exact command the signature is named after, evaded it
  entirely. Both FC 5 and FC 6 write a control output bypassing
  select-before-operate, so the rule now matches `[5, 6]`, and the title
  and description are corrected. Also added the equivalent
  `DNP3-DIRECT-OPERATE` rule to the dataplane signature builtins, which
  previously had no Direct Operate rule at all.

### Security

- **Cleared all HIGH/CRITICAL Trivy findings** in the runtime image, the
  Go module graph, and the UI lockfile. No application behavior changed.
  - Go toolchain 1.25.10 → 1.25.13 (`go.mod` and both Dockerfile builder
    stages), fixing stdlib `crypto/x509` CVE-2026-27145 and later
    advisories.
  - `golang.org/x/crypto` 0.49 → 0.55 (CVE-2026-39828 in `x/crypto/ssh`),
    `x/net` 0.52 → 0.58 (CVE-2026-25681), `x/text` 0.35 → 0.41
    (CVE-2026-56852), with `x/sys`, `x/mod`, `x/sync`, `x/tools` to
    matching versions.
  - Wolfi runtime base digest refreshed, picking up OpenSSL 3.6.2
    (CVE-2026-31789, CRITICAL) and BusyBox 1.37.0-r58 (CVE-2023-39810).
  - UI: `next` and `eslint-config-next` 15.5.10 → 15.5.24 (CVE-2026-75604
    unauthenticated RCE, CVE-2026-44573 middleware information disclosure),
    `postcss` 8.5.18, `nanoid` (CVE-2026-67213) and `sharp` lock bumps,
    plus dev-dependency fixes for `brace-expansion`, `browserslist`,
    `flatted`, `js-yaml`, and `picomatch`. The UI stays on the 15.5 line.

### Changed

- **Test harness.** The Playwright route smoke honors `PLAYWRIGHT_PORT`
  so it cannot silently reuse an unrelated server on port 3100, and
  `ui/test-results/` is git-ignored. New regression tests cover the NFLOG
  lifecycle (including a 100-commit concurrent Reconfigure/Start loop) and
  commits without a candidate.

## [0.1.29] - 2026-06-01

### Added

- **Inline Commit on the candidate-changes status bar.** The site-wide
  "candidate config differs from running config" bar (rendered on every
  page via the app shell, including the Firewall page) now has an inline
  **Commit** button beside "Review Candidate Diff". A staged candidate
  can be applied from wherever the bar appears instead of only from the
  Config page, reducing the "where do I commit?" friction when editing
  firewall rules. Commit errors surface inline; the Review link is kept
  for review-before-commit.

## [0.1.28] - 2026-05-13

Second hardening follow-up after Codex review on
[PR #22](https://github.com/tonylturner/containd/pull/22) flagged
a sharp gap in v0.1.27's supervise loop.

### Fixed

- **NFQUEUE handle is unconditionally closed before retry.** v0.1.27
  added supervise+retry to the NFQUEUE consumer, but a panic inside
  `run()` skipped the `nf.Close()` call: the close paths were a
  separate ctx-watcher goroutine and the register-error early
  return, neither of which fire on a recovered panic. Result: the
  kernel kept the old binding while supervise immediately called
  `nfqueue.Open` again — every retry hit EBUSY, supervise burned
  through all 8 attempts, then gave up. The "restart after panic"
  path was actually "restart-and-loop-fail until giveup". Now
  `defer nf.Close()` runs immediately after `nfqueue.Open()` so
  every return path — normal, error, or panic-via-recover —
  releases the handle. The separate ctx-watcher goroutine is gone
  (redundant with the deferred close + the main `<-ctx.Done()`).
  Codex review on PR #22 caught this as P1.

**Tests**

1 new test (`TestNFQueueSuperviseCleansUpBetweenRetries`) that
asserts the supervise loop cannot re-enter `runFn` while a previous
attempt's deferred cleanup is still in flight — a regression in the
defer-close path would surface as an overlap flag flip.

## [0.1.27] - 2026-05-13

Hardening follow-up to v0.1.26. No behavior changes on the happy path —
addresses a defensive-only code path that didn't actually recover the
way the comment claimed it did.

### Fixed

- **NFQUEUE consumer is supervised with bounded retries** instead of
  silently exiting on panic. v0.1.26 added a `defer recover()` around
  the consumer goroutine to keep a malformed-netlink panic from
  killing the engine, but the recovered path returned from the
  goroutine without restarting the consumer — leaving the kernel
  queue permanently undrained. In practice the panic is unreachable
  with the v0.1.26 `mdlayher/netlink` v1.11.1 bump, but as defense in
  depth the recover should restart. New `supervise()` loop with
  exponential backoff (250ms → 30s, capped) and a hard ceiling of 8
  retries; a permanently-failing kernel surface logs "giving up"
  via `OnError` rather than spinning forever. Context-cancel exits
  cleanly without consuming a retry. Codex review on
  [PR #21](https://github.com/tonylturner/containd/pull/21) caught
  the original silent-exit as P1.

**Tests**

3 new tests covering panic-then-restart, give-up-after-max-retries,
and clean-cancel paths. Test-only `withFastBackoff` seam compresses
the production envelope to sub-millisecond so the giveup test runs
in ~10ms instead of ~62s.

## [0.1.26] - 2026-05-13

Cross-platform ICS DPI enforcement, boot-time interface autobind, and a
batch of fixes surfaced by an end-to-end lab integration shakedown on
macOS Docker Desktop. Builds on v0.1.25's L4 event pipeline.

### Added

- **NFQUEUE-based ICS DPI enforcement.** New `dataplane.nfqueueGroup`
  config field. When non-zero, the compiler emits `queue num <N>` as
  the verdict for dpiEligible rules (those with an ICS predicate)
  instead of plain accept/drop, and the engine starts an NFQUEUE
  capture consumer at that group. Packets flow `kernel → queue →
  handlePacket → DPI decoders → enforceDPIEvents`, which evaluates
  the rule's ICS predicate (function-code allowlist, register
  ranges, etc.) and applies `BlockFlowTemp` via the `block_flows`
  nft set when a violation is detected. Without this, ICS rules
  compiled to plain accept and the function-code allowlist was
  decorative. Verified end-to-end: RTAC Modbus FC3 (in allowlist
  `[1..6]`) passes; FC8 (not in allowlist) triggers a `block_flows`
  entry within seconds, blocking the flow.

- **Forward-chain rule ordering reworked to support DPI.** The
  compiler now emits dpiEligible queue rules BEFORE the
  `ct state established accept` fast-path; otherwise only the SYN
  of an inspected flow reaches the queue and the data-bearing
  packets (carrying the actual Modbus/DNP3/CIP PDUs we need to
  inspect) match ct established and skip DPI entirely. Also moved
  `block_hosts`/`block_flows` drop rules above `ct established` so
  retroactive DPI verdicts actually drop subsequent packets of an
  already-established flow. Non-DPI rules continue to benefit from
  the conntrack fast-path.

- **`AutoBindDefaultInterfaceDevices` runs at mgmt boot.** Before
  the HTTP server begins accepting traffic, mgmt blanks any stale
  `interfaces[].device` references in the stored config and re-runs
  the subnet-match autobind (the existing `CONTAIND_AUTO_*_SUBNET`
  -driven logic). Without this, Docker/LinuxKit ethN reshuffles
  across container restarts left the stored device fields pointing
  at the wrong kernel interface; mgmt-access checks then used the
  wrong iface and the first API request from the management plane
  could 403. The function is exported as
  `AutoBindDefaultInterfaceDevices` so other startup paths can
  trigger the same logic.

### Fixed

- **`mdlayher/netlink` bumped to v1.11.1** (was a pre-release
  pseudo-version that predated the upstream fix). The old version
  panicked with `slice bounds out of range [:140] capacity 138`
  when `getBuffer` allocated raw `n` bytes for the message and
  later sliced to `nlmsgAlign(n)` which rounds up. Upstream fixed
  this by allocating `nlmsgAlign(n)` directly — the comment in
  `getBuffer` now explicitly says "aligned to the next multiple of
  the alignment of a netlink message, to avoid panic when parsing
  messages from the buffer." Visible on the LinuxKit kernel
  underlying macOS Docker Desktop, where it killed the engine
  process the moment the NFQUEUE consumer received a non-aligned
  message. Also bumped `florianl/go-nfqueue/v2` to v2.0.3 for
  compat. No fork needed — upstream already had it.

- **`nflog` consumer is cancelled before Reconfigure swap.**
  Previously `Engine.Configure(dataPlane)` built a fresh engine and
  `Reconfigure` swapped state, but the old nflog consumer goroutine
  kept the netfilter group registration with a closure over the
  now-defunct event store. The new `Start` then hit EPERM trying to
  re-register the group → `service.nflog.unavailable` event with no
  firewall.rule.hit events flowing despite kernel drops queuing to
  nflog. Engine now tracks `nflogCancel context.CancelFunc`;
  `Reconfigure` cancels the previous consumer after swap, so the
  new `Start` finds the group free.

- **`capture.Manager` accepts `Mode: "nfqueue"` without
  `Interfaces`.** Previously short-circuited when `len(Interfaces)
  == 0`, which made NFQUEUE mode unreachable from any config that
  didn't also pin specific eth devices. NFQUEUE is interface-
  agnostic (packets arrive via the kernel queue), so the check now
  only applies to AFPACKET mode.

- **`X-Containd-Warnings` is now a multi-value header.**
  `setWarningHeader` was joining warnings with `\n` into a single
  `Header.Set` value. Go's `net/http` strips control characters
  from header values for security, which collapsed all warnings
  into one space-separated string on the receiver. Each warning
  now gets its own `Header.Add` call so clients can read them
  cleanly via `Header.Values("X-Containd-Warnings")`. Embedded
  newlines within a single warning are converted to spaces to keep
  the value RFC 7230 §3.2 compliant.

- **`POST /api/v1/templates/ics/apply` accepts both hyphenated and
  underscored template names.** `GET /api/v1/templates` returns the
  canonical hyphenated form (e.g. `modbus-read-only`) but the apply
  switch was written with underscores (`modbus_read_only`). Anyone
  copy-pasting from the list endpoint would get a 400 "unknown ICS
  template". `buildICSTemplateRules` now normalizes hyphens to
  underscores at the boundary.

**Tests**

10 new test functions across affected packages: hyphenated template
acceptance, multi-value warning header propagation, NFQUEUE manager
with no interfaces, NFQUEUE + chain-reorder snapshot fixtures,
boot-time autobind no-op vs repair paths.

**Note for downstream consumers**

The `Compiler.QueueID` field added in this release pairs with
`NFQueueGroup` in the runtime config. Set both or neither — a queue
verdict in the compiled ruleset without a userspace consumer attached
would freeze inspected traffic at the kernel hook.

## [0.1.25] - 2026-05-12

### Added

Closes #19.

- **L4 firewall rule events** now flow into `/api/v1/events` for rules
  with `log: true` that don't have an `ics:` block. `Compiler.NFLogGroup`
  emits an `nft log prefix "containd:<id>:<ACTION> " group <N>` clause
  before the verdict on non-DPI rules with `Log: true`. New userspace
  consumer at `pkg/dp/capture/nflog_linux.go` (using
  `github.com/florianl/go-nflog/v2`) subscribes to the configured
  group and appends `firewall.rule.hit` events to the event store.
  Rule IDs are sanitized to `[A-Za-z0-9_-]` in the prefix so quote/
  colon/shell-meta characters in IDs don't produce broken nft syntax
  or unparseable consumer events.

- **Per-rule `ICSPredicate.Mode` is honored.** New
  `(*Engine).effectiveMode(matched)` helper resolves with 3-tier
  precedence: per-rule `Mode` > global `DPIMode` > `"learn"` (safe
  default). `enforceDPIEvents` evaluates per-event and skips verdict
  application unless effective mode is `"enforce"`. The
  `firewall.rule.hit` log event fires regardless of mode so operators
  in monitor-mode still get visibility for the observation phase
  before promoting rules to enforce.

- **ICS templates ship with `Log: true`** (Mode left blank to inherit
  global). All 6 protocol templates + ModbusRegisterGuard. Purdue
  Model's 4 explicit deny rules also gain `Log: true`. Operators
  applying a template under monitor mode now see what would have
  been blocked.

- **Apply-time `mode` parameter** on both
  `POST /api/v1/templates/apply` and `POST /api/v1/templates/ics/apply`
  HTTP endpoints. When set (`"learn"` or `"enforce"`), overrides each
  generated rule's `ICSPredicate.Mode`. Invalid values return 400.

- **`containd templates apply <name> [--mode <learn|enforce>]`** CLI
  flag. Threads through to the HTTP endpoint with the existing
  `validateFirewallICSMode` validator.

- **UI embed-path autodetect** in `ui/lib/api-core.ts`. If the page
  is loaded from `/containd/*` (the convention for embedding the
  containd UI behind a path-prefixed reverse proxy), prefix all API
  calls with `/containd`. `NEXT_PUBLIC_API_BASE` env var still wins
  if set. Fixes the templates UI returning "Failed to preview" when
  accessed via an embedded `/containd/templates/` URL. Wizard's ICS
  Communication card now also sets `log: true` on its generated rule.

### Changed

- `templates.Apply(name, cfg)` retains its existing signature; a new
  sibling `templates.ApplyWithOpts(name, cfg, ApplyOpts{Mode: ...})`
  is the mode-aware path used by the new handler/CLI surfaces.

### Security

- Bumped Go toolchain `1.25.8` → `1.25.10` (in go.mod and both
  build/Dockerfile.{mgmt,engine}) to clear 5 HIGH stdlib CVEs flagged
  by Trivy: CVE-2026-33811, CVE-2026-33814, CVE-2026-39820,
  CVE-2026-39836, CVE-2026-42499.

- Added `github.com/florianl/go-nflog/v2 v2.3.0`.

**Tests**

23 new test functions across the changed packages, covering log
clause emission, DPI suppression, no-group disables logging, prefix
truncation, rule-ID sanitization for unsafe characters, nflog prefix
parse + foreign-prefix rejection + malformed-prefix rejection +
packet field decode, effectiveMode resolution (per-rule wins,
global fallback, learn default, case normalization), template
factories ship `Log: true`, `ApplyWithOpts` overrides, HTTP apply
with `mode=enforce`/blank/invalid.

**Note on v0.1.24**

v0.1.24 was tagged briefly but the release workflow failed at its
VERSION-vs-tag guard (VERSION file lagged the tag). No image was
published for that tag. v0.1.25 is the first release containing
these changes.

## [0.1.23] - 2026-05-08

### Changed
- Transparency note in `docs/mkdocs/secure-by-design.md` under **§ 2 Default Passwords** documenting the v0.1.22 lab-mode credential pinning openly. Calls it out as a deliberate weakening of the default-password posture, scoped to the lab boundary, with explicit "when lab mode is appropriate" and "when lab mode is NOT appropriate" lists, the trade-offs (no credential rotation, SSH-on-:2222 uses the same pinned cred), and roadmap for a future per-instance bootstrap that preserves classroom usability without a universal shared credential.
- `docs/mkdocs/threat-model.md` § Auth Bypass / Privilege Escalation residual-risk list now flags lab mode and links to the secure-by-design transparency note.
- `docs/mkdocs/lab-compose.md` `.env` reference documents `CONTAIND_LAB_MODE` and explicitly warns it should not be enabled on deployments reachable from hostile or shared networks.
- This is a docs-only release rolling the transparency content into the published image alongside the v0.1.22 code change. No new behavior beyond v0.1.22.

## [0.1.22] - 2026-05-08

### Fixed
- `CONTAIND_LAB_MODE=1` now pins the canonical credential. The HTTP password-change endpoints (`POST /api/v1/auth/me/password` and `POST /api/v1/users/:id/password`) return 403 with a clear lab-mode message instead of accepting the change. `GET /api/v1/auth/me` no longer advertises `mustChangePassword: true` in lab mode, so the UI doesn't trigger a force-change flow that would (a) drift the credential away from the documented `containd/containd` default that workshop docs and SSH-on-:2222 depend on, and (b) hit the now-locked endpoint with a confusing CSRF/Origin error when accessed via a reverse proxy. `seedDefaultAdmin` also clears `MustChangePassword` at seed time in lab mode so the flag is never persisted. Surfaced by the RangerDanger workshop integration where students were forced to change the password on first login, breaking subsequent SSH-terminal labs and triggering CORS/CSRF errors when the change was attempted through the proxy. New `TestLabModeLocksPasswordChange` pins the contract.

## [0.1.21] - 2026-05-07

### Fixed
- `compileEntry` now emits one nft rule per protocol on the entry instead of only the first. A rule declaring `[tcp/502, tcp/20000, tcp/8080]` was silently compiling to a single tcp/502 line — every other protocol black-holed. The skeleton "only first protocol supported" code path was finished.
- `writeForwardChain` now emits ALLOW rules before DENY rules. nftables is first-match, so a broad deny ("block lan1->lan2 for tcp/8080") emitted before a narrow allow exception ("rtac/10.30.30.20->lan2/8080") would silently shadow the allow. Within each action, sort by ID for determinism.
- `applyRunningConfig` now calls `autoBindDefaultInterfaceDevices` after loading the committed config. Imports that use logical names (`wan`/`dmz`/`lan1`/`lan2`) with empty or stale `device` fields would otherwise compile to nft rules referencing whatever eth name the JSON happened to specify — silently wrong if the kernel's actual device order differs (e.g. docker assigns ethN by alphabetical network name, not compose order). Now resolved against the running kernel state at commit time.

## [0.1.20] - 2026-05-07

### Security
- Bumped Go toolchain in `build/Dockerfile.mgmt` and `build/Dockerfile.engine` from `golang:1.25.8-alpine` to `golang:1.25.9-alpine`, clearing three Trivy HIGH findings against the published image: `CVE-2026-32280` and `CVE-2026-32281` (crypto/x509 chain-validation DoS) and `CVE-2026-32283` (crypto/tls KeyUpdate DoS). All fixed in Go 1.25.9.

## [0.1.19] - 2026-05-07

### Added
- Tab-completion in the containd CLI. The `containd cli` shell now uses `peterh/liner` for line editing, prefix-match tab-completion against the registered command set (`Registry.Commands()`), and persistent history (`~/.containd_history`, override with `CONTAIND_CLI_HISTORY`). Falls back to plain reading when stdin isn't a TTY so non-interactive scripts keep working.

### Changed
- `shell` / `bash` in the CLI loop now exit the loop alongside `exit` / `quit` / `logout`, instead of printing the misleading "Already in Linux shell. Type 'exit' to return." Wrappers that launch `containd cli` (the SSH appliance shell, RangerDanger's in-app firewall terminal) drop the operator back to bash on return — so `shell` and `bash` are equivalent to `exit` here, not a separate sub-shell.

## [0.1.18] - 2026-04-09

### Fixed
- Fixed daemon lifecycle bug where clamd, envoy, and nginx were started with the HTTP request context, causing them to be killed when the API request completed. All supervised daemons now use a background context.
- Added CAP_SYS_TIME pre-start check for chrony NTP. Without the capability, chronyd exits immediately; the status API now reports a clear actionable error instead of silent failure.
- Added post-start stability check for the NTP daemon: if it exits within 1 second, the error is captured and the status API correctly reports running=false.

### Added
- Added 10 NTP unit tests covering config rendering (chrony and openntpd formats), poll interval conversion, Apply file writes, disable cleanup, status reporting, env var detection, and config path selection.
- Added SYS_TIME capability and CONTAIND_SSH_SHELL_MODE to the starter docker-compose.yml.
- Migrated the standalone engine image (Dockerfile.engine) from distroless to Wolfi for consistency with the management image.

### Changed
- Updated documentation (SPDX.md, sbom.md, audit-baseline.md) to reference Wolfi instead of distroless.

## [0.1.17] - 2026-04-09

### Changed
- Migrated container base image from debian:bookworm-slim to Wolfi (cgr.dev/chainguard/wolfi-base). Wolfi is glibc-based and actively patched, reducing CVE surface significantly compared to Debian while retaining a real Linux shell, tcpdump, and standard troubleshooting tools. Removed 39 Debian-specific CVE suppressions from .trivyignore.
- Embedded services (nginx, unbound, nftables, openvpn, clamav) are now installed via Wolfi apk. Tini is now installed from the Wolfi package repository.
- Replaced OpenNTPD with chrony for NTP time synchronization. Chrony is available in Wolfi, actively maintained, and is the standard NTP implementation on modern Linux. The NTP manager auto-detects chrony or falls back to openntpd. Config generation, validation, and supervision adapted for chrony's format and CLI.
- Pinned Wolfi base image by digest for reproducible builds.
- Updated CSAF advisory containd-2026-001 status to resolved by v0.1.17 base image migration.

## [0.1.16] - 2026-04-09

### Added
- Added configurable Linux shell mode to the SSH server. Set `CONTAIND_SSH_SHELL_MODE=linux` or use `set system ssh shell-mode linux` to drop into a real bash shell on SSH login with access to tcpdump and standard Linux tools. Type `configure` to enter the appliance CLI, `exit` to return to bash. The default `appliance` mode preserves existing behavior with a new `shell` command to access Linux.
- Added `containd cli` subcommand and `/usr/local/bin/configure` symlink for entering the appliance CLI from the Linux shell.
- Added `set system ssh shell-mode` CLI command and `show system` display of the current shell mode.

### Changed
- Switched container base image from distroless to debian:bookworm-slim to support real Linux shell access and tcpdump. Service binaries (nginx, unbound, nftables, openvpn, openntpd, clamav) are now installed via apt instead of staged from intermediate build layers.
- Published CSAF advisory containd-2026-001 documenting inherited Debian 12 CVEs from the base image change. See [advisory](security/csaf/advisories/containd-2026-001.json) and tracking issue #16.

### Security
- The base image change introduces 39 known HIGH/CRITICAL CVEs from upstream Debian 12 packages with no fixes currently available. These are in OS-level dependencies, not containd code. Operators not needing the Linux shell feature should use v0.1.15. See `.trivyignore` for the full suppression list.

## [0.1.15] - 2026-03-14

### Added
- Added route-level sanity coverage for the management API and a browser-driven route smoke suite over the shipped UI pages so release validation catches broken views and endpoint drift before user testing.

### Fixed
- Fixed ICS and firewall rule views so ICS predicate fields such as Modbus function codes are serialized and normalized as real JSON arrays instead of crashing the UI after template-generated rule creation.
- Clarified `security.txt`, CSAF provider metadata, and release packaging so containd now explicitly documents that it currently publishes CSAF provider metadata and authoring scaffolding, while advisory JSON documents are only published when a real vulnerability disclosure exists.

## [0.1.14] - 2026-03-13

### Added
- Added a repeatable audit/verification toolchain with coverage, performance, complexity, Semgrep, race, and smoke workflows so release validation can exercise correctness, security, and runtime behavior from a single documented path.
- Added threat-model, testing, performance, audit-baseline, and code-boundary documentation plus broader regression coverage, fuzz targets, and benchmark baselines across the API, services, CLI, SSH, dataplane, and ICS/IT-DPI parser surfaces.

### Changed
- Refactored oversized runtime, HTTP, CLI, dataplane, and UI modules into bounded domain files, resolving the oversized-file and high-complexity audit findings without changing the supported user-facing workflows.
- Refreshed Secure by Design documentation to reflect completed pledge items and added a simpler adherence status table for operators and reviewers.

### Fixed
- Hardened browser cookie-auth writes so same-origin enforcement now runs before session-refresh/auth side effects and correctly treats default ports as equivalent during origin checks.
- Fixed config import and factory reset flows so IDS rules are fully cleared or replaced instead of silently retaining stale table contents from prior state.
- Enabled DPI by default in the bootstrap/runtime startup path and validated config tab query parameters so first-run behavior matches the expected appliance defaults more reliably.
- Fixed race-only service supervision regressions in the VPN and syslog test/runtime paths, stabilized ClamAV/socket test fixtures for `-race`, and removed committed secret-looking test credential literals that tripped PR scanners.

## [0.1.13] - 2026-03-12

### Added
- Added a dedicated DPI smoke phase with a lightweight Modbus/TCP client/server harness so the default smoke suite now validates live protocol visibility, write detection, inventory population, and DPI enforcement behavior in addition to forwarding/NAT.

### Changed
- Updated the local development compose topology to honor the same `.env`-driven subnet and interface IP variables as the starter compose, so customized lab ranges and interface auto-assign hints stay aligned across both paths.

### Fixed
- Fixed first-boot/default interface binding and `Auto-assign` so interface-to-device mapping now follows subnet-aware matching instead of kernel index order, and can repair the old legacy default binding pattern when recognized.
- Fixed ICS policy template apply so generated firewall rules are actually written into candidate config and appear in the firewall UI after apply/commit instead of remaining preview-only.
- Fixed DPI flow handling so inspectable TCP flows are not prematurely cached as allowed before protocol decoders can inspect later packets, restoring reliable live protocol stats, top-talkers, and inventory updates.
- Ignored Python cache artifacts produced by the new smoke fixture scripts so `__pycache__` and `*.pyc` files stop polluting the worktree during local test runs.

## [0.1.12] - 2026-03-12

### Added
- Added per-user MFA requirement controls with a 7-day enrollment grace period, admin-side grace extension/reset actions, and restricted post-grace access until MFA is enabled.

### Changed
- Reworked the user-management page into separate manage/create tabs so MFA policy controls and account actions remain usable on narrower screens.

### Fixed
- Fixed the quickstart CI workflow YAML so GitHub Actions can parse the generated-password step correctly and rerun CI after `v0.1.11`.

## [0.1.11] - 2026-03-12

### Added
- Added optional app-based TOTP MFA for local accounts, including login challenge/verification, self-service enrollment in the UI, and admin-side MFA reset support for local users.
- Added a documented public advisory process with CSAF provider metadata, advisory authoring templates, and release packaging for machine-readable security materials.
- Added dedicated documentation for logging/evidence surfaces and update policy so operators and instructors can explain what containd records, forwards, and expects during secure updates.

### Fixed
- Removed the hardcoded password value from the quickstart CI smoke by generating a fresh password at runtime instead of committing a scanner-visible credential string.
- Removed the secret-looking JWT placeholder from `.env.example` so starter guidance no longer ships a committed fake secret value that looks like a real disclosure.

### Changed
- Tightened `SECURITY.md`, `security.txt`, and the Secure by Design docs to reflect the actual vulnerability disclosure workflow, advisory/CVE expectations, machine-readable publication points, and the current bootstrap-password caveat.
- Updated the API schema and local user-management surfaces to expose MFA state and the new MFA flows cleanly.

## [0.1.10] - 2026-03-12

### Fixed
- Removed the starter/dev compose dependency on Compose `interface_name`, restoring compatibility with Docker Engine versions older than `28.1` and fixing the CI quickstart smoke failure on GitHub-hosted runners.

### Changed
- Clarified Docker lab documentation so subnet-based auto-assign is the supported stable interface-mapping mechanism, while `interface_name` is described as an optional newer-engine feature for custom lab files.

## [0.1.9] - 2026-03-12

### Added
- Added `scripts/quickstart.sh` for the recommended two-command starter path and `scripts/bootstrap-starter.sh` for customizable lab bootstrap with cross-platform Docker/WSL-friendly setup.
- Added Windows / WSL deployment guidance and a dedicated lab-compose customization guide in the embedded docs.
- Added fresh-config bootstrap defaults for capture interfaces and dataplane enforcement, plus tests for the new environment helpers and bootstrap logic.

### Fixed
- Fixed starter and dev Docker Compose runtime privileges so nftables, routing, TUN, interface auto-assign, and block actions work in the supported container-lab deployment model.
- Fixed engine apply error handling so runtime capability failures are surfaced with useful detail instead of collapsing into generic save errors.
- Fixed starter bootstrap collisions with existing Docker networks by automatically selecting a non-overlapping starter subnet block on first setup when the defaults are already in use.

### Changed
- Switched the documented starter deployment to enforcement-on lab mode by default and clarified the ownership boundary between Docker-defined topology and containd-defined segmentation.
- Updated README and MkDocs deployment docs to center the new quick-start flow, advanced bootstrap flow, and Docker Desktop / WSL classroom guidance.
- Tightened diagnostics UI behavior so temporary block actions reflect enforcement availability and backend runtime errors directly.

## [0.1.8] - 2026-03-12

### Fixed
- Repaired the public starter compose and service write paths so interface, routing, NAT, firewall, config lifecycle, and service saves no longer degrade into generic UI failures.
- Fixed partial firewall rule updates so editing one field no longer drops the rest of the rule payload on save.
- Made direct service saves persist even when runtime apply hits an engine or service warning, and surfaced those warnings back to the UI instead of failing the request outright.
- Fixed the embedded forward and reverse proxy runtime configuration so Envoy validates cleanly, Nginx uses writable temp paths, and repeated service applies stop colliding with already-running Nginx listeners.
- Kept AV runtime state in sync even when another service apply fails, so AV update/definitions actions continue to work after mixed service changes.

### Changed
- Upgraded the public starter compose from a thin single-network quickstart to the full multi-interface lab topology used in development, with `.env`-driven Docker-managed networks and stable interface mapping.
- Clarified README and Docker Compose docs around Docker-owned topology versus containd-owned segmentation, and documented that full enforcement/runtime networking requires a Linux Docker host rather than Docker Desktop.
- Expanded CI coverage for the documented starter compose path so it now exercises core write flows instead of only health/read-only checks.
- Improved UI/API result handling across extended feature pages so warnings and backend validation details are shown directly for services, dataplane actions, and config operations.

## [0.1.7] - 2026-03-11

### Changed
- Single-sourced release versioning via the repo `VERSION` file and separated it from `SchemaVersionCurrent`, so future releases no longer need manual version edits across unrelated files.
- Release workflow now publishes the matching `CHANGELOG.md` section as the GitHub release body and verifies that the pushed tag matches the repo `VERSION` file.


## [0.1.6] - 2026-03-11

### Fixed
- Auto-wired the management plane to the local engine in combined `all` mode so the public standalone appliance can commit config changes, drive simulation, and query runtime state without extra environment variables.
- Fixed the published Docker Compose healthcheck to use `/usr/bin/containd`, matching the runtime image layout.
- Made the engine HTTP client fail fast on missing base URLs and non-2xx simulation responses instead of silently pretending control succeeded.
- Treated a missing `/proc/net/nf_conntrack` table as an empty conntrack view instead of a public quickstart error.

### Changed
- Added CI coverage for the documented standalone/public compose path, including health, login, interface state, and simulation control checks.
- Updated README and MkDocs deployment docs to describe the real combined-mode defaults and the new standalone image override flow.
- Updated release metadata and build version to `v0.1.6`.

## [0.1.5-beta] - 2026-03-11

### Security
- Bumped the Go toolchain and embedded stdlib to `1.25.8` across local builds, CI, and Docker images to address `CVE-2026-25679` and `CVE-2026-27142`.

### Changed
- Clarified the split between Dashboard and live Monitoring with first-run guidance on the dashboard and a telemetry-focused monitoring landing page.
- Routed the in-app Help button to page-specific documentation instead of always opening the docs root.
- Updated local font packaging to self-hosted npm dependencies instead of fetching Google fonts during the build.
- Simplified monitoring language so Events and Flows read more like operator tools and less like internal telemetry surfaces.
- Made topology and config details more action-oriented without changing the existing visual system.

### Fixed
- Restored exact candidate-vs-running config dirty detection in the global status bar.
- Finished the Events page live/pause control and visibility-aware polling.
- Made the Policy Wizard success state explicit about candidate config and commit requirements.
- Updated release metadata and schema/build version to `v0.1.5-beta`.
- Added clearer next-step actions in topology detail panels and reframed config workflow copy around live, staged, and review/apply states.
- Fixed multi-arch release packaging so build-only Docker stages run on the native build platform instead of hanging in emulated arm64 `npm ci` and builder steps.

### Added
- Single-binary appliance (`containd all|mgmt|engine`) with combined management and data plane.
- Zone-based firewall with nftables enforcement, NAT (SNAT masquerade + DNAT port forwarding), and default-deny posture.
- Config lifecycle: candidate/running configs with diff, commit, commit-confirmed (auto-rollback), and rollback.
- Deterministic JSON config export/import with schema versioning.
- SQLite-backed persistence for config, audit, and user databases.
- JWT-based authentication with admin and view-only roles; session invalidation on logout.
- HTTPS with auto-generated self-signed certificate and custom cert install/rotate.
- SSH console with CLI shell (`show`, `set`, `diag` command families), menu, and setup wizard.
- Web-based CLI console (xterm.js) embedded in the management UI.
- Full management UI: dashboard, interfaces, zones, firewall rules, routing, NAT, topology view, monitoring, diagnostics, sessions/conntrack, audit log.
- Embedded DNS resolver (Unbound) with config-driven management.
- Embedded NTP client (OpenNTPD).
- Embedded forward proxy (Envoy explicit forward proxy) with domain ACLs.
- Embedded reverse proxy (Nginx) with upstream pools and TLS termination.
- WireGuard VPN with kernel interface management, peer config, and runtime status.
- OpenVPN client and server with managed config, profile upload, local PKI, and downloadable client profiles.
- DHCPv4 server with per-interface scopes, persistent leases, and MAC-based reservations.
- ICS/OT asset model with criticality, tags, and policy references.
- Full ICS protocol DPI: Modbus/TCP, DNP3, CIP/EtherNet/IP (with EPATH and MSP sub-service parsing), S7comm, IEC 61850 MMS, BACnet, OPC UA.
- IT protocol DPI: DNS (with compression pointer support), TLS (SNI/JA3/versions/ciphers), HTTP/HTTP2, SSH, RDP, SMB, SNMP, NTP.
- ICS asset auto-discovery from observed traffic (`pkg/dp/inventory`).
- Learn mode: passive traffic learning with automatic allowlist rule generation (`pkg/dp/learn`).
- Protocol anomaly detection: malformed frames, protocol violations, rate anomalies (`pkg/dp/anomaly`).
- Signature-based IDS with 16 built-in ICS malware signatures (`pkg/dp/signatures`).
- PCAP offline analysis: upload capture files for DPI processing and policy generation (`pkg/dp/pcap`).
- Event export in CEF, JSON, and Syslog formats to file/UDP/TCP destinations (`pkg/dp/export`).
- Protocol statistics and top talkers (`pkg/dp/stats`).
- 7 ICS policy templates (Purdue baseline, maintenance windows, per-protocol defaults) (`pkg/cp/templates`).
- Schedule predicates and identity predicates on firewall rules.
- Prometheus /metrics endpoint for monitoring integration (`pkg/common/metrics`).
- TCP reassembly with out-of-order segment handling and pre-allocated buffers.
- NFQUEUE selective DPI steering with per-flow verdict caching.
- Optional eBPF XDP/TC fast path for early drops and hardware counters.
- Event spill-to-disk for high-volume event handling.
- Native IDS with Sigma-compatible rule evaluation over DPI events.
- Antivirus pipeline: ICAP client, async scanning queue, optional embedded ClamAV with freshclam.
- Syslog forwarding (UDP/TCP, RFC 5424/JSON, retry/backoff).
- Structured logging (zap) with per-service log files, JSON/console toggle, and env-based overrides.
- Pcap capture forwarding to external sensors.
- Static routing, policy-based routing, and OS route detection/adoption.
- Interface discovery and auto-assignment (WAN to default-route device).
- Conntrack visibility and targeted session kill.
- Diagnostics: ping, traceroute, TCP traceroute, interface reachability probe.
- Docker Compose lab topology with 8 networks (WAN, DMZ, LAN1-6) and stable gateway IPs.
- MkDocs Material documentation site embedded in the appliance image.
- Smoke test suite for NAT/forwarding/DNAT rule-order validation.

### Security
- Default-deny firewall posture with built-in management access rule.
- Distroless container image (nonroot) for minimal attack surface.
- Auth required by default on all management endpoints.
- Session denylist for immediate logout invalidation.
- JWT validation with strong secret enforcement when lab mode is disabled.
- MustChangePassword enforcement on first login.
- nftables injection prevention on firewall rule inputs.
- TLS 1.2+ with hardened cipher suite list.
- HSTS enabled by default.
- CORS with wildcard origin rejection.
- SameSite=Strict session cookies.
- Path traversal protection on all file-serving endpoints.
- Rate limiting on authentication and sensitive API endpoints.

### Changed
- Flow hash uses strings.Builder for reduced allocations.
- Verdict cache with TOCTOU fix for concurrent access safety.
- Flow sweep runs outside mutex to reduce lock contention.
- Event store uses in-place shift to avoid allocations.
- Regex caching in IDS rule evaluation.
- Schedule predicate evaluation is allocation-free.
- TCP reassembler uses pre-allocated segment buffers.

[Unreleased]: https://github.com/tonylturner/containd/compare/v0.1.34...HEAD
[0.1.34]: https://github.com/tonylturner/containd/compare/v0.1.33...v0.1.34
[0.1.33]: https://github.com/tonylturner/containd/compare/v0.1.32...v0.1.33
[0.1.32]: https://github.com/tonylturner/containd/compare/v0.1.31...v0.1.32
[0.1.31]: https://github.com/tonylturner/containd/compare/v0.1.30...v0.1.31
[0.1.30]: https://github.com/tonylturner/containd/compare/v0.1.29...v0.1.30
[0.1.29]: https://github.com/tonylturner/containd/compare/v0.1.28...v0.1.29
[0.1.28]: https://github.com/tonylturner/containd/compare/v0.1.27...v0.1.28
[0.1.27]: https://github.com/tonylturner/containd/compare/v0.1.26...v0.1.27
[0.1.26]: https://github.com/tonylturner/containd/compare/v0.1.25...v0.1.26
[0.1.25]: https://github.com/tonylturner/containd/compare/v0.1.23...v0.1.25
[0.1.23]: https://github.com/tonylturner/containd/compare/v0.1.22...v0.1.23
[0.1.22]: https://github.com/tonylturner/containd/compare/v0.1.21...v0.1.22
[0.1.21]: https://github.com/tonylturner/containd/compare/v0.1.20...v0.1.21
[0.1.20]: https://github.com/tonylturner/containd/compare/v0.1.19...v0.1.20
[0.1.19]: https://github.com/tonylturner/containd/compare/v0.1.18...v0.1.19
[0.1.18]: https://github.com/tonylturner/containd/compare/v0.1.17...v0.1.18
[0.1.17]: https://github.com/tonylturner/containd/compare/v0.1.16...v0.1.17
[0.1.16]: https://github.com/tonylturner/containd/compare/v0.1.15...v0.1.16
[0.1.15]: https://github.com/tonylturner/containd/compare/v0.1.14...v0.1.15
[0.1.14]: https://github.com/tonylturner/containd/compare/v0.1.13...v0.1.14
[0.1.13]: https://github.com/tonylturner/containd/compare/v0.1.12...v0.1.13
[0.1.12]: https://github.com/tonylturner/containd/compare/v0.1.11...v0.1.12
[0.1.11]: https://github.com/tonylturner/containd/compare/v0.1.10...v0.1.11
[0.1.10]: https://github.com/tonylturner/containd/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/tonylturner/containd/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/tonylturner/containd/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/tonylturner/containd/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/tonylturner/containd/compare/v0.1.5-beta...v0.1.6
[0.1.5-beta]: https://github.com/tonylturner/containd/releases/tag/v0.1.5-beta
