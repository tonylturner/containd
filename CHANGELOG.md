# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Upgrade notes

- Telemetry event IDs are JSON strings. API clients that parse event IDs as
  numbers must accept decimal strings.

### Added

- An authoritative `managed` boolean in TLS status identifies the next-start
  identity's upload policy without ambiguous file-path inference.
- System settings show management TLS reload failures while the last valid
  certificate keeps serving, and offer certificate upload only for the managed
  identity; external identities show how to rotate them at their source.
- Service fault banners on the services overview, service settings and VPN page
  distinguish quarantined configuration from runtime retries and explain AV
  fail-policy enforcement.
- Evidence health in the UI shell, Audit persistence view and `show audit --status`,
  with per-destination/source syslog backlog, retry, loss and continuity counters.
- Authenticated `GET /api/v1/evidence/status` and sanitized `evidence.state` in health.

### Fixed

- Cache accepted and rejected management TLS file identities so unchanged
  handshakes do not read or parse PEM, and a reload does not block other
  handshakes from serving the last-good identity.
- Publish management HTTPS certificate chains and private keys together as one
  durable, atomically replaced `/data/tls/server.pem` bundle. Import valid legacy
  default-path pairs automatically without changing the originals; invalid legacy
  pairs get a fresh self-signed bundle. Operator-owned paths are read-only, with
  last-good retention on invalid rotation, explicit status errors and upload 409s.
- Preserve TLS identity and its managed/external selection across factory reset;
  share the validated public-leaf snapshot with status and SSH/local CLI pins.

### Changed

- Document established-session re-evaluation after policy changes and why a
  blocked connection can remain visible in Sessions until conntrack timeout.
- Reject unknown, case-mismatched or duplicate top-level keys in full-config
  API writes and validation with HTTP 400 naming the key. API callers must use
  canonical names such as `dataplane` and `schema_version`. Old backups with
  the retired `export` section still import for schemas 0.1.0–0.1.7.
- Serialize telemetry event IDs as decimal JSON strings across API, UI, CLI,
  previews and syslog; audit record IDs remain numeric.
- Forward engine and management syslog streams independently, retry failed
  destinations, and report telemetry retention loss. New destinations start at
  current tails without backfill; audit resumes its durable cursor after restart.
- Keep operations and management available when audit persistence fails, with
  visible degradation rather than an audit fail-closed policy.
- Describe IEC 62443 indicators as automated requirement checks and check-based security levels, not a standards assessment.

### Fixed

- Keep zone security scores, topology conduit selection and staged zone updates
  separate for names that differ by case or punctuation.
- Make admin MFA disable atomic with the required account's new enrollment grace
  period, so a failed operation leaves the account unchanged.
- Keep topology security matrix columns visible at 1024 px and horizontally
  scrollable for larger zone selections.
- Omit unknown DHCP and WireGuard runtime gauge series instead of reporting
  them stopped. Publish the VPN aggregate only when a VPN is observed running;
  service faults no longer manufacture stopped runtime observations.
- Keep connecting OpenVPN clients supervised instead of quarantining them when
  the remote is slow or unreachable; expose connection status separately from
  process status while retaining the server readiness gate.
- WireGuard configuration is applied to the kernel. The netlink attribute numbers
  did not match the kernel interface, so enabling WireGuard failed.
- Project stored service faults for firewall replay and report per-service
  status. Retain AV fail policy and allow unrelated edits carrying unchanged
  faults. WireGuard teardown removes only containd-created links, including
  custom names and old names after rename. Engine runtime failures are attributed
  per service without blocking other services or firewall application.

### Security

- Reject unsafe daemon configuration fields and require valid proxy TLS certificate/key pairs before publishing configuration.
- Restrict OpenVPN profile imports to the shared bounded parser; manage client credentials by issuer/serial ID with read-only downloads and durable revocation.
- OpenVPN credential lists report whether a running managed server has loaded the current revocation list; the VPN page offers Apply revocation only while it has not.

## [0.1.37] - 2026-10-31

### Upgrade notes

- Back up before upgrading. The configuration schema advances from 0.1.9 to
  0.1.10. 0.1.36 and earlier cannot read schema 0.1.10; restore a pre-upgrade
  backup to downgrade.
- Off-loopback deployments (split, or combined with a wildcard/interface
  `CONTAIND_ENGINE_ADDR`) must set the same dedicated `CONTAIND_ENGINE_SECRET`
  on both peers and use `https://`, or leave the engine URL empty in combined
  mode to derive it. Generate with `openssl rand -hex 32`. No lab bypass or
  plaintext fallback exists. Rotate by changing and restarting both peers;
  replace any exported client credentials too.
- Firewall rules now use first-match in listed order: the first matching
  enforcing ALLOW, DENY or RESET decides; monitor rules never decide. Before,
  an overlapping ALLOW won regardless of position. Configs below schema
  0.1.10 are upgraded on load, import or commit: potentially overlapping
  terminals are reordered to preserve legacy rule precedence, and the
  before/after rule order is recorded. Review the order after upgrade;
  a DENY placed above a broader ALLOW now takes effect.
- Port forwards only translate; firewall policy decides admission. Unless a
  rule already references the forward, the upgrade inserts a matching
  `viaForwards` ALLOW only when no enforcing ICS scope overlaps. Full
  containment in an enforcing ICS scope generates no grant; partial or
  uncertain overlap generates no grant for any of the forward's traffic and
  produces a warning. Existing rules and defaults still decide delivery;
  some previously admitted traffic may now be denied.

### Changed

- Add ordered firewall-rule placement and moves, atomic port-forward publication
  and deletion with placement explanations, and candidate-aware previews;
  via-forward rules report historical preview unavailable.
- Published management and engine images expose their release version, revision,
  creation time, vendor and authors as OCI labels.
- Release promotion to `:latest`, including manual promotion, now requires
  successful CI from a push to main for the exact peeled tag commit. Pending CI
  waits for a bounded poll; missing, failed or cancelled CI fails promotion with
  evidence in the workflow summary.
- IT DPI HTTP parsing reads request and header lines directly from the packet
  payload instead of allocating a buffered reader per packet.
- The UI drops the unused `glob` dev dependency and its override.

### Security

- Prevent concurrent deletion or demotion of the last administrator.
- Make MFA login and enrollment challenges single-use and durable across management
  restarts, and invalidate them on password, TOTP or role changes. Pending
  challenges issued before this upgrade must be restarted.
- Require secret-derived TLS 1.3 mutual authentication for every non-loopback
  engine API listener and route. Numeric loopback HTTP remains unchanged.
  Export scraper/curl credentials with `containd enginecredentials DIRECTORY`.

### Fixed

- The engine keeps watching kernel interface, address and route changes after
  an interrupted system call instead of stopping until restart; drift was
  otherwise repaired only by the 10-second periodic reconcile.
- Direct CLI login directs accounts needing MFA or password rotation to the
  web UI or SSH, and accounts needing MFA enrollment to the web UI.
- Partial account profile updates preserve omitted fields and still allow explicit clearing.
- Interface PATCH writes preserve omitted top-level fields; a supplied `access`
  object replaces that object. Interface edits send explicit clears for removed
  aliases, device bindings, zones and VLAN settings.
- Service, policy, network, PCAP and staged-config editors block saves until settings
  load successfully and while reads are unavailable. Failed refreshes keep drafts
  instead of substituting defaults or reporting success; saves preserve unrelated
  settings, including default-route metrics and gateway metadata. Saved staged
  JSON adopts later refreshes unless it has been edited again.
- CLI read-modify-write edits for NAT, port forwards, proxies, interfaces,
  routing and system settings stop without writing when current configuration
  cannot be read, rather than substituting defaults or running configuration.
  Proxy edits preserve domains, client ACLs, upstream settings, logging and
  reverse sites. Interface edits preserve unrelated device, VLAN, bridge,
  addressing and access settings. Outbound quick start
  completes all reads before staging changes and retains unrelated NAT, routing
  and firewall rule settings, including when creating the first rule. Empty
  interface, firewall-rule, asset, object and zone lists return JSON arrays
  rather than `null`.
- Scripted `containd cli` sessions exit with status 1 if any command fails,
  including when later commands or `exit` run.
- Routine interface apply and reconciliation remove only stale addresses
  containd created, preserving Docker/foreign primary and secondary addresses,
  IPv6 link-local addresses and the reserved management device. Address ownership
  persists across engine process restarts; unmarked addresses from 0.1.36 and
  earlier remain unowned on upgrade. Destructive replacement remains an explicit
  administrator operation. See [address ownership and upgrades](docs/mkdocs/dataplane.md#interface-address-ownership-and-upgrades).

## [0.1.36] - 2026-10-31

### Upgrade notes

- Back up before upgrading. Schema 0.1.7 advances through the 0.1.8
  retired-protocol scope cut to 0.1.9, which migrates exact `learn` modes to
  `monitor`. 0.1.35 and earlier cannot read schema 0.1.9, so downgrade requires
  restoring a pre-upgrade backup.
- Former `learn` ALLOWs no longer admit traffic (including NFQUEUE flows
  subject to the default DENY), and former `learn` DENYs no longer drop at L4
  without a queue; see Security below.
- On upgrade, unchanged built-in IDS rules for retired protocols are removed;
  other saved references, including custom rules, put management in recovery
  until a valid configuration is committed.
- Copied CIP, Modbus and DNP3 template rules are not repaired automatically;
  re-apply the updated templates. The general template registry skips existing
  CIP rule IDs, so remove old CIP template rules before reapplying there.
- CIP event fields `command`, `command_code` and `session_handle` are renamed
  to `enip_command`, `enip_command_code` and `enip_session_handle`, without
  aliases. Upgraded configurations default to tolerant ICS parsing; select
  `strict` if required.
- AV scanning requires an explicit `services.av.scan.include` selection;
  without one, no traffic is intercepted.
- Console WebSocket connections require 30-second, single-use tickets;
  `?token=` is no longer accepted. The `/containd/` reverse-proxy UI regression
  affecting the RangerDanger deployment in 0.1.35 is fixed (#57).

### Security

- The web console uses 30-second, single-use WebSocket tickets instead of
  session JWTs in URLs. Upgrades require a ticket; `?token=` is no longer
  accepted. Management access logs redact credential query values.
- Console ticket issuance has no count limits, so pending-ticket counts no
  longer deny connections for shared lab accounts. Tickets remain single-use
  with a 30-second lifetime and lazy expiry cleanup.
- ICS modes are now rule-local `monitor` or `enforce` (rule > global > monitor).
  Monitor rules only observe; they never admit, drop, hold or reset traffic.
  A former `learn` ALLOW inside an enforce envelope used to admit at L7 and
  could mask an enforce DENY through ALLOW precedence. As monitor it does
  neither, so that traffic is now denied (and reset where the envelope resets).
  Former `learn` DENY rules no longer drop at L4 without a queue. In NFQUEUE
  mode a former `learn` ALLOW also no longer admits its flow past the firewall's
  default DENY; traffic it matched now needs an L4 allow or an enforcing ALLOW.
  Review policy allowances before upgrading; other enforcing rules and strict
  scopes still apply.
- Schema 0.1.9 migrates exact `learn` modes to `monitor` in running, candidate
  and previous banks and clears protocol-less modes, with durable
  `config.rule_modes.migrated` audit records per bank. Fresh writes reject
  `learn`. Back up before upgrading: 0.1.35 and earlier cannot read schema
  0.1.9; restore a pre-upgrade backup to downgrade.

- Verified AF_PACKET ICS policy and decoder dispatch use the post-DNAT backend
  and pre-SNAT client on both observed legs. Conntrack deletion uses the verified
  original tuple while RST injection retains packet-space endpoints.

- ICS decoder events expose CIP request targets (logical, symbolic or unknown;
  responses carry none) and mark
  incomplete CIP MSP/CPF and DNP3 object coverage for per-object policy checks.
  Role-violating IEC 104 ASDUs retain every decoded object and its role finding.
- Learned ICS rules now come only from supported requests and are split by
  source, destination, protocol, unit and function/service code. Modbus rules
  retain only that tuple's bounded address spans; DNP3 and CIP suggestions no
  longer misrepresent station, object-group or path values as addresses.
  Previously generated wider rules are not removed automatically.
- CIP rules reject `addresses`; DNP3 now interprets them as point indexes and
  requires object groups. DNP3/CIP reject the ineffective Modbus `unitId` filter.
  Both editors expose unsupported stored filters for explicit removal; invalid
  stored predicates enter management recovery until corrected.
- Modbus address rules now cover the whole request span. An `ALLOW` with
  `addresses` matches only when every register or coil the request reads or
  writes lies inside the listed entries; previously only the starting address
  was checked, so an `ALLOW` of `10-11` admitted a read or write of 8 registers
  at address 11. A `DENY` with `addresses` matches any overlap, and also
  matches any Modbus request whose span cannot be bounded (unknown function
  code, malformed PDU, quantity outside protocol limits, byte count that
  disagrees with the quantity).
- HTTP DPI events no longer carry the first 4 KiB of the raw request or
  response (`preview`) or its SHA-256 (`hash`). Those bytes could include
  `Authorization` and `Set-Cookie` headers and form bodies, and reached the
  event store, the events API and exports once packet-preview scanning no
  longer removed them. Events keep the parsed metadata (method, path, host,
  status, user agent, ports). Sigma rules can no longer select `preview` or
  `hash`.

### Added

- IEC 104 `commandStates` (SCS/DCS/RCS) and `commandQualifiers` (QU)
  predicates constrain single, double and regulating-step commands; exact
  learner suggestions bind the observed state/qualifier tuple.
- PCAP Analysis now brings imported captures and bounded live watches into one
  evidence review workflow: explicitly generate certified suggestions, inspect
  replay proof and withheld reasons, review IEC 104 and wire/NAT scope, then
  atomically stage selected revisions as monitor rules. Learning never changes
  running policy; candidate commit and a deliberate mode edit remain required
  to enforce. IEC state/QU command subsets can certify; setpoint values/QL,
  bitstrings and select-before-operate sequences remain withheld. Other
  unsupported relations are withheld, and CIP is observation-only.
- Firewall and ICS tables show applied-policy shadow message matches,
  would-allow/would-deny counts and their start time, with rule-filtered monitor
  events. `GET /api/v1/firewall/shadow-counters` distinguishes unavailable from
  zero; counters reset on successful apply or engine restart, not failed apply.
- ICS editors, global DPI settings, wizard and templates offer Inherit,
  Monitor (safe) and Enforce. Monitoring does not start learning; live collection
  is off until an administrator starts an explicit bounded live watch.

- Content identification for Modbus, DNP3, IEC 104 and EtherNet/IP on AF_PACKET
  and in PCAP analysis, with passive alternate-port decoding, content/port
  badges, mismatch and outside-rule-port scope evidence. Identification never
  changes verdicts; observation-bound connections do not generate ALLOW rules.
  Prometheus exposes identification outcomes, incomplete reasons, capacity
  refusals, transport losses and observer occupancy under `containd_identify_*`.
- DPI events and directional flow summaries include a verified
  `transportConnectionId` for locally tracked AF_PACKET TCP/UDP connections,
  with correlation status and conntrack-zone authority health.
- Both ICS editors, CLI and API schemas expose DNP3 station/group/variation/point
  selectors, CIP instance/attribute/tag selectors, and IEC 104 cause, originator,
  P/N, T and select/execute selectors. Clearing a selector sends a merge-PATCH
  null; previews send the complete effective predicate without removal markers.
- DNP3 secure-operations templates explicitly allow Confirm and startup functions,
  restrict Write to time/IIN groups 50/80, and deny Save Configuration alongside
  restart and stop operations.
- `services.av.scan` selects the traffic the scanning gate intercepts:
  include and exclude entries of directional zone pairs, destination ports
  and CIDRs, a download mode (`hold` or `stream_tail`) and the ICS-marked
  zones and assets that pass unscanned content under a closed fail policy.
  Exclusions win, and a selection may not include an ICS decoder port.
- The engine intercepts the HTTP/1.x connections that `services.av.scan`
  selects and scans each object with ClamAV or ICAP. Uploads are held in every
  mode; downloads are held until the verdict in `hold` mode, while
  `stream_tail` forwards all but the final 64 KiB before the verdict. While
  enforcement is on, nftables steers every new TCP connection between the
  selected zones on the selected ports, forwarded connections and inbound
  IPv4 port forwards alike, to the engine's loopback listeners, matched on the
  destination after DNAT. It dials the server from the client's address, so
  the server sees the client IP unless the existing source NAT masquerades
  the connection. The firewall policy decides gated connections in both
  directions. Revocations and temporary blocks reset gated connections they
  match. Management is never intercepted, and a connection opened before the
  selection covered it stays unscanned until it closes. Content the gate
  cannot frame (HTTPS, HTTP/2, `CONNECT`, `Upgrade`), partial objects (`206`
  or `Content-Range`) and bodies larger than `maxSizeBytes` are reported as
  not scanned and follow
  `failPolicy`; an endpoint in `scan.icsZones` or `scan.icsAssets` passes
  unscanned outcomes under `closed`. Detections are refused under either
  policy: a detected held object gets `403`, while a streamed download whose
  prefix was already forwarded resets both connections. A relayed body that
  fails part way also resets both connections, so a truncated object never
  looks complete.
- `scan.downloadMode: stream_tail` forwards a download as it arrives except
  its last 64 KiB, which the gate holds until the verdict; a blocking verdict
  resets both connections. Uploads are held in every mode. In both download
  modes the gate remembers a URL whose download it refused as infected for
  10 minutes (at most 4096 entries) and refuses a later request for it before
  contacting the origin under either fail policy, so a withheld tail cannot
  be fetched with a `Range` request.
- The `av` entry of `GET /services/status` reports the scanning gate under
  `gate`: its state (`off`, `refuse`, `pass`, `pending` or `open`), the
  admission installed in nftables, the loopback listeners, scanner readiness,
  gated connections, and routing or host warnings. The Antivirus page shows
  the same state, edits the scan selection (include and exclude entries by
  zone and port, download mode, ICS zones and assets) and the HTTP download
  and upload switches, and flags an ICS decoder port before saving.
- The ruleset preview (`GET /dataplane/ruleset`) samples the scanning gate's
  admission state and reports it as `runtime.gateAdmit` with
  `runtime.gateAdmitReason`, so the previewed ruleset carries the gate chain
  an apply would install now.
- Gate events under protocol `av`: `service.av.scanned` for every scanned or
  unscanned object, `service.av.gate_connection` for a connection the gate
  could not complete, `service.av.gate_state` for each admission change and
  `service.av.pending` for a commit whose backend was still starting.
  Detections keep `service.av.detected`. Object events carry the client, the
  effective destination and, for a port forward, the original destination,
  with direction, verdict, action, backend, reason (including `aborted` for
  an object the client abandoned before the verdict) and size.
- `scripts/smoke-av-gate.sh` smokes the scanning gate on a live engine with
  the EICAR test file: fail-open and fail-closed with the scanner ready, an
  unavailable backend, ICS assets, an exclusion, an inbound port forward and
  an unselected port. Fixtures are under `test/data-smoke/av/`;
  `SMOKE_MUTATION=no-gate` must fail its refusal checks.
- Per-protocol `dataplane.dpiIcsParsing` settings (`tolerant` or `strict`) for
  Modbus, DNP3, CIP and IEC 104, with Parsing controls in Firewall DPI settings.
  Tolerant evaluates decoded fields and alerts on nonconformant content; strict
  drops nonconformant frames and resets the session when enforcing.
- Scheduled workflows check the published `:latest` management and engine
  images daily and after each release: Cosign signatures, signed CycloneDX SBOM
  attestations, and a Trivy HIGH/CRITICAL scan of every platform image.
  `scripts/verify-published-images.sh` runs the same checks locally. The README
  badges for Trivy, Cosign and SBOM show these results.
- The Sessions page can kill ICMP and ICMPv6 connections. The connections
  list shows the identifier, type and code of each ICMP entry where ports would
  be, original and reply. A connection-scope kill revokes the exact flow, NAT
  included; a client-service kill ends all of the client's pings to that host.
- An ICMP or ICMPv6 kill also drops echo requests and replies that have no
  connection state: ICMP that a `notrack` rule exempts from connection
  tracking, and replies that arrive after the connection's state was deleted.
  They are matched by the addresses and identifier of each direction, in the
  new `revoke_icmp4` and `revoke_icmp6` sets of `inet <enforceTable>`. Existing
  tables gain these sets on their next apply, and existing revocations are kept.
- `show conntrack` shows the identifier, type and code of ICMP and ICMPv6
  connections in place of ports.
- The firewall and ICS rule impact preview shows the time range of retained
  events it searched and the newest matching events, and says when there were
  no events to search.

### Changed

- The management UI builds with Next.js 16 and ESLint 10 (flat config). The
  topology canvas uses `@xyflow/react` 12, the maintained successor of `reactflow`.
- Topology keeps dragged node positions across its periodic refresh, and its zoom
  controls sit top-left, clear of the legend.
- PCAP analyze responses are now `{dataset, stats}`, without profiles or generated
  rules. `POST /learn/generate` requires a sealed dataset ID; `POST /learn/apply`
  requires a request ID and selected suggestion IDs/revisions, stages all or none,
  and never commits. Profile reads (`GET /learn/profiles`), bulk clear
  (`DELETE /learn`), and the internal profile/bulk-rule endpoints are removed.
  Evidence is bounded, persists across restarts and expires after seven days;
  old `learned-*` rules are only flagged for overlap, never removed automatically.
- `GET /api/v1/inventory/{ip}` returns an array with every protocol and role
  observed for the address, and 404 when there is none.
- Apply ICS parsing policy to framed but undecoded content and exclude it from learned allowances.
- Restrict default CIP port 2222 inspection to UDP; TCP/2222 remains containd's SSH service.
- Infer IEC 104 for numeric port 2404 rules imported from Suricata or Snort.
- Preserve CIP response metadata and MSP child identities; report unwalked protocol structure and malformed UDP encapsulations instead of silently omitting them.
- Correct the EtherNet/IP command codes for ListServices (0x0004), ListIdentity (0x0063) and ListInterfaces (0x0064), and name IndicateStatus and Cancel.
- DNP3 inspection now reconstructs transport segments and tracks fragmented application responses, exposing point indices and CROB values with explicit incomplete/unsupported coverage. Application fragments are still decoded independently, without atomic whole-response prevention.
- Classify Modbus diagnostics (function 8) sub-functions by the specification; sub-functions 3, 10 and 20 are writes and unknown sub-functions are reported as undecoded.
- ICAP verdicts are never cached: each scan reaches the server with its direction, HTTP headers and endpoints; native ClamAV caching is unchanged.
- `services.av.failOpenIcs` is retired in favour of `scan.icsZones` and
  `scan.icsAssets`; a stored value still loads and is ignored, and the
  Antivirus page no longer offers the ICS fail-open setting.
- A services apply whose clamd is still starting when its three-second
  budget ends is pending, not failed: the commit succeeds with the warning
  `services: AV backend is still starting …; scanning is pending until it is
  ready`, the AV status shows the gate `pending`, and the engine keeps
  bringing the backend up. Selected objects are refused under `closed` and
  passed under `open` until it is ready.
- `timeoutSec` bounds connecting to the scanner backend and its probes; each
  scan is bounded by the gate's own deadline, ten times `timeoutSec` and at
  least one minute, so a large clean object is no longer cut short by the
  backend timeout.
- Every clamd database activation is confirmed in the background: the engine
  installs a probe signature and scans for it until clamd detects it, within
  five minutes, retrying a failed activation with a bounded backoff. The AV
  status reports `reload_pending` meanwhile, and
  `service.av.clamav_reload_confirmed` records each confirmed activation.
- An empty `services.av.mode` now selects the native ClamAV backend; ICAP is
  an optional remote backend that accepts exactly one server.
- ICAP scanning follows RFC 3507: uploads are sent as `REQMOD` and downloads
  as `RESPMOD` with the original HTTP heads, streaming the body with
  `X-Client-IP`/`X-Server-IP`. A reply is infected on `X-Infection-Found`,
  `X-Violations-Found`, `X-Virus-ID` or a `VirusFound` ICAP status, clean only
  on `204`, and a scan error otherwise. The `OPTIONS` probe requires `REQMOD`
  when uploads are scanned and `RESPMOD` when downloads are scanned. The
  encapsulated request head is the client's, `Cookie` and `Authorization`
  included, as ICAP specifies.
- Upgraded configurations default to tolerant ICS parsing without migration.
  IEC 104 malformed or profile-violating APDUs with a known length now reach
  the rules with a conformance alert instead of resetting the session. Set
  `dataplane.dpiIcsParsing.iec104` to `strict` to retain that reset behavior.
  Lost frame boundaries and integrity faults still fail closed in enforce
  scope in both parsing modes.
- ICS rule predicates no longer treat a function code or CIP object class that
  was not decoded as zero, so such a message matches no function-code or
  object-class predicate. Modbus, DNP3 and CIP decoders now report conformance
  findings, and EtherNet/IP UDP 2222 is decoded as implicit I/O while
  encapsulated UDP is decoded on 44818.
- IEC 104 `ics.decision` events no longer use the reasons `role` and
  `unsupported`: decoded content carries `conformance` codes instead, and a
  strict rejection uses reason `nonconformant`. `malformed` now means only
  unframeable bytes or a stream fault.
- `MODBUS-WRITE-COIL-ALL` now matches only FC 15 requests, not quantity echoes
  in replies. `ICS-WRITE-STORM` now alerts on 20 initiator write commands per
  connection within 10 seconds; replies and exceptions do not count, and an
  IEC 104 APDU with multiple object events counts once.
- DPI denials now drop the packet and best-effort reset only that TCP session,
  without installing a host or service block. Fresh connections, including
  same-source-port reconnects, can start immediately and other sessions are
  untouched. UDP denies drop only the datagram; IPv6 and unavailable injectors
  report reset unavailability. Per-peer `ics.session` events report resets sent
  or failed, not confirmed closure. IEC 104 keeps its existing abort path.
  DPI block elements installed before upgrading have no owner marker and are
  not cleared automatically; they expire within their existing 10-minute TTL.
- Restored the full README overview and dashboard screenshot.
- Modbus `addresses` must now cover whole requests (see Security). Before
  upgrading, compare each Modbus rule's `addresses` with the `address` and
  `quantity` of the requests it admits on the Events page, and widen the
  entries to cover whole requests.
- The CLI guide documents SSH shell modes again: `appliance` and `linux`,
  how `CONTAIND_SSH_SHELL_MODE` and `set system ssh shell-mode` select them,
  switching between the CLI and the Linux shell, the PTY requirement, and the
  root-shell and lab-mode caveats.
- The ICS DPI guide documents protocol anomaly detection, the signature API
  with its 20 built-in signatures and temporary custom signatures, the decoded
  event fields of each ICS decoder, a Modbus function-code and address rule
  example, and how the TLS `ja3` fingerprint differs from reference JA3.
- On upgrade, unchanged built-in IDS rules for removed industrial protocols
  are removed automatically and recorded in an audit record. Any other saved
  reference to a removed protocol starts the appliance in management recovery;
  the saved configuration remains exportable until a valid configuration is
  committed.
- IDS rules, custom signatures, Sigma rules, firewall rules and decoder toggles
  reject `enip` with `EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command`.
  The protocol name `cip` covers the whole EtherNet/IP stack. Suricata and Snort
  rule files that use `enip` still import as `cip`.
- CIP events (including MSP sub-events) replace `command`, `command_code` and
  `session_handle` with `enip_command`, `enip_command_code` and
  `enip_session_handle`, without aliases. `cpf_item_types` reports all CPF item
  types in packet order as one comma-joined string without spaces for valid
  SendRRData/SendUnitData item lists, usable with IDS scalar operators; alert
  details show the encapsulation command and CPF items.

### Fixed

- Behind a reverse proxy that mounts the UI under `/containd/`, login,
  logout and forbidden redirects stay under the mount instead of leaving it.
  The breadcrumb no longer shows the mount as a page, and the active navigation
  item is highlighted.
- The web console displays its server greeting once, followed by a clean prompt.
- Management URL builders avoid duplicate base-path prefixes when a reverse
  proxy has already rewritten API or asset paths.
- Console ticket upgrades work through proxies that omit the published port
  from `Host`; ticket issuance retains cookie-authenticated origin checks.
- Modbus write-single-coil (FC5) values other than ON (`0xFF00`) and OFF
  (`0x0000`) are invalid on the wire and no longer match an ICS ALLOW, in monitor
  or enforce mode. An enforce ALLOW for FC5 now leaves such writes to the
  default verdict; DENY and RESET rules still match them.
- TCP flows pin one stream framer for both directions, preferring the server
  port when endpoints use different ICS ports, in live and PCAP inspection.

- AF_PACKET resolver queue or byte overflow stops passive DPI and identification
  decoding for the affected connection incarnation, without changing forwarding.
  A `dpi.coverage.loss` event and `containd_dpi_coverage_losses_total` counter expose
  the loss; decoding resumes only with a new connection incarnation.

- PCAP analysis and replay honor big-endian and nanosecond captures. Analysis
  reports truncated coverage for partial final records instead of hiding them.

- Live and offline DPI events retain packet capture timestamps, including
  malformed events; ICS tagging no longer replaces them with wall time.

- TCP/2404 flows outside IEC 104 table ownership now use generic TCP
  decision serialization, denial reconnects and incarnation retirement.

- The HTTP scanning gate releases a held upload's object slot before its
  final response reaches the client, so a following upload or the response's
  download scan is not refused as busy by the previous upload.
- Modbus transaction pairing separates connection incarnations, directions,
  transaction IDs and unit IDs, including locally masqueraded AF_PACKET
  traffic. Missing connection evidence reports correlation unavailable instead
  of an unmatched-reply violation; inventory and learning use verified logical
  client/backend roles without changing wire telemetry or policy addresses.
  Unmatched-reply detection requires capture from the connection's opening SYN.
  For ordinary packet loss or inspection bypass it pauses for two quiet minutes
  and resumes; queue or byte overflow instead stops decoding for that
  incarnation until a new connection incarnation. Resolver admission is
  limited to industrial traffic and bounded. NFQUEUE and PCAP evidence reports
  `correlationStatus: wire`.
- Empty ICS function/service code fields now mean any code in both rule editors,
  without injecting zero from whitespace or separators. Invalid selector values
  block saving and preview, and clearing generic restrictions removes them.
- Template previews display the generated rule's nested ICS protocol and codes.
  ICS rule listing and dashboard counts recognize all predicate fields, and the
  CLI accepts and displays CIP object classes.
- Successful IDS imports and zone, interface and identity collection changes
  appear immediately without discarding unrelated edits. Saving IDS rules keeps
  imported additions; import and creation forms do not block configuration refreshes.
  VPN profile uploads likewise update their configuration path while retaining edits.
- DHCP, DNS, NTP, syslog, AV, proxy, VPN, IDS, NAT, routing, zone, interface,
  wizard, identity, firewall, ICS and template editors keep unsaved edits during staged-save, commit
  and automatic refreshes, and warn when settings change on the server.
  Edits made while a save is outstanding survive its acknowledgement, even when
  changed back to the previous server value. Explicit Refresh discards edits.
  List fields retain unfinished text while typing.
- On narrow screens, the sidebar collapses behind a Menu button so the main
  content has the full viewport width. Navigation closes after choosing a
  link or pressing Escape; the desktop sidebar stays visible.
- CIP read-only rules no longer classify Apply Attributes, Set Member,
  connection controls or class-specific mutations as reads. Classification
  uses the request target and validates supported read bodies; unknown
  operations and uncorrelated replies have no read/write category. The CIP
  monitor template uses read-only/write-only predicates instead of unsafe
  service-code lists. Previously saved template rules require replacement.
- Protocol read counters require explicit read evidence instead of treating
  every non-write event as a read. CIP learning uses decoded target-aware
  service names and excludes requests without a known access category.
- Modbus and DNP3 read-only rules match only known reads. Unknown and
  vendor function codes, unknown Modbus diagnostic sub-functions, MEI types
  other than 14, Modbus Write File Record (FC 21), and DNP3 freeze,
  initialize, start, unsolicited, assign-class, time, file, configuration and
  authentication functions no longer count as reads. Unknown operations omit
  `is_write`. The Modbus read-only template also denies FC 21.
- Modbus exception replies now complete their request's transaction, so an
  exception no longer leaves the transaction pending, and an exception with
  no prior request is reported like an unmatched response.
- `set dataplane enforcement` in the CLI keeps the other dataplane settings
  instead of resetting them, and rejects values other than `on`, `off`,
  `true`, `false`, `1` and `0`.
- The Alerts page lists protocol anomalies and signature matches beside rule
  alerts, with their anomaly type or signature ID, and search covers those
  identifiers and the protocol.
- Discovered ICS assets keep a separate observation per protocol and role,
  so a host that speaks two protocols, or is both client and server, no
  longer has one observation overwrite another.
- Security conduit analysis names and classifies ICS protocols by transport
  and port, so a TCP rule on port 2222 is no longer shown as EtherNet/IP.

- The scanning gate tracks connections by both TCP endpoints, so connections
  sharing a client IP and port keep their own masquerading, events and resets.
- The scanning gate releases a held upload's object slot before exposing its
  final response or admitting its download scan, so a following upload or
  response scan is not refused as busy. If the origin answers before the gate's
  last write returns, it keeps the client connection open rather than treating
  the upload as truncated and dropping the next pipelined response.
- Modbus request/reply decoding and ICS policy direction follow the connection
  opener, including clients bound to port 502. Offline PCAP analysis uses
  SYN/SYN-ACK orientation, with service-port hints only for midstream captures.
  Modbus, DNP3 and CIP inventory roles stay stable across replies and exceptions.
- Generic DPI denial tombstones now expire after 10 seconds and are capped at
  16,384 entries, evicting the oldest first. Expiry and eviction release the
  exact tuple's cached denial and failed streams so reconnects remain immediate;
  late payload still drops through mid-stream protection. Capacity evictions
  are counted in `containd_dp_denied_tcp_evictions_total`.
- TCP CIP now reassembles split EtherNet/IP encapsulations, inspects every coalesced encapsulation, and fails closed on mid-stream pickups in an enforce scope.
- The Modbus decoder no longer invents fields. Replies no longer report their
  byte count and data as `address` and `quantity`, and FC 5/6 report `value`
  instead of `quantity`. Requests report fields per function code, including
  `byte_count` for FC 15/16 and `read_*`/`write_*` for FC 23; read replies
  report `byte_count` and `register_count`.
- Learned Modbus rules list each observed address span (for example `10-11`)
  instead of only start addresses, so generated rules cover the traffic they
  observed without suggesting stored rules are rewritten.
- Sigma rules can match the Modbus fields `byte_count`, `register_count`,
  `and_mask`, `or_mask`, `read_address`, `read_quantity`, `write_address` and
  `write_quantity`.
- Synthetic lab-mode Modbus events carry the same fields as decoded traffic
  and include FC 23 requests.
- Modbus alert details show the value of FC 5/6 writes and the read and write
  ranges of FC 23 requests.
- Without a client PTY, `shell` and `bash` in the SSH appliance CLI no
  longer start a Linux shell that has no terminal and hangs the session.
  They print that the Linux shell needs an interactive session and the CLI
  keeps running.
- After `exit` from a Linux shell opened with `shell` in the SSH appliance
  CLI, the CLI no longer loses the next input: the shell's input copy kept
  reading the SSH channel and discarded it. The shell also receives lines
  typed ahead of it, and stops taking window-size changes when it exits.
- `system.ssh.shellMode` accepts only `appliance`, `linux` or empty. Any
  other value, such as `Linux` or `bash`, is rejected on save and commit
  instead of silently meaning `appliance`. A value written by an earlier
  release, whether stored or in an imported backup, becomes the mode that
  release ran (`linux` in any letter case becomes `linux`, any other value
  `appliance`): a stored one does not start management in recovery, and a
  backup restores without an error. `CONTAIND_SSH_SHELL_MODE` keeps
  accepting any letter case.
- `show system` displayed the saved SSH shell mode, even when
  `CONTAIND_SSH_SHELL_MODE` overrode it or a committed change had not yet
  been applied by a restart. It now shows the mode SSH runs
  (`ssh.shell_mode`), its source (`ssh.shell_mode_source`) and, when they
  differ, the saved mode (`ssh.shell_mode_saved`). `show system ssh` lists
  the same mode and source. A CLI without the appliance's store, such as
  `containd cli` or the SSH console, runs `show system` on the appliance.
- The SSH console no longer loses management access while the connection is
  open. Its token expired 5 minutes after login, or 30 minutes after the last
  command, and later commands failed with status 401 until the user
  reconnected. Each request now uses a fresh token for the connection's
  session, which stays valid until the connection closes or, with a JWT
  secret, reaches the 4-hour session limit.
- `configure` and `containd cli` in a Linux shell opened over SSH act as the
  SSH login instead of logging in as `CONTAIND_CLI_USER` with
  `CONTAIND_CLI_PASSWORD` (default `containd` / `containd`). They worked only
  while that account kept its default password, and acted as that account
  rather than the SSH user. The SSH server forwards their requests from a
  socket that exists only while the shell runs, so the shell holds no token
  or password. `containd cli` outside an SSH shell, such as through
  `docker exec`, still logs in with those variables.
- `containd cli` outside an SSH shell, such as through `docker exec`, and
  the container health check (`containd healthcheck`) work on deployments
  without management HTTP. They called `http://127.0.0.1` at the port of
  `CONTAIND_MGMT_ADDR`, so they failed when HTTP was off, and could send the
  CLI password to another process holding that port. Management now records
  the listeners it bound in `run/management.json` beside the configuration
  store, in a directory only its user can open, and removes the file when it
  stops. The CLI and health check call those listeners the way the SSH
  console does: HTTP unless it redirects, otherwise HTTPS trusting only the
  served certificate, following no redirect. Without the file they report
  `management is not running`.
- Several sessions multiplexed on one SSH connection, such as with OpenSSH
  `ControlMaster`, no longer share CLI client state. Concurrent commands
  wrote the same API token field without synchronisation.
- The built-in CIP IDS rules never matched: they named protocol `enip`, but
  the CIP decoder reports `cip`. They now name `cip`. On upgrade, unchanged
  built-in CIP rules are updated to `cip` and recorded in the same audit
  record; an edited copy that names `enip` starts the appliance in management
  recovery until it is corrected.
- All four IDS exporters validate `rawSource` as a cache against the rule's
  current predicates before reusing it. Edited or corrupt cached source falls
  through to exact native export or a refusal naming the unsupported predicate;
  conversion-loss safeguards remain in place.
- Sigma and YARA IDS exports now report refusals instead of dropping native
  predicates. Sigma round-trips containd's decoder fields, supported operators,
  Boolean conditions, protocol/kind tags and severity; imports preserve each
  UTF-8 document's source bytes.
  YARA accepts only byte-content rules without native event or network
  predicates. Refusal comments, API counts and UI feedback
  cover every export format.
- Snort 3 and Suricata IDS exports refuse unsupported application predicates
  instead of widening them to generic traffic. Downloads list every refusal in
  comments and report a refused count in the API header and Export panel.
  Valid same-format cached source remains lossless; native content uses the
  target engine's option syntax.
- Snort imports keep Snort 3 content modifiers, negation, hex content and
  escaped punctuation, so containd's own Snort exports re-import unchanged.
  Quoted option values no longer split on `;` or `,`.

### Removed

- The "Multiple ICS protocols on same flow" anomaly. It grouped traffic by
  host pair rather than by connection, so it raised a high-severity anomaly
  for every host that legitimately speaks two ICS protocols to one peer.
- Asynchronous antivirus scanning of HTTP packet previews and the AV block TTL
  setting (`services.av.blockTtlSeconds`). Antivirus backends scan complete
  HTTP objects instead; no dynamic block follows a detection, so the setting
  had no effect. A stored or exported configuration that still contains it
  loads and the value is ignored. The AV page and the AV status no longer
  show a queue depth or block TTL.
- Removed S7comm, BACnet/IP, OPC UA and IEC 61850 MMS inspection, templates and
  protocol-specific detections. Industrial inspection supports Modbus/TCP,
  DNP3, IEC 60870-5-104 and optional CIP/EtherNet/IP.

## [0.1.35] - 2026-10-26

### Security

- In IEC 104 envelopes a segment carrying both SYN and RST no longer opens, establishes or closes a session: every session and every enforce envelope drops it, and learn mode no longer starts a session at it.
- The web console and SSH CLI sessions call a management listener on 127.0.0.1 only through a socket management itself bound. A failed loopback or HTTPS bind, or a reserved-endpoint fallback after a failed wildcard bind, no longer sends bearer tokens to another process holding that port. With no bound listener reachable on 127.0.0.1 the console reports it and SSH stays off with a listener fault.
- In IEC 104 envelopes a RST without payload closes a session only at the
  sequence number its receiver expects next. A forged or stale RST no longer
  makes the engine stop following a live connection.
- In an IEC 104 enforce envelope a session starts only at a SYN of a handshake
  that connection tracking has not seen complete; a SYN sent into an
  established connection no longer opens one. The `iec104_envelope` nft chain
  now has three rules and sets the handshake mark bit `0x02000000` alongside
  `0x01000000`.
- With NFQUEUE, a SYN sent into an established Modbus or DNP3 connection
  covered by an enforce ICS rule no longer restarts inspection. After an
  engine restart, or once the engine forgot an idle connection, such a SYN
  could choose where the engine started framing the connection's bytes.
  Inspection now starts only at a handshake that connection tracking has not
  seen complete; otherwise the connection stays dropped as
  `stream_midstream`. Generic ICS rules now jump to the new `ics_queue` nft
  chain, which queues with skb mark `0x02000000` for such handshakes.
- Outside lab mode, wrong TOTP codes and wrong current passwords are limited
  per account across all client addresses, on web/API and SSH. Five wrong
  codes, or ten wrong current passwords, without a success lock that check
  for 15 minutes. A locked check is refused before the guess is checked
  (web/API `429` with `Retry-After`), and each lock writes one denied audit
  record. The counts survive a restart. Password login is never locked by
  these limits; resetting the account's password lifts them.
- A TOTP code is accepted once per account. Web/API login, MFA self-disable
  and SSH login refuse a code whose time step is not later than the last
  accepted one, including after a restart.
- Outside lab mode, refused SSH logins write `ssh.login` denied records naming
  the account and client address: unknown or non-admin account, wrong
  password, unauthorized key (once per unauthenticated connection, with
  fingerprints), and wrong or reused TOTP code. SSH key logins now share the
  password login rate limit.
- Wrong codes at MFA enrollment and a wrong password or code when turning MFA
  off write denied `auth.mfa.enable` / `auth.mfa.disable` records.
- Outside lab mode, the SSH menu password reset and the setup wizard ask for
  the current password before changing it, and record a wrong one as denied.
- Outside lab mode, SSH applies the web login's account checks. The bootstrap
  admin must change its password at SSH login, for password and key logins,
  before the CLI, menu or shell opens. Password login of an account with TOTP
  MFA asks for the code through keyboard-interactive authentication, and an
  account past its MFA enrollment grace period cannot log in over SSH. Clients
  limited to the `password` method, such as `sshpass`, cannot complete these
  steps. Lab-mode SSH is unchanged.
- A password or MFA change from the web UI, the API or the SSH console ends the
  account's other sessions and closes their SSH connections. Deleting an
  account closes its SSH connections. A new password must differ from the
  current one.
- SSH login rate limiting counts attempts per client address and account;
  previously every connection started a new count.
- User creation, change and deletion, profile changes, password changes,
  management TLS certificate replacement, SSH key enrollment and refused SSH
  logins now write audit records. SSH console password changes are recorded as
  `auth.password.change` (was `user.password.set`).
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
  dropped and its flow blocked when its TCP stream cannot be inspected:
  conflicting or rewritten retransmitted bytes, framing the decoder rejects,
  reassembly limits, or a decoder fault. Before, inspection restarted at a
  later segment and a prohibited command could pass. An `ics.decision` event
  with reason `stream_error` or `decoder_panic` names the rule. Learn mode and
  IEC 104 are unchanged.
- With NFQUEUE, a Modbus or DNP3 connection covered by an enforce ICS rule no
  longer restarts inspection at a FIN or RST that its receiver ignores. A FIN
  or RST ends the stream only when it is in window, and never on a connection
  already denied. A SYN with a new sequence number on a live connection now
  drops and blocks it with reason `stream_resync`. After a decoder fault, the
  bytes held before it are not inspected again. Before, a crafted RST, FIN or
  SYN could make a later prohibited command be framed from the middle of a
  message, so it passed.
- With NFQUEUE, a Modbus or DNP3 connection covered by an enforce ICS rule
  that the engine did not see from its SYN is dropped, as IEC 104 sessions
  already are. This covers connections open across an engine restart or a
  data-plane configuration change, and connections idle longer than the
  engine's 5-minute flow timeout. Inspection used to start at the first segment
  it saw, which could fall inside a message. An `ics.decision` event with
  reason `stream_midstream` names the rule. No flow block is installed: the
  client's next connection is inspected from its first byte. Learn mode is
  unchanged.
- With NFQUEUE, a Modbus or DNP3 connection covered by an enforce ICS rule now
  stays dropped after a denied command until the connection ends. If the nft
  flow block could not be installed, the client's retransmission of the denied
  command could reach the device about 30 s after the denial.
- Validation refuses a firewall rule that names an ICS protocol and is in
  effective enforce mode while `dataplane.nfqueueGroup` is 0. Without an
  inline path the first prohibited command reached the device while the UI
  showed "enforce". Set a queue, or set the rule's `ics.mode` to `learn`.
  Rules without an ICS protocol and a global `dpiMode: enforce` alone stay
  valid. `dataplane.dpiMode` accepts only `learn` or `enforce`.

### Added

- System Settings shows the subject alternative names (DNS names and IP addresses) of the certificate the HTTPS listener serves, and of the saved certificate where the next management start serves other files. GET /system/tls adds `servedCertDnsNames` and `servedCertIps`.
- The topology security view summarizes how many zones fall below their SL target, counting every zone and not only those in the matrix, and names each with its achieved and target level.
- `GET /api/v1/dataplane/ruleset/status` reports the installed ruleset's status (failed apply, schedule planner, applied rule warnings, ICS coverage) to any authenticated user, without compiling the candidate and without the ruleset text.
- `show syslog status` shows audit record forwarding: totals, backlog and, per
  forwarder, cursor, backlog, last send and last error.
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
  warnings, including zones without interfaces and rules whose addresses share
  no family; boot recovery state on every page, with or without a management
  reservation; enforcement health with the failed apply and schedule planner
  state; tags on Active Flows; and the audit forwarding backlog on the syslog
  service page.
- The engine image ships ClamAV, FreshClam and CA roots. The engine renders
  and supervises clamd and a single FreshClam schedule, reports live readiness
  and the definitions version, and validates custom definitions before
  activating them with a clamd reload. ICAP `useTls` uses verified TLS 1.2 or
  newer with no plaintext fallback.
- The Sessions page and `GET /api/v1/conntrack` show the kernel's real IPv4
  and IPv6 connections, including NAT reply tuples, and report an unavailable
  backend as an error instead of an empty list. The list comes from a
  ctnetlink dump only, so it works on kernels that do not export
  `/proc/net/nf_conntrack`. A cancelled request stops the dump, and the
  `limit` bounds the records held in memory. Kill now works for TCP and UDP:
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

- The Firewall and ICS pages show every role why firewall enforcement is degraded; the applied ruleset status no longer needs an admin ruleset preview.
- `GET /api/v1/system/tls` returns cleaned certificate paths, the subject and expiry of the certificate the bound HTTPS listener serves (`servedCertSubject`, `servedCertNotAfter`), and the bound listener addresses (`boundHttpListenAddr`, `boundHttpsListenAddr`), with `httpListenChanges` and `httpsListenChanges` saying whether the next start binds another listener. Every wildcard spelling of a port is the same listener; a listener bound at a specific address in place of a configured wildcard shows its next-start row.
- System Settings shows the listeners, certificate files and certificate served now, and adds a "(next start)" row only where the next start differs.
- The UI shows the detail of API errors, such as why a certificate upload was rejected.
- The ICS and firewall pages label enforcement health "ICS connection reset unhealthy" when the engine fails to reset a Modbus or DNP3 connection it picked up mid-stream and no IEC 104 enforce envelope is active.
- System Settings reports a certificate upload that is stored for the next start as a warning instead of "updated".
- `GET /api/v1/system/tls` adds `servedCertFile` and `servedKeyFile`, the
  files the bound HTTPS listener serves now. A certificate upload returns
  status `updated` when the listener serves the uploaded files (from its next
  TLS handshake), and `stored` with a warning when they are served from the
  next start. An upload that would replace only one of the served certificate
  and key is refused with 409.
- After resetting a fail-closed ICS connection it picked up mid-stream, the
  engine answers the endpoints' challenge ACKs by sending the reset again, up
  to three times within a second, as it does for IEC 104 sessions.
- A failed reset of such a connection makes the `iec104Enforcement` health
  object unhealthy while an enforce rule of another ICS protocol is loaded
  (`active` stays false).
- A client of a fail-closed ICS connection (Modbus, DNP3 and the other
  non-IEC 104 ICS rules in enforce mode with NFQUEUE) that loses its
  connection, for example by restarting, can reconnect at once from the same
  source port. A SYN without payload sent into an established connection no
  longer blocks the client for 10 minutes; it passes without restarting
  inspection. A SYN with payload that does not start the connection's stream
  is still dropped and blocked (`stream_resync`).
- A fail-closed ICS connection the engine picks up mid-stream (after an engine
  restart, an idle timeout or a new handshake on its tuple) is reset once at
  both endpoints (reason `stream_midstream`, no flow block), so clients
  reconnect at once instead of waiting for their TCP timeout. IPv6 connections
  and engines without the reset injector still only drop.
- ICS firewall rule `addresses` entries are validated where they are saved. An
  entry is one value or an inclusive `low-high` range, each unsigned decimal or
  `0x` hex, with low <= high. Modbus entries end at 65535; other protocols at
  4294967295. Entries such as `0x01G0`, `-5` or `0x200-0x100` are refused with
  an error naming the rule and the entry. A stored configuration with such an
  entry starts in management recovery until a valid configuration is
  committed. Before, the engine skipped such entries, so a rule matched only
  its valid entries.
- SSH CLI sessions call the management API over HTTPS when the HTTP listener
  is disabled, trusting only the certificate the HTTPS listener serves. SSH now
  stays off only when neither listener is bound. The in-app console and SSH use
  the same loopback connection, and neither follows a redirect.
- Firewall rules with a schedule no longer re-read the schedule or its
  timezone for each packet: schedules are parsed once per applied ruleset.
- Rule matching parses addresses once per applied ruleset, and the engine
  caches each zone's networks until the kernel reports a link or address
  change. Inline ICS packets no longer read the interfaces or allocate memory
  for rule and zone scope checks.
- In split mode the ruleset preview admits the same management listeners
  that management applies, including listeners still bound until a restart:
  management compiles the previewed snapshot, as it does for apply.
- Validation refuses zone names that are blank, longer than 125 bytes, or
  have leading or trailing whitespace. A stored configuration with such a
  zone fails validation at boot, and management starts in recovery until it
  is fixed.
- A failed ruleset apply no longer hides the ruleset still in force. The
  engine ruleset status keeps the installed revision and adds the failed
  snapshot and its error, rule counters keep working, and health reports
  `enforcement.state: degraded`.
- The Secure by Design page maps all seven CISA pledge goals again and credits
  the default design. Operator steps are deployment guidance. No goal has a
  design gap.
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

- A gateway whose interface is a logical name (such as `wan`) now resolves to the interface's device, as route interfaces already did. Before, a route without its own interface through such a gateway failed with "route interface not found".
- `set outbound quickstart` guesses the WAN gateway as the web UI does: the other address of a /31, and no gateway for a /32 or when the WAN interface holds the first address of its subnet (it used to stage the interface's own address).
- The routing page's Auto WAN default route reads the WAN address as strictly as the firewall quick start, and both infer the gateway the same way: the other address of a /31, and no gateway for a /32 or when the WAN interface holds the first address of its subnet.
- The firewall's outbound quick start binds the wan-gw gateway and default route to the WAN interface's OS device, as Auto WAN and the CLI quick start do.
- The ICS templates and NAT pages show loading until the first answer instead of "No templates available", disabled SNAT, no port forwards or setup tips. NAT settings the server did not return are reported as unavailable instead of being shown, and saved, as disabled NAT.
- The flows list keeps its rows and "Showing x of y" footer during its 10-second refresh.
- Diagnostics refuses IPv4 addresses with leading zeros (such as 192.0.2.07) for temporary host and flow blocks.
- Port fields accept decimal digits only ("1e3" and "0x50" are refused). IPv6 address and CIDR checks now match the server's parser, so inputs such as ":::", "1::2::3" and "10.0.0.0/" are refused.
- The NAT port-forward ingress zone defaults to "wan" only when that zone exists; otherwise a zone must be chosen. Before, the row could show one zone, stage "wan", and fail on save.
- The Publish Internal Service wizard checks the internal server address on the server step and shows the error under the field. A port forward's destination must be IPv4, so other text no longer passes the step only to fail at Stage.
- Adding a port forward on the NAT page refuses a fractional port (it took `1.5` as port 1) and a destination that is not an IPv4 address, instead of failing on save.
- IP address and CIDR fields refuse IPv4 octets with leading zeros (`192.0.2.05`), which the server rejects.
- The Alerts page shows a loading placeholder until the first alert list arrives, instead of the "No alerts yet" empty state.
- The Alerts page hides the earlier alert list while loading fails, as Flows, Templates and Sessions do, instead of showing it beside the error.
- The Publish Internal Service wizard checks the port (1-65535) on the server step and shows the error under the port field, instead of accepting any value until Stage.
- The topology status chip no longer reads ALL NOMINAL while firewall enforcement is degraded or unavailable. It shows the firewall enforcement state from health and, unless enforcing, why: a failed ruleset apply, a degraded schedule planner or health's reason.
- The sessions, NAT, policy wizard, diagnostics (block flow) and dataplane (forward targets) pages format endpoints like the events and flows pages: a missing or zero port shows the address alone, and an IPv6 address with a port is bracketed (`[2001:db8::5]:502`).
- Syslog RFC 5424 events and the web UI (events, flows, alerts, dashboard) show an endpoint without a port when the event has none, as for ICMP and ICMPv6 rule hits, and bracket an IPv6 address that has a port (`[2001:db8::1]:2404`). Before, syslog printed `addr:0` and the UI printed `addr:`.
- Firewall rule hits logged through NFLOG for ICMP and ICMPv6 packets now carry their source and destination addresses and transport `icmp` or `icmpv6`, without ports.
- SSH is recorded as a bound management listener only after its socket binds. A failed SSH bind leaves SSH off with a listener fault instead of reporting it enabled; HTTP and HTTPS are unaffected.
- HTTP redirects to HTTPS only when the HTTPS listener bound.
- SSH exec requests report exit status 0 on success and 1 on a failed or empty command, and the appliance shell reports 0 when it closes, so OpenSSH clients no longer exit 255.
- With the Linux shell (`ssh.shellMode` linux), a shell killed by a signal reports exit-signal with the signal's name (RFC 4254) instead of exit status 4294967295, and a shell wait error reports 1 instead of 0.
- In an IEC 104 enforce envelope, the server's RST refusing a client's SYN (for example, a station that does not listen on 2404) now reaches the client, which fails at once instead of retrying its SYN until it times out. Every other packet before the SYN-ACK, apart from the client's SYN, is still dropped.
- An IEC 104 client that lost its connection without closing it, for example
  by restarting, reconnects at once from the same source port in an enforce
  envelope instead of being dropped until the session idles out.
- With redirect-http-to-https enabled and HTTPS not served (disabled, or its
  certificate failed at boot), the HTTP listener no longer redirects to a port
  nothing listens on.
- The in-app console and SSH no longer call an HTTP listener that redirects to
  HTTPS; they call HTTPS.
- The in-app console pins the certificate the HTTPS listener serves. Before,
  it pinned the saved setting, which a listener fallback or a certificate path
  saved after boot can make differ.
- Management listener readouts agree with what is served. The TLS settings
  show the effective listeners, including environment overrides. The console
  calls the bound HTTP listener. SSH no longer falls back to port 8080: with no
  bound HTTP or HTTPS listener it stays off and reports a fault. `show system` always
  shows `ssh.listen`, and both saved-settings views say they exclude
  environment overrides.
- Web UI: the zone form refuses names longer than 125 bytes or with leading
  or trailing whitespace before saving, as the server does, and shows the
  server's error if one comes back.
- A rule whose ICS `addresses` list holds only unparseable values no longer
  matches every address; it matches none.
- Management-reservation validation treats a blank HTTPS or SSH listen
  address as the default address that management binds, so a blank value no
  longer hides a conflict with the reserved port.
- `containd healthcheck` and `containd cli` refuse a `CONTAIND_MGMT_ADDR`
  with no port instead of probing it.
- Web UI: the login password and MFA steps, own password change and MFA
  disable show the server's lock message and when to try again after a `429`,
  instead of a generic failure. A wrong current password or code in the
  profile dialog shows the server's message instead of "Unauthorized".
- Web UI: user management actions, MFA actions included, and the AV, DNS,
  NTP and syslog Save buttons show pending and saved feedback. The acting
  button is disabled while its save runs, so a double click submits once.
- Web UI: a page shows the data as unavailable instead of crashing when an
  API response has the wrong shape. Shape checks cover 18 list and object
  routes. The topology view reads health from the shared health store.
- Management INPUT admits the listeners management serves: HTTPS on its
  default port when its settings are unset, the addresses set by
  `CONTAIND_MGMT_ADDR`, `CONTAIND_MGMT_HTTPS_ADDR` and `CONTAIND_SSH_ADDR`,
  and, until a restart binds a committed listener change, the listeners still
  bound. Management recovery admits the bound listeners instead of always
  adding the appliance defaults.
- Zones whose names differ only in case, spaces, hyphens or underscores get
  separate nftables interface sets; before, their sets merged, so local input
  and NAT rules for one also matched the others' interfaces. Zone sets are
  named `zone_<hex-encoded name>`; a zone with interfaces can have a name of at
  most 125 bytes.
- The rule impact preview no longer warns that a zone has no interfaces when
  the running configuration assigns some.
- After enforcement is turned off, the ruleset status reports no installed
  ruleset instead of the deleted one.
- The engine ends the inspection streams of a connection it forgets when a
  handshake contradicts the connection's recorded direction, so failed and
  fail-closed streams no longer stay in memory until the next reconfiguration.
- The syslog forwarder no longer reads its format without a lock while a
  configuration is applied.
- `show syslog status` and `show services status` print the forwarders'
  protocols.
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
- `GET /api/v1/anomalies` and `show anomalies` list the protocol anomalies the
  engine detected, and `DELETE /api/v1/anomalies` clears them. Before,
  management never reached the engine's anomaly detector: the list was always
  empty and a clear did nothing.
- The learn mode API reads the engine's learner: `GET /api/v1/learn/profiles`
  lists learned profiles, `POST /api/v1/learn/generate` and
  `POST /api/v1/learn/apply` use rules generated from them, and
  `DELETE /api/v1/learn` clears them. Before, management never reached the
  engine's learner: profiles and generated rules were always empty.
- The signatures API reads and changes the engine's signature set:
  `GET /api/v1/signatures` lists the loaded signatures, `POST` adds a live
  signature until the engine restarts, `DELETE /api/v1/signatures/{id}` removes
  one and `GET /api/v1/signatures/matches` lists recent matches. Adding an ID
  that is already loaded returns `409`. Before, management never reached the
  engine: the lists were always empty and adds and deletes failed.
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

- The unused top-level `export` configuration section and the unwired `pkg/dp/export` DPI event exporter. Stored and imported configurations that still contain `export` load normally; the section is ignored and dropped on the next save.
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

[Unreleased]: https://github.com/tonylturner/containd/compare/v0.1.37...HEAD
[0.1.37]: https://github.com/tonylturner/containd/compare/v0.1.36...v0.1.37
[0.1.36]: https://github.com/tonylturner/containd/compare/v0.1.35...v0.1.36
[0.1.35]: https://github.com/tonylturner/containd/compare/v0.1.34...v0.1.35
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
