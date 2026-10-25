# Product Roadmap

This page is the single product roadmap for containd. It replaces the short
security roadmap that used to live in [Secure by Design](secure-by-design.md).

The roadmap comes from the 2026-10-25 maturity audit of branch `iec104` at
`40ec7f81`. The full audit reports are in the repository at
`docs/audits/2026-10-25/`. Item IDs in brackets point to findings in those
reports (see [Finding IDs](#finding-ids)).

## Product Frame

containd is a containerized industrial firewall for **testing, training, and
protecting containerized workloads**.

- **Goal:** a very mature firewall for RangerDanger labs, ICS security
  courses, and Docker/Compose workload segmentation.
- **Priority capabilities:**
    - secure remote access (SRA), because the next RangerDanger lab is an SRA
      lab;
    - industrial DPI that is correct on the wire;
    - a firewall that is fast and efficient, shown by measurements.
- **Non-goal:** a production firewall that protects physical interfaces.
- **Out of scope:** an installable ISO or appliance image. That is likely a
  future, separate project.
- **Also not planned:** a replacement Kubernetes CNI, a home-grown remote
  desktop stack, or compliance certification claims. IEC 62443 mappings are
  teaching evidence only.

## Principles

1. **Truth before breadth.** The audit found that the largest gap is not
   missing features. It is controls that are accepted but not enforced, and
   "saved" shown as "protecting". Fix truth first.
2. **Saved, applied, and protecting are three states.** Every surface (API,
   CLI, UI, events) shows which one is true.
3. **Reject what we cannot enforce, then build it.** An unsupported
   predicate, import construct, or service option is rejected or labelled
   non-enforcing. It is never accepted silently. A label is only an interim
   state: every capability that does not work yet has its own track item
   below, and that item ends with the capability working. We never "remove
   the scaffolding" or "mark it unavailable" as the plan.
4. **Integrate, do not reinvent.** containd owns the network boundary. An
   external SRA broker owns human identity, approvals, protocol sessions, and
   recordings.
5. **Every claim has a test.** A lab claim needs a packet-path or
   server-state test, not a rendered config or a mocked UI route.

## Status

| Release | Content | State |
|---|---|---|
| 0.1.32 | Current `main` and `:latest` | Released |
| 0.1.33 | IEC 104 monitor types 5, 7, 9, 11, 15, 21, and 30–37; reserved management path; staged configuration with a global commit bar; base-path assets; engine-owned rule preview; IEC evidence retention and query; release gate (1.11); S7 and RDP X.224 wire-byte fixes; transport accounting once per packet; capture-derived IEC 104 regression corpus; imported rules without executable content no longer alert on every event | In progress on `iec104` |

`:latest` moves only after a complete work effort is tested and merged to
`main`. Older RangerDanger releases pull `:latest`.

## Stage 1 — Trust Baseline

Prerequisite for the SRA lab. Each item is a separate change with its own
tests.

| # | Outcome | Findings |
|---|---|---|
| 1.1 | The engine control API is private: loopback or authenticated transport only; no unconditional TCP/8081 accept. | QS-Q1 |
| 1.2 | One account-assurance contract for web, SSH, and CLI: forced password change and MFA apply to SSH; credential and MFA changes revoke sessions; MFA challenges are single-use; the last admin cannot be demoted; login throttling ignores the source port; login redirects stay on-origin. | SRA-H1–H3, M9–M11; QS-Q2, Q3, Q18, Q19; CP-F8; UI-U11 |
| 1.3 | Two explicit deployment profiles: **training** (open, convenient) and **strict** (no universal bootstrap, HTTPS-first writes, Secure cookies, no Docker socket, management published on loopback). Neither silently falls back to the other. | QS-Q4–Q8, Q15 |
| 1.4 | The wire enforces what the policy says: reject identity and schedule predicates on kernel-only rules; bind DNAT accepts to the translated destination and a policy allow; first-match-in-listed-order precedence for kernel, evaluator, and preview (decided); owned-table apply that keeps other tables and active blocks; explicit established-flow behavior on policy change; reject unsupported IPv6 and domain exclusions. | SRA-H10, L1; DP-2–5, 10, 20, 27, 28 |
| 1.5 | Interface, DHCP, and WireGuard addressing keeps the host IP; address reconcile removes only owned addresses; correct netlink subscriptions. | DP-1, 21; SRA-H7 |
| 1.6 | Desired, applied, and protecting revisions with retry on the same boot and a readiness signal that means "protecting". | DP-8, 16; CP-F14, F18; SRA-M1 |
| 1.7 | No silent data loss on writes: CLI and UI read-modify-write fail on a failed read and keep unrelated fields (NAT, proxies, syslog, IDS rules, service drafts); PCAP apply and template preview use the real API shapes. | SRA-H8, M8; DP-23; ICS-D05, D23; CP-F10, F20; UI-U01, U02, U04, U06–U08 |
| 1.8 | Remote-access transports are configured safely: TLS without a certificate fails; daemon directives cannot be injected; OpenVPN restarts on change, finds its files, and can revoke a client; proxy controls that are not enforced are rejected. | SRA-H4–H6, H9, M2, M3; CP-F9 |
| 1.9 | Evidence is complete and loss is visible: syslog forwards both engine and management events; audit records account, role, credential, and TLS changes; audit write failures are reported. | CP-F1, F2, F7, F21; SRA-M4, M5; QS-Q11 |
| 1.10 | Docs match code. Until its track item lands, each capability shows its true current state in docs, API, and UI: eBPF (P.3), traffic graphs (O.1), IEC 62443 view (O.2), YARA (D.3), external rule imports (D.2). This is interim. The track items make each capability work. | DP-14, 24; QS-Q16, Q21; UI-U03, U09, U10; ICS-D02, D26 |
| 1.11 | Release gate: a tag moves `:latest` only from `main`, after CI, signing, and SBOM for the exact commit. Prereleases never move `:latest`. | QS-Q12, Q13 |

## Stage 2 — Secure Remote Access Lab

The priority capability. Depends on Stage 1 items 1.1–1.6 and 1.8.

### Responsibility split

| Owner | Responsibilities |
|---|---|
| **containd** | Zones and conduits; broker-to-asset allowlists; VPN transport; ICS enforcement on inspected links; **grant-bound network leases** with engine-local hard expiry; flow and conntrack termination; network evidence. |
| **SRA broker** (external) | Identity federation and MFA; vendor and sponsor lifecycle; request and approval; per-session authorization; credential injection; SSH, RDP, VNC, and HTTP sessions; recording; supervisor view and termination. |
| **RangerDanger** | Lab narrative, simulated OT impact, scenarios, and pass/fail checks. |

Many users share one broker IP. The firewall cannot tell them apart, so broker
admission stays authoritative. Killing access closes the remote channel; it
must not stop the PLC or the process.

### Items

| # | Outcome | Findings / source |
|---|---|---|
| 2.1 | SRA contract: personas (operator, sponsor, vendor, auditor), first protocol, broker and IdP choice, strict-profile rules. | SRA §4.2, N4; UI N1 |
| 2.2 | Grant and lease API: a narrow machine-authenticated adapter (not an admin session) takes grant ID, subject, asset, protocol, deadline, and reason, and returns an applied lease ID and revision. Leases expire in the engine even if management is down, and are reconciled on restart. | SRA X1, X2; DP X2 |
| 2.3 | Active revocation: expiry, revoke, or account disable closes established flows and conntrack and denies reconnects, without collateral damage to other sessions. | SRA M6, X2; DP-18, 27 |
| 2.4 | Broker integration on a reference Compose topology: broker in a DMZ zone, one unavoidable conduit through containd to each approved asset. | SRA X3, §6 |
| 2.5 | SRA operator UI: requests, approvals, active sessions, terminate, expiry. The current **Sessions** page (conntrack) is renamed **Connections**. | UI X1, X5 |
| 2.6 | Correlated evidence: identity → approval → lease → flow → rule → recording reference, exportable without secrets. | SRA X3; UI X3; DP X4 |
| 2.7 | Golden Compose topology and bypass matrix: same-network peers, alternate networks, published ports, direct addresses, IPv6, and crash/restart are tested and denied. | DP N5 |
| 2.8 | RangerDanger SRA acceptance scenarios (owned by RangerDanger): stolen password cannot launch access; wrong asset and self-approval are denied; active sessions end on expiry, idle, and revoke; recordings link to the approval. | SRA §6 |

## Capability Tracks — Industrial DPI and Performance

Priority capabilities. These tracks run beside Stages 1 and 2 when their
dependencies allow. They do not wait for Stage 3. Each item has its own
ticket, and each item ends with the capability working and measured.

### Industrial DPI

| # | Outcome | Findings / source |
|---|---|---|
| D.1 | ICS DPI wire conformance: an independent corpus derived from captures for every decoder (request, reply, error, split, coalesced, retransmitted). Fix OPC UA service IDs, CIP connected and response layouts, BACnet CreateObject, Modbus address scope and diagnostics, DNP3 fragments, and MMS attribution. S7 and RDP X.224 bytes ship in 0.1.33. | ICS-D03, D04, D07–D12; ICS N3, X1 |
| D.2 | Imported Suricata, Snort, and Sigma rules execute with their full meaning (content, offsets, PCRE, flow, ports, addresses, modifiers) for a declared subset. The importer rejects constructs outside the subset, and the subset grows. Group disable is enforced. | ICS-D02, D06, D16, D17, D27; ICS N1, L2 |
| D.3 | YARA rules execute on reassembled payloads and on transferred files, through an embedded YARA engine. | ICS-D02 |
| D.4 | Passive IEC 104 inventory: controlling and controlled stations by session direction, observed CA, IOA, and types, last seen, attempted versus accepted. Bounded, and separate from the learner. | IEC backlog 6; ICS-D15 |
| D.5 | IEC 104 holdback pressure: held packets and bytes, pending age, timeout and bound aborts, verdict failures, in a diagnostics view. | IEC backlog 7 |
| D.6 | IEC 104 APCI lifecycle anomalies: I-frames before STARTDT or after STOPDT, impossible sequence and ACK transitions, stalled TESTFR. Observational first. | IEC backlog 9 |

### Firewall performance and efficiency

| # | Outcome | Findings / source |
|---|---|---|
| P.1 | Measured baseline: compile and apply at 10, 100, 1000, and 10000 rules; flow churn, long sessions, mixed and DPI traffic; p50, p95, p99 latency, throughput, CPU, memory, and queue loss on Linux Docker and Docker Desktop. Published numbers and CI trend gates. | DP P1, X3; QS-Q17 |
| P.2 | Efficiency: bounded aggregate flow, stream, and stats state; precomputed zone and rule matching (no per-event syscalls, no linear scan); batched block updates; queue, NFLOG, and parser loss counters. | DP-9, 19; DP X3 |
| P.3 | eBPF fast path, made real: XDP and TC programs that consult correct maps, atomic map sync with TTL expiry, counters, a tested attach matrix with fallback, and verdict parity with nft. P.1 measures its benefit. | DP-14; DP L3 |

### Honest operator views

| # | Outcome | Findings / source |
|---|---|---|
| O.1 | Real telemetry in place of synthetic graphs: dashboard, services, and AV charts read stored time series of real counters; demo mode replays recorded captures through the real decoders. | UI-U03, U10; ICS-D20 |
| O.2 | IEC 62443 zone and conduit assessment backed by evidence: target versus achieved security level per foundational requirement, each claim linked to config and test evidence. Teaching evidence, not certification. | UI-U09 |

## Stage 3 — Mature Training Platform

| # | Outcome | Findings / source |
|---|---|---|
| 3.1 | Moved to track item D.1. | — |
| 3.2 | Executable-rule contract: address predicates never compile to ANY. External formats are covered by D.2 and D.3. | ICS-D01, D14 |
| 3.3 | Canonical event contract across live, offline, demo, API, UI, and export; wire the configured SIEM export; bounded flow and stats state; correct packet and byte accounting. | ICS-D21, D24, D25; DP-9, 19; ICS X3, X5 |
| 3.4 | Learn → review → enforce loop with passive inventory (including IEC 104), exact generated rules, and an explicit apply step. | ICS-D14, D15; ICS X2; UI X2 |
| 3.5 | Transactional config revisions with compare-and-set, crash-safe commit-confirmed, and a complete versioned policy bundle (config plus IDS) with explicit secret handling. | CP-F4, F5, F15, F16; CP N3, N4 |
| 3.6 | Automation contract: complete OpenAPI, role matrix tests, CLI parity, structured warnings. | CP-F11, F12, F17; CP X2 |
| 3.7 | Operator UI quality: keyboard and screen-reader task completion, contrast, small screens and zoom, honest unknown and stale states. | UI-U12–U14, U16–U20; UI N2, N5 |
| 3.8 | Guided labs and instructor tooling: versioned scenarios, objectives, checks, checkpoint and reset. | UI X4; CP X4 |
| 3.9 | Assurance: Linux privileged test matrix, browser and backend tests in CI, scheduled fuzzing with a kept corpus, performance trend gates (from P.1), tested least-privilege profiles, continuous supply-chain scans. | QS-Q13, Q14, Q17, Q24; QS N7–N9 |

## Stage 4 — Later, On Demand

- OIDC federation, phishing-resistant MFA, and vendor lifecycle (SRA L1).
- Session and file-transfer governance (SRA L2).
- Outbound site connectors and multi-site isolation (SRA L3).
- Workload identity controller for Docker names and labels (DP X5).
- Kubernetes-adjacent gateway adapter beside Cilium or Calico (DP L2).
- Dual-stack IPv6 and a transparent bridge profile (DP L1).
- New protocols when a lab needs them, MQTT first (ICS L1); versioned
  detection content packs (ICS L2).
- Per-student fleet orchestration (CP L1); virtual failover drills (DP L4).

## Decisions

Decided by the product owner on 2026-10-25.

| Topic | Decision |
|---|---|
| `:latest` promotion | Only tags on `main` move `:latest`, after signing and SBOM. Prereleases never move it. This part of item 1.11 ships in 0.1.33; the CI gate follows in Stage 1. |
| SRA broker | Integrate an existing gateway (Guacamole-class SSH/RDP/VNC) and an OIDC IdP. Do not build a remote desktop stack. |
| SSH native shell | Training profile only. The strict profile disables the native shell, and SSH meets the same MFA assurance as the web. |
| Established flows after a policy change | Leases always terminate existing flows. Ordinary edits keep existing connections, and the UI says so. |
| Rule precedence | First match in listed order, everywhere: kernel, evaluator, and preview. This changes behavior (today the kernel sorts allow before deny). |
| Stage 1 start | Stage 1 starts after 0.1.33 ships. |
| Capabilities that do not work yet | Make each one real under its own ticket. A label or a removal is never the end state. Industrial DPI and firewall performance are priority tracks. |

Still open (decide when the ticket starts):

| Topic | Recommendation |
|---|---|
| External rule formats (D.2) | Execute a declared Suricata, Snort, and Sigma subset with full meaning in the native engine, and reject the rest at import. The alternative is to embed Suricata as a second engine. |
| YARA engine (D.3) | Embed YARA-X through its C API. The alternative is libyara through go-yara. Both need cgo in the image build. |

## Finding IDs

| Prefix | Report in `docs/audits/2026-10-25/` |
|---|---|
| SRA | `secure-remote-access.md` |
| DP | `dataplane-enforcement.md` (numbered findings) |
| ICS | `ics-dpi-ids.md` |
| CP | `control-plane.md` |
| QS | `quality-security-ops.md` |
| UI | `ui-surface.md` |

`research-benchmarks.md` in the same folder lists the external products and
guidance used as benchmarks. Line references in the reports are for commit
`40ec7f81` and drift as the code changes.
