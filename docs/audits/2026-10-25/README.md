# containd maturity audit — 2026-10-25

Read-only source audit of branch `iec104` at `40ec7f81` (VERSION 0.1.32).
The roadmap built from these reports is `docs/mkdocs/roadmap.md`.

| Report | Scope | Finding IDs |
|---|---|---|
| `secure-remote-access.md` | Identity, SSH, VPN, proxies, SRA target architecture, RangerDanger SRA lab design | SRA-H*, M*, L* |
| `dataplane-enforcement.md` | nftables, NFQUEUE, NAT, netcfg, routing, IPv6, eBPF, Compose packet path | DP-1 … DP-28 |
| `ics-dpi-ids.md` | Industrial and IT decoders, IDS formats, learning, inventory, PCAP, export | ICS-D01 … D27 |
| `control-plane.md` | Config lifecycle, backup, services, audit, syslog, API and CLI contracts | CP-F1 … F21 |
| `quality-security-ops.md` | CI, release, supply chain, deployment defaults, auth assurance, threat model | QS-Q1 … Q25 |
| `ui-surface.md` | Pages, data truth, drafts, accessibility, responsive layout, UI tests | UI-U01 … U23 |
| `research-benchmarks.md` | External products and guidance used as benchmarks | — |

Evidence labels: **Verified** means the code or document was read (and, where
stated, a targeted probe ran). **Inferred** means a consequence or
recommendation. Line references are for `40ec7f81` and drift as code changes.
The IEC 104 work for 0.1.33 was in progress during the audit and is not
re-audited here. Paths written `<audit-artifacts>/…` name probe files that
were kept outside the repository; fix changes turn those probes into
regression tests.
