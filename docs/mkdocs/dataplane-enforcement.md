# Enforcement Strategy

- **nftables**: zone firewall, NAT (SNAT masquerade + DNAT port forwarding), conntrack for state tracking, dynamic sets/maps for performance. This is the primary enforcement path.
- **NFQUEUE selective DPI steering**: flows matching DPI criteria are diverted to userspace via NFQUEUE; all other traffic stays on the kernel fast path. Per-flow verdict caching (TOCTOU-safe) avoids redundant inspection.
- **Userspace enforcement**: compile/install nftables rules, dynamic set updates on IPS/AV/signature verdicts, host and flow blocking via `POST /api/v1/dataplane/blocks/host` and `POST /api/v1/dataplane/blocks/flow`.
- **Verdicts**: allow/deny/reset, alert-only, temp block (flow/host), rate-limit, tag.
- **eBPF (XDP/TC)**: optional acceleration for early packet drops, hardware counters, and kernel-to-userspace event streaming. Enabled when kernel support is available; does not replace nftables.
