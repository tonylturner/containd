# Enforcement Strategy

- Baseline: nftables for firewall/NAT, conntrack for state, dynamic sets/maps for performance.
- Userspace: compile/install nftables rules, selective DPI/IDS via NFQUEUE/AF_PACKET mirrors, dynamic set updates on IPS verdicts.
- Verdicts: allow/deny/reset, alert-only, temp block (flow/host), rate-limit, tag.
- Optional: eBPF (XDP/TC) for early drops/counters and kernel-event streaming; must remain optional.
