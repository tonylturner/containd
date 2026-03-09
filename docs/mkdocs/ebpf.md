# eBPF

eBPF (XDP/TC programs) provides optional acceleration for early packet drops, hardware counters, and kernel-to-userspace event streaming. The primary enforcement path uses nftables and conntrack, which is always available. eBPF acceleration is enabled when the kernel supports it and can be toggled independently of the nftables path.
