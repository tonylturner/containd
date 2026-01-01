# Data Plane Packages

Skeleton for capture, flow tracking, enforcement, DPI/ICS decoders, IDS, and engine coordination.

Current subpackages:
- `capture`: AF_PACKET capture worker (Linux) with interface validation; NFQUEUE steering planned.
- `engine`: orchestrates capture, immutable rule snapshots, and verdict application.
- `flow`: flow/session tracking primitives.
- `rules`: compiled firewall snapshot structures and evaluator (zones/CIDRs/proto/port, plus ICS/identity predicates).
- `verdict`: verdict/action model used by enforcement paths.
- `enforce`: nftables compile/apply path (baseline enforcement + dynamic sets).
- `dpi`: selective inspection framework with protocol decoders and event emission.
- `ics`: OT protocol decoders (Modbus/TCP today).
- `ids`: IDS rules engine over DPI events.
- `itdpi`: IT metadata decoders for DNS/TLS/HTTP and related protocols.
- `events`: in-memory event/flow store for UI/API consumption.
- `pcap`: capture/replay/forwarding helpers for diagnostics and sensors.
- `netcfg`: netlink helpers for interfaces, routes, and policy routing.
