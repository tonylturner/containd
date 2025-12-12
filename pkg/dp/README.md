# Data Plane Packages

Skeleton for capture, flow tracking, enforcement, DPI/ICS decoders, IDS, and engine coordination.

Current subpackages:
- `capture`: packet interception and mirroring scaffolding.
- `engine`: orchestrates capture and immutable rule snapshots.
- `flow`: flow/session tracking primitives.
- `rules`: compiled firewall snapshot structures and evaluator.
- `verdict`: verdict/action model used by enforcement paths.
- `enforce`: nftables compile/apply skeleton (Phase 1 baseline).
- `dpi`, `ics`, `ids`: placeholders for selective inspection and detection.
