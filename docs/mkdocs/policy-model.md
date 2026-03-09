# Policy Model

- Zone-based firewall with nftables backend and optional eBPF XDP/TC acceleration.
- Candidate/running configs; commit/rollback/commit-confirmed flows.
- Policies reference zones, CIDRs, assets, and ICS protocol primitives across all 7 supported ICS protocols (Modbus, DNP3, CIP, S7comm, MMS, BACnet, OPC UA) -- including function codes, register ranges, service codes, and read/write classification.
- Schedule predicates enable time-based rule activation (e.g., maintenance windows).
- Identity predicates enable user-based access control on firewall rules.
- 7 ICS policy templates available (Purdue baseline, maintenance windows, per-protocol defaults) via `GET /api/v1/templates/ics` and `POST /api/v1/templates/ics/apply`.
- General policy templates available via `GET /api/v1/templates` and `POST /api/v1/templates/apply`.
- Firewall rule preview via `POST /api/v1/firewall/rules/preview` allows testing rule matches before committing.
- Learn mode generates allowlist rules from observed traffic (see [ICS DPI](ics-dpi.md#learn-mode)).
