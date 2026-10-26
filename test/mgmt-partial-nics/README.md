# Partial-NIC management smoke

This regression harness checks automatic interface binding and management
reachability when fewer NICs are attached than the configured interface set,
including restart after NIC renumbering. See
[Reserved Management Path](../../docs/mkdocs/management-reservation.md) for
operator configuration.

Run `bash scripts/smoke-mgmt-partial-nics.sh` from the repository root.
It builds the local binary and tests 5, 7 and 8 NICs, each with fresh data,
both with and without a management reservation. Source `.10` and proxy `.3`
must receive HTTP 200 before policy, after policy and after ethN renumbering.
The outsider `.11` follows ordinary policy; all-access-off without a reservation
also denies both named peers.

`rd-policy.json` is an unchanged copy of the RangerDanger readiness probe's
`exact-policy.json` (the RD shipped five-interface policy). It grants lan3
management but **omits dataplane enforcement**, which a full replacement
interprets as false. The smoke checks that actual runtime state after restart,
rather than silently adding enforcement to the fixture. The reserved cases keep
enforcement on while setting every access flag off.

The fixture uses the exact RD subnets and endpoint IPs inside a disposable
`--network none` container with private Linux network namespaces. This avoids
Docker IPAM collisions with an independently running RD lab on 10.99.99.0/24.
Only the appliance namespace has 5/7/8 ethN NICs; the management peers share a
private L2 switch. No host ports, bridges, routes or RD resources are changed.
The script removes its uniquely named container, image and fresh volumes
on exit. Diagnostics remain in the repository's ignored
`build/mgmt-partial-nics.*` directory.
