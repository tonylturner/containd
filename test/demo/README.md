# Recorded demonstration traffic

`manifest.json` selects the existing Modbus, DNP3, IEC104, CIP and IT recordings.
It references repository-relative paths, without duplicating capture bytes.
Both the combined appliance and the split engine image install this manifest,
`NOTICE`, the selected files and their fixture licenses below
`/usr/share/containd/demo`, preserving those paths. `LoadCaptureSet` expects
this installed directory layout, with `manifest.json` directly below its root.
Tests stage the same layout in a temporary directory.

The recordings are Apache-2.0 fixture data. Generator software is not included.
Eight recorded-then-edited negatives are explicitly marked `mutated: true`:
Modbus `bad-layout`, `bad-length`, `pid-nonzero`, `truncation`; DNP3 `crc-flip`,
`header-crc`, `qualifier-tail`; CIP `udp-short-mutation`. IEC104 `malformed`
was recorded from a malformer client and is **not** byte-edited. See each
family's testdata README and mutation recipes for provenance and limits.
The byte-built `test/identify` fixtures are not part of this set.

## Illustrative topology and pacing

This is recorded traffic on an illustrative topology, not measured routed
traffic or evidence that policy would forward a packet. ICS clients map to
`dmz` and servers to `lan`; IT clients map to `lan` and servers to `wan`.
When a default zone is absent, the client/server roles fall back respectively
to the first/second non-`mgmt` configured zones, repeating the only zone when
just one exists. Same-zone traffic does not charge a conduit.

Configured zone index `k` maps to `198.18.k.0/24`, with pseudo-interface
`demo:<zone>` and role `leaf`. The first capture uses client `.10` and server
`.20`; later capture endpoints and additional hosts use `.21+` in manifest
order, keeping independent recordings out of each other's transport state.
The address plan supports zone indices 0–255 and up to 234 extra endpoints.
Original endpoint addresses remain in the manifest. Client ports are normalized
to 20000–60999 in first-observed order. Each loop uses a disjoint port block,
whose width is the recording's number of distinct client ports; blocks wrap
when the next whole block would exceed 60999.
Server ports, payloads and sequence numbers do not change. This includes
normalizing service-bound recorded clients such as Modbus source port 502;
the original role is retained in the manifest. Port rotation is finite and
does not promise globally unique flow tuples forever.

Replay waits clamp each recorded inter-frame gap to 100 ms–5 s, including
equal/backward timestamps, with 10 s between captures and at the loop boundary.
Injection timestamps are current time. This is a paced demonstration, not
original-rate forensic replay. Interface bytes use PCAP original link-layer
length, with tx on the sender and rx on the receiver. Conduit bytes subtract
the Ethernet/VLAN header. Both count frames, not decoded application objects.
Totals accumulate across captures and loops, reset per Run and use the caller's
run id as their epoch; stopped runs publish no samples.

The processor must handle a packet promptly. Replay calls it synchronously,
and returning from Run joins all packet handling without a helper goroutine.
Derived rule snapshots retain operator ICS ids/actions in monitor mode and
operator IDS inputs, and add an any-address IEC104 monitor envelope only when
the operator has no IEC104 rule. Parsing modes and signatures are independent
processor settings; snapshot derivation does not change them.
