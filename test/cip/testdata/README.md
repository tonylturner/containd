# EtherNet/IP wire fixtures

These are **diagnostic captures, not a CIP conformance certification**.
They were generated headlessly by CIPDIP commit
`12c7397cf8d1a4d608c82ba3f15c788308636c57` (Apache-2.0), using its original
client API, serializers and adapter server. No bundled captures were used.
Neither endpoint used containd.

## Contents and limitations

* `explicit-io.pcap`: original Ethernet capture, including TCP handshake,
  registration, UCMM read/write/error exchanges, a three-child MSP, a
  ForwardOpen/Close exchange and two UDP datagrams. The TCP scenario selects
  TCP only; the UDP records are retained unchanged in `udp-enip-io.pcap`.
* `udp-enip-io.pcap`: original capture records 18–19, filtered without changing
  packet bytes. Explicit Class 1 configuration was used, including transport
  class trigger 1 and `--enable-udp-io`. Nevertheless, the wire is an entire
  SendUnitData encapsulation with A1/B1 items on UDP/2222, **not** native
  sequenced-address (8002)/B1 I/O CPF. The decoder correctly reports its
  incompatible native-I/O layout. This is not connected-explicit evidence.
* `udp-short-mutation.pcap`: **synthetic negative**, derived from the valid
  UCMM request in `explicit-io.pcap`, record 8. The byte at transport-payload
  offset 47 was removed, leaving the encapsulation length unchanged. TCP
  was replaced with UDP from 49152 to 44818, with corrected IPv4/UDP lengths
  and checksums. It proves a truncated UDP encapsulation is reported once.

CIPDIP's emitted UCMM and MSP replies do not set the service response bit.
For example, original records 9 and 15 start their CIP payloads with `0e`
and `0a`, not `8e` and `8a`. The oracle and decoder both preserve the
wire's request identity; neither imputes a response layout from direction.
The MSP reply-shaped bytes consequently have an invalid request MSP table.
ForwardOpen/Close reply bodies also lack ordinary CIP response headers.
No genuine additional-status reply or MSP status `0x1e` was generated.
Those layouts, real reply headers, nested budgets and connected-explicit
B1 prefixes have separately labelled synthetic unit tests, not captured
positive claims.

The public client interface exposes `InvokeService` only over SendRRData;
its B1 send/receive methods are I/O methods. They were not relabelled as
connected explicit messaging. These generator limitations require another
independent source for complete positive coverage.

`client.log`, `server.log` and `capture.log` preserve endpoint observations.
The unknown-service negative receives an error response, but CIPDIP logs
`ERROR: Handle CIP request error: unsupported service: 0x7E`. The generation
script deliberately exits 1 on that server error rather than claiming a
clean run. The final capture reports 25 packets and zero capture drops.
Docker bridge partial pseudo-header checksums are retained, not repaired
in the original captures; tshark identifies the checksum-offload pattern.

## Reproduction

From the checkout root, with Docker Desktop, Python 3 and tshark 4.6.7:

```bash
CIPDIP_SOURCE=/path/to/read-only/cipdip bash test/cip/capture/generate.sh
# The diagnostic server-error exit described above is expected; inspect logs.
python3 test/cip/capture/derive.py
python3 test/cip/capture/export.py --transport tcp test/cip/testdata/explicit-io.pcap
python3 test/cip/capture/export.py --transport udp \
  test/cip/testdata/udp-enip-io.pcap test/cip/testdata/udp-short-mutation.pcap
```

The generator uses a private, named Docker bridge and no host port bindings.
It builds a pinned `git archive`, never the mutable source checkout.
Its image base digest, direct Debian package versions, source archive hash,
Go module locks, full installed-package inventory and recipe checksums are
recorded under `capture/`. It requires CGO and libpcap-dev. Containers and
the network are removed after capture. On an early error it stops and leaves
only its named resources for diagnosis; it never prunes unrelated resources.

Ephemeral ports, sender context, TCP sequence numbers and timestamps vary on
regeneration. Review the manifest's frame inventory, UDP roles and expectations
against the new independent PDML before refreshing checksums. Do not generate
expected semantic values from containd.

The independent oracle command is:

```text
tshark -n -r CAPTURE -o tcp.desegment_tcp_streams:TRUE -o enip.desegment:TRUE \
  -o enip.o2t_run_idle:TRUE -o enip.t2o_run_idle:FALSE -T pdml
```

`export.py` retains each nested CIP object's own fields and emits one row per
object; it never interprets comma-flattened repeated fields as object structure.
The original PDML is retained beside every TSV. Product expectations are
separate from the oracle and include wire-identity, conformance and coverage
assertions. Tests replay fresh Managers in both position modes, including
TCP splitting, coalescing, reordering and retransmission.

To verify the inventory:

```bash
(cd test/cip/testdata && shasum -a 256 -c SHA256SUMS)
GOFLAGS=-mod=mod go test ./pkg/dp/ics/cip -run TestIndependentCaptures
```
