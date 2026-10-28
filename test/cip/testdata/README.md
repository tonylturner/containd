# EtherNet/IP reference fixtures

Small, real endpoint captures from **OpENer** adapter commit
`0e1ab7ee5c272950c0dc8daf7793008d7a518912` and **EIPScanner** scanner commit
`12c89a57ec2e7449efb1348be52af10be9ef9701`. Neither endpoint is containd.
These are interoperability evidence, **not** an ODVA conformance certification.
Pinned sources, licenses, generation commands and limitations are described in
[`../capture/`](../capture/README.md).

| Scenario | Observed coverage |
| --- | --- |
| `explicit` | UCMM read/write requests and replies; success; unknown attribute `0x14`; undersized write `0x13`; rejected ForwardOpen with additional status `0x012f` |
| `connected` | Class 3 ForwardOpen; connected SendUnitData request/reply with A1/B1 and sequences 1/2; success/error replies; successful ForwardClose |
| `io` | Successful class 1 ForwardOpen and ForwardClose, plus the original native UDP/2222 exchanges |
| `native-io` | Unchanged UDP records filtered from `io`; bare CPF 8002/B1 in both directions, not ENIP encapsulation; lineage lists original frame numbers |
| `msp` | Three-child mixed read/write/error-path request; **blocked** response `0x08`, not `0x1e`; driver exits 1 |
| `msp32` | Exactly 32 request children; **blocked** response `0x08`, no executed child replies; driver exits 1 |
| `udp-short-mutation` | **Mutation**: native record 1 loses payload byte 51; B1 still declares 34 bytes; IP/UDP lengths/checksums repaired; exact parent SHA/offset in mutation JSON |

The pinned OpENer Message Router does not implement MSP. There is **no positive
MSP reply or `0x1e` coverage**. The negative status is a conformant unsupported
service reply, not a wire deviation. Its requests remain useful captured input,
but the failed scanner exits and logs are retained without claiming success.

The decoder deliberately reports `cip.service_payload_unsupported` for nonempty
service bodies, `cip.encapsulation_payload_unsupported` for RegisterSession
bodies, and `cip.cpf_item_unsupported` for ForwardOpen's socket-address item.
These are **current decoder coverage limitations**, not OpENer defects. Their
expected locations are explicit per object. All pristine events have no
`conformance` findings; the short-CPF mutation has `cip.cpf_layout`. Native I/O
is decoded as opaque assembly data with no guessed service or transport class.

Each pcap has a tshark 4.6.7 TSV and compressed raw PDML oracle, separate product
expectations, and SHA256 inventory. TSV excludes tshark's size-zero inferred
response paths and preserves repeated additional statuses as arrays. Original
Docker bridge checksum-offload artifacts are retained, not rewritten. TCP
captures include their handshakes and are pristine/contiguous. Go replay tests
use fresh Managers in both positioning modes and test split, coalesce, reorder,
retransmit and combined transforms; fuzz inputs come from the same pcaps.

```bash
(cd test/cip/testdata && shasum -a 256 -c SHA256SUMS)
GOFLAGS=-mod=mod go test -race ./pkg/dp/ics/cip/...
```
