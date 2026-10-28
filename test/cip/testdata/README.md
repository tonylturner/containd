# EtherNet/IP reference fixtures

Small, real endpoint captures from **OpENer** adapter commit
`0e1ab7ee5c272950c0dc8daf7793008d7a518912` and **EIPScanner** scanner commit
`12c89a57ec2e7449efb1348be52af10be9ef9701`. MSP uses **cpppo 4.4.3** adapter
commit `00e38df798ed45b35c15454ef376cde7fca76cd2` with the same scanner.
None of the endpoints is containd.
These are interoperability evidence, **not** an ODVA conformance certification.
Pinned sources, licenses, generation commands and limitations are described in
[`../capture/`](../capture/README.md).

| Scenario | Observed coverage |
| --- | --- |
| `explicit` | UCMM read/write requests and replies; success; unknown attribute `0x14`; undersized write `0x13`; rejected ForwardOpen with additional status `0x012f` |
| `connected` | Class 3 ForwardOpen; connected SendUnitData request/reply with A1/B1 and sequences 1/2; success/error replies; successful ForwardClose |
| `io` | Successful class 1 ForwardOpen and ForwardClose, plus the original native UDP/2222 exchanges |
| `native-io` | Unchanged UDP records filtered from `io`; bare CPF 8002/B1 in both directions, not ENIP encapsulation; lineage lists original frame numbers |
| `msp` | Three mixed Get/Set Attribute children executed successfully; request and reply tables |
| `msp32` | Exactly 32 mixed children executed successfully; request and reply boundary |
| `msp-error` | Real nonexistent-attribute child fails `0x08`, but wrapper status is 0; **stack deviation**, not `0x1e` coverage; driver exits 1 |
| `udp-short-mutation` | **Mutation**: native record 1 loses payload byte 51; B1 still declares 34 bytes; IP/UDP lengths/checksums repaired; exact parent SHA/offset in mutation JSON |

cpppo implements MSP, but sets wrapper status 0 even when a child fails. There
is **no positive `0x1e` coverage**. The failed scanner exit and original logs are
retained without claiming success. No reply bytes are synthesized or rewritten.

All reference events have no `conformance` or `undecoded` findings, including
RegisterSession, writes and ForwardOpen socket-address metadata. Operation
values and known metadata are data, not unwalked protocol structure. The
short-CPF mutation has `cip.cpf_layout`. Native I/O is decoded as opaque assembly
data with no guessed service or transport class.

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
