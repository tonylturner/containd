# EtherNet/IP reference capture tooling

The unmodified OpENer POSIX sample is the adapter; EIPScanner is the scanner.
`source-lock.json` pins both source commits and archive SHA256 values. The image
pins its Debian base digest and a dated package snapshot. `LICENSES/` retains
upstream licenses; `NOTICE` describes the tools and independent oracle.

`scanner.cpp` uses EIPScanner's service API for UCMM and its encapsulation/CPF
serializers for class 3 SendUnitData. Class 1 I/O uses its ConnectionManager.
The **request** MSP offset table is assembled locally and passed through the
generic service API. Every response comes from the real adapter; both reference
stacks serialize their own I/O datagrams. There is no reply rewriting and no
containd in the path.

## Generate

Prerequisites: Docker Desktop, Python 3, tshark **4.6.7**, Bash, SHA256 tooling.
Run from the checkout root, choosing new absolute output directories:

```bash
bash test/cip/capture/capture.sh "$PWD/build/cip-runs/explicit" explicit
bash test/cip/capture/capture.sh "$PWD/build/cip-runs/connected" connected
bash test/cip/capture/capture.sh "$PWD/build/cip-runs/io" io
```

The following are **failed coverage probes**, not successful generation. Run
and inspect them separately: each currently exits **1**, preserving its pcap,
scanner exit status, and endpoint/capture logs. Do not ignore the exit codes.

```bash
bash test/cip/capture/capture.sh "$PWD/build/cip-runs/msp" msp
bash test/cip/capture/capture.sh "$PWD/build/cip-runs/msp32" msp32
```

OpENer replies with general status `0x08` (service not supported) to both MSP
requests. Its pinned Message Router registers GetAttributeSingle but not MSP.
These captures prove mixed MSP **requests** and the 32-child request boundary,
not child execution, MSP replies or status `0x1e`. Changing the scanner cannot
add a service missing in the adapter. No alternative reply is synthesized.

To assemble the successful exchanges and explicitly labelled failure evidence:

```bash
python3 test/cip/capture/assemble.py build/cip-runs "$PWD/build/cip-new-testdata"
(cd build/cip-new-testdata && shasum -a 256 -c SHA256SUMS)
```

Assembly rejects a failed positive, an unexpectedly successful blocked probe,
missing observed layouts, empty captures, TCP loss/retransmission or malformed
pristine traffic. It does not convert the failed probes into positive coverage.
Review new evidence before replacing the committed fixtures. Copy the consumer
README and LICENSE separately when replacing the directory.

Each invocation owns unique `containd-corpus-cip-*` containers/network, captures
in the adapter's network namespace, publishes no host ports, and cleans up only
its own containers/network even on failure. The reusable image is
`containd-corpus-cip-reference`; remove that image only if you created it.
OpENer's orderly SIGINT exit is 202 (its documented implementation uses
200 + signal); the scanner's actual exit is independently preserved/returned.

`export-oracle.sh` preserves tshark's raw PDML as deterministic gzip and one TSV
row per CIP object. Size-zero inferred request paths are excluded: a response
must not acquire its request's address. Repeated additional-status words and
CPF item types/lengths are JSON arrays, never flattened numeric strings. It
rejects coalesced/partial original ENIP PDUs rather than guessing attribution;
packetization derivatives are exercised independently by the Go replay test.

`mutate.py` filters native UDP records without changing their bytes and records
the original frame mapping. It then removes the final payload byte of native
record 1, preserving the declared B1 length but repairing UDP/IP lengths and
checksums. The mutation metadata names the parent digest and exact byte offset.

`finalize.py` records the current decoder's opaque-body coverage limitations
separately from the independent oracle. It never labels those as adapter wire
violations. There is no complete CIP conformance claim.

Tool checks:

```bash
python3 -B -m unittest discover -s test/cip/capture -p 'test_*.py' -v
bash -n test/cip/capture/capture.sh test/cip/capture/export-oracle.sh
shellcheck test/cip/capture/capture.sh test/cip/capture/export-oracle.sh
```
