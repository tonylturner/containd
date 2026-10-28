# EtherNet/IP reference capture tooling

The unmodified OpENer POSIX sample is the explicit/I/O adapter; cpppo 4.4.3
is the MSP adapter. EIPScanner is the scanner for both. `source-lock.json`
pins all three source commits and archive SHA256 values; `requirements.lock`
pins cpppo's greenery dependency and source archive hash. The image
pins its Debian base digest and a dated package snapshot. `LICENSES/` retains
upstream licenses; `NOTICE` describes the tools and independent oracle.

`scanner.cpp` uses EIPScanner's service API for UCMM and its encapsulation/CPF
serializers for class 3 SendUnitData. Class 1 I/O uses its ConnectionManager.
`msp-scanner.cpp` assembles the **request** MSP offset table locally and passes
it through the generic service API. `cpppo-adapter.py` configures one INT array
and uses cpppo's supported shutdown control API; it does not change protocol
handling. Its unused UDP listener is disabled to allow orderly shutdown. Every
response comes from the real adapter; OpENer and EIPScanner serialize their own
I/O datagrams. There is no reply rewriting and no
containd in the path.

## Generate

Prerequisites: Docker Desktop, Python 3, tshark **4.6.7**, Bash, SHA256 tooling.
Run from the checkout root, choosing new absolute output directories:

```bash
bash test/cip/capture/capture.sh "$PWD/build/cip-runs/explicit" explicit
bash test/cip/capture/capture.sh "$PWD/build/cip-runs/connected" connected
bash test/cip/capture/capture.sh "$PWD/build/cip-runs/io" io
bash test/cip/capture/capture.sh "$PWD/build/cip-runs/msp" msp
bash test/cip/capture/capture.sh "$PWD/build/cip-runs/msp32" msp32
```

Before relying on cpppo, the scanner verifies every returned child header and
count: the mixed Get/Set Attribute request executes three successful children;
the boundary case returns all 32 successful children. The adapter's real MSP
implementation is also in `server/enip/device.py`, `Message_Router.request`.

The following **failed coverage probe** exits **1**, preserving its pcap, scanner
exit status and endpoint/capture logs. Do not ignore that exit code:

```bash
bash test/cip/capture/capture.sh "$PWD/build/cip-runs/msp-error" msp-error
```

The nonexistent attribute 99 fails for real (`0x08`), but cpppo returns MSP
wrapper status **0**, not the required **0x1e**. Its Message Router sets wrapper
status 0 unconditionally after processing children. This is labelled stack
deviation evidence, not positive 0x1e coverage. No response is synthesized or
repaired. OpENer remains the adapter for all non-MSP scenarios; its unsupported
MSP probes are not retained.

To assemble the successful exchanges and explicitly labelled failure evidence:

```bash
python3 test/cip/capture/assemble.py build/cip-runs "$PWD/build/cip-new-testdata"
(cd build/cip-new-testdata && shasum -a 256 -c SHA256SUMS)
```

Assembly rejects a failed positive, an unexpectedly successful 0x1e probe,
missing observed layouts, empty captures, TCP loss/retransmission or malformed
pristine traffic. It does not convert the failed probe into positive coverage.
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

`finalize.py` expects no conformance or undecoded codes on reference traffic.
Attribute values, service parameters, known command bodies and CPF metadata
are data, not unwalked protocol structure. The short-UDP mutation alone expects
`cip.cpf_layout`. There is no complete CIP conformance claim.

Tool checks:

```bash
python3 -B -m unittest discover -s test/cip/capture -p 'test_*.py' -v
bash -n test/cip/capture/capture.sh test/cip/capture/export-oracle.sh
shellcheck test/cip/capture/capture.sh test/cip/capture/export-oracle.sh
```
