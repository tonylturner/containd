# Modbus/TCP capture generator

The client and server run unmodified **pymodbus 3.11.4**, BSD-3-Clause, on a
private Docker bridge. No firewall or containd decoder participates. The
adapter asserts responses and reads back changed datastore values; client
failures stop capture generation. tcpdump shares the server network namespace.
Only invocation-owned containers and networks are removed.

The Dockerfile pins the available offline bootstrap image by digest and
verifies pymodbus's version. That image contains Python 3.11.2-1+b1,
tcpdump 4.99.3-1 and iproute2 6.1.0-3 on Debian 12/arm64.
`source-lock.json` inventories the installed Python source and distribution
metadata by SHA256; pymodbus has no runtime Python dependencies. The original
BSD notice is in `LICENSES/pymodbus.txt`.
The upstream release tag resolves to commit
`bf0e1b67233b4f65bde531c51fea97e461927ef3`. All 58 inventoried source/metadata
files also match the official wheel, SHA256
`89865929f53bd5e32b4076dde00ee86d9b8afb1686832ed74e69d55df22729c3`,
locked in `requirements.lock`. To repeat that independent check, download the
wheel URL in `source-lock.json` and run
`python3 test/modbus/capture/verify-wheel.py <wheel-path>`.

The bootstrap digest is **local**, not a published Docker Hub dependency.
On a new host, transfer it with `docker save`/`docker load` before building.
There is no claim that a fresh apt/PyPI rebuild will reproduce this image.
The generated image's actual identities are retained in
[`../testdata/images.json`](../testdata/images.json).

From the repository root, with Docker Desktop running, Python 3 and host
tshark **4.6.7** installed:

```bash
bash test/modbus/capture/capture.sh "$PWD/build/modbus-captures"
cp build/modbus-captures/*.pcap build/modbus-captures/*.log build/modbus-captures/images.json test/modbus/testdata/
python3 test/modbus/capture/mutate.py test/modbus/testdata
bash test/modbus/capture/export-oracle.sh test/modbus/testdata
python3 test/modbus/capture/finalize.py test/modbus/testdata
(cd test/modbus/testdata && shasum -a 256 -c SHA256SUMS)
GOFLAGS=-mod=mod go test ./pkg/dp/ics/modbus -run TestReferenceCaptureManager
```

Captures contain full handshakes, so session roles come from the opener, not
port heuristics. Docker allocates the network automatically; no host ports
are published. Generation requires the bootstrap image locally, not external
network access. To check the installed source lock:

```bash
docker run --rm --name containd-corpus-modbus-lock-check --pull=never \
  -v "$PWD/test/modbus/capture:/capture:ro" \
  modbusspan-tools@sha256:2bbeea56d58c5192ebda1d8314637c3c9995341df21e733110405040bae77fbc \
  /venv/bin/python /capture/source-lock.py > build/modbus-source-lock.json
cmp test/modbus/capture/source-lock.json build/modbus-source-lock.json
```

The oracle exporter records only independent tshark observations, with explicit
TCP reassembly, out-of-order reassembly, Modbus desegmentation and UINT16
register preferences. `finalize.py` separately declares decoder expectations;
it never invokes containd. The four negative pcaps are mutations with exact
parent SHA256, original frame and payload/file offsets in `mutations.json`.
IPv4/TCP lengths and checksums are repaired only on those modified frames.

Diagnostics use the serial-line profile in MODBUS Application Protocol
Specification V1.1b3 §6.8.1, pp.22–24. Subfunctions 3, 10 and 20 respectively
change the ASCII delimiter, clear counters/register, and clear overrun
counter/flag. Subfunction 4, not 3, forces listen-only mode.
The reviewed PDF is available from
<https://www.modbus.org/file/secure/modbusprotocolspecification.pdf>,
SHA256 `f80d0d7132fd035104c3f21b01026470e3310ca3d8d493d9a9737d0d32ad2eb1`.
