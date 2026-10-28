# Independent DNP3 endpoints

The generator uses archived opendnp3 3.1.2 at commit
`26b4c01e4839bbbda8866655e086471c4917ee53` (Apache-2.0), not containd.
The master/outstation drivers adapt the upstream examples and retain their
copyright/license headers. Upstream NOTICE and LICENSE are in `LICENSES/`.
`source-lock.json` authenticates the stack and its three header-only dependencies.
The base image is digest-pinned and Debian packages use a date-pinned snapshot.

Run from the repository root, supplying a **new absolute output directory**:

```sh
bash test/dnp3/capture/capture.sh /absolute/path/to/new-output
```

This is a headless, resource-creating generation command. It builds a named
`containd-corpus-dnp3-*` image and creates only its own private bridge and named
containers. It publishes no host ports, uses no firewall and removes only its
own containers/network. Images and full logs remain for evidence. Build, task,
command-status, capture and coverage failures stop the run. Package versions,
image identity and input hashes are recorded with the manifest. Network access
is required for the pinned Debian snapshot and checksum-locked source archives.

Scenarios isolate link keepalive, startup/integrity, class/range reads,
unsolicited events, CROB select/operate plus direct operate, OBJECT_UNKNOWN IIN,
and a 700-analog response with 1024-byte application fragments (each split into
several link frames). `finalize.py` rejects missing independent observations;
a driver exiting successfully is not coverage proof.

The oracle requires host tshark **4.6.7**. `export-oracle.sh` records explicit
TCP/IP/DNP3 reassembly preferences. PDML subtrees preserve each object and point;
no comma-joined field column is interpreted as an object hierarchy. `raw`
TCP payloads in the TSV always belong to the original capture record.

`mutate.py` derives `crc-flip.pcap` from the named good `class-range.pcap`,
records its parent SHA256, record number and exact pcap byte offset, flips one
DNP3 data CRC byte and repairs that packet's TCP checksum. This is a labelled
mutation, **not traffic emitted by opendnp3**. It is never a framing-header CRC
mutation. Offload checksums elsewhere remain untouched.

After a successful run, preserve only manifest-referenced assets, SHA256SUMS,
README.md and LICENSE in `../testdata/`; full logs and PDML are generation
artifacts, not additional fixtures. Regeneration is semantic, not byte-identical:
ISNs, timestamps, ephemeral ports and unsolicited timing may differ. Do not reuse
historical routed captures: they can include a firewall and cannot prove this
direct-endpoint topology.

Additional named-parent mutations cover a bad framing-header CRC (records end
at the target packet, without fabricating FIN) and a reserved qualifier followed
by an uninspected object tail. Qualifier mutations repair DNP3 data CRCs before
repairing TCP; their explicit coverage expectations are separate from tshark's
observations. No mutation is described as traffic emitted by the stack.
