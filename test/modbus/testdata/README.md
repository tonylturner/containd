# Modbus/TCP reference captures

These Apache-2.0 wire fixtures were generated directly between unmodified
pymodbus 3.11.4 endpoints. Generator code, immutable image/source identities,
dependency versions, BSD notice, and reproduction commands are in `../capture/`.
The fixtures contain lab-only values, no credentials or private device data.

| Scenario | Coverage |
| --- | --- |
| `operations` | FC1/2/3/4/5/6/15/16/22/23 requests/replies; units 1/2/3; asserted datastore readbacks; maximum legal quantities ending at 65535; overflowing address span; exceptions 2 and 11 (unknown unit 99). 50 events. |
| `diagnostics` | FC8 subfunctions 0–4, 10–20; normal requests/replies plus gateway exceptions for every subfunction using missing unit 99. 64 events. |
| `source502` | Both client and server port 502; opener sends FC3 address 65534, quantity 2; reply contains two registers. 2 events. |
| `pid-nonzero` | First `operations` request, PID changed to 1; decoded with `modbus.pid_nonzero`. |
| `bad-layout` | First request shortened to a frameable, incomplete FC1 quantity; `modbus.pdu_layout`, no authorized span. |
| `bad-length` | First request's MBAP length changed to 1; one malformed event / FrameError. |
| `truncation` | First request loses its final two bytes without changing MBAP length; incomplete at EOF, no fabricated event. |

`manifest.json` records provenance and exactly selected observation frames.
`SHA256SUMS` authenticates pcaps, independent tshark tables, expectation files,
mutation recipes, image identities and client/capture logs. `mutations.json`
records named parent hashes and exact original byte offsets. Negative pcaps
retain only the opening handshake and modified first request: they are
**mutations, not stack-generated positive traffic**.
`server.log` has trailing whitespace removed; the capture output directory
retains its original text. Oracle TSV quotes empty cells to preserve all columns.

## Independent oracle and limits

`*.expected.tsv` is tshark **4.6.7**, not decoder output. Export preferences:
`-2 -o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:TRUE
-o mbtcp.desegment:TRUE -o modbus.mbus_register_format:UINT16`.
Rows select `tcp.len > 0`, including malformed or incomplete content without
Modbus fields. Empty observations remain empty, not zero or copied requests.

With both ports 502, tshark observes MBAP and function code but does not
classify the body. `source502.expectations.json` explicitly labels its
additional endpoint-scenario assertions as supplemental, not oracle fields.
The Manager must still infer orientation from the captured SYN.

The real pymodbus TCP server returns a short normal FC8/sub4 response even
though the serial-line profile specifies no normal reply. This is retained
unchanged and expected to carry `modbus.pdu_layout`. pymodbus also implements
sub19, reserved in that profile; its requests/replies carry
`modbus.diagnostics_subfunction` as undecoded. Neither is claimed to certify
serial-device behavior. Exceptions carry no subfunction; no request identity
or diagnostic write category is invented for them.

Linux endpoint TCP checksum offload leaves partial pseudo-header checksums
in server-eth0 captures; original bytes are retained. Capture logs report zero
kernel drops. Mutation frames have recalculated full checksums; their retained
handshakes still reflect endpoint offload.

Tests replay every scenario through a fresh Manager in raw-sequence and
anchored-session-offset modes, then split, coalesce, reorder and retransmit
inputs. They compare ordered directional semantics, oracle fields, address
spans, findings and partial EOF behavior. The pcaps also seed parser/stream
fuzzing. These checks demonstrate decoder conformance for this inventory,
not universal device interoperability or live firewall prevention.
