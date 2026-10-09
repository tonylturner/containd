# IEC 60870-5-104 Linux truth harness (milestone B §10.2)

Proves, on Docker Desktop's Linux VM (or any Linux Docker host), what the
containd firewall does to real IEC 104 traffic: first-command prevention,
two-sided reset and reconnect, monitoring both ways, and US-unaffected
behaviour. The plant's own state is the evidence, never a client timeout.

| Path | What | Licence |
|---|---|---|
| `compose.yml` | lib60870 RTU and control centre on two disposable networks, the branch-built containd firewall routing between them, management published to 127.0.0.1 only, no host networking | Apache-2.0 |
| `endpoint/` | `iec104ep` (RTU, control centre, one-shot command client) on lib60870-C v2.4.1, built only into the harness image | **GPLv3** |
| `malformer/` | pure-Go client for split, coalesced, malformed, unsupported and same-5-tuple cases; never links lib60870 | Apache-2.0 |
| `capture/` | regenerates the reference pcaps in `testdata/` | Apache-2.0 |
| `testdata/` | lib60870 wire captures, Wireshark expected-decode tables, provenance | Apache-2.0 test data |
| `preflight/` | checkpoint-1 NFQUEUE and raw-RST kernel harness (`scripts/preflight-iec104.sh`) | Apache-2.0 |

## GPL boundary (spec D3)

lib60870-C is GPLv3-or-commercial, so `endpoint/iec104ep.c` is a GPLv3
combined work. It is compiled only inside `endpoint/Dockerfile`, whose image
ships the pinned lib60870 tarball and `iec104ep.c` under `/usr/share/src` and
the GPLv3 text under `/usr/share/licenses/iec104`. containd's Go code never
imports, links or copies it; the endpoints talk to containd over TCP/2404
only. Do not publish that image as a containd artefact.

## Run

```sh
bash scripts/smoke-iec104.sh
```

The script builds the branch firewall image (`build/Dockerfile.mgmt`) and the
endpoint image if they are absent, brings the stack up under a unique compose
project, routes both endpoints through the firewall, applies an L4 baseline
and then the §12.4 EU policy, runs every §10.2 assertion, writes
`build/iec104-smoke/results.json`, and tears down everything it created.

| Variable | Default | Use |
|---|---|---|
| `IEC104_FIREWALL_IMAGE` | `containd/containd:iec104-smoke` | firewall image under test |
| `IEC104_ENDPOINT_IMAGE` | `containd-iec104-endpoint:iec104-smoke` | lib60870 endpoint image |
| `IEC104_PROJECT` | `iec104-smoke-<time>-<pid>` | compose project |
| `IEC104_CC_SUBNET`, `IEC104_RTU_SUBNET` | `10.233.0`, `10.234.0` | first three octets of the two /24s, for a parallel run |
| `IEC104_FRESHNESS_SECONDS` | `660` | telemetry freshness window (spec: > 10 minutes) |
| `IEC104_HOLD` | `5s` | how long a malformed-case client waits for a reset |
| `IEC104_REUSE_PORT` | `40404` | fixed client port for the same-5-tuple case |
| `IEC104_RESULTS_DIR` | `build/iec104-smoke` | results location |

Statuses: `PASS`; `FAIL` (baseline or harness defect, independent of IEC
enforcement); `GATE-FAIL` (needs the integrated L1-L4 engine);
`NOT-IMPLEMENTED` (kept only for the freshness window when it is shortened
below ten minutes). Exit 0 is acceptance (everything passed); 1 is a `FAIL`
or a setup error; 3 means the baseline passed but gate assertions remain.
Passing with skips is not acceptance (B6).

Two assertions use extra tooling. The stale-retransmit case (`malformer
-scenario stale-retransmit`) opens a raw-socket TCP session (ports 40405 and
40406), sends a forbidden command, re-handshakes from the second port, then
injects a later segment of the first session carrying a forbidden command to
IOA 2003; it suppresses the container's own RST with an `iptables` OUTPUT
rule so the raw handshake completes. The queue-bind case builds
`test/iec104/queueholder`, which binds NFQUEUE 101 before the engine does, so
the engine's bind fails and (per E3/K6) enforcement must keep the config,
fail closed and report unhealthy.

## Endpoint points and state

The RTU point map is in `testdata/README.md`. The policy allows only the
type 46 double command at CA 1 / IOA 2001. The RTU also actuates CA 1 /
IOA 2002 and CA 2 / IOA 2001, so a forbidden command that gets through
really changes the plant. The RTU writes `/state/rtu.json` after every
change:

| Key | Meaning |
|---|---|
| `breaker_position`, `breaker_state` | CA 1 / IOA 1001 (2 / `closed`, 1 / `open`) |
| `writes_applied` | executes that actuated any command point |
| `commands_received` | every non-GI ASDU the RTU decoded, whatever it answered |
| `gi_requests` | interrogation commands decoded |
| `connections_opened`, `connections_closed` | server-side TCP session events |
| `last_actuated`, `last_command` | the most recent actuation and decoded command |

A prevention assertion passes only if `commands_received` (or `gi_requests`)
does not move: the RTU never decoded the forbidden bytes. The reset assertion
needs both sockets: the client reads `ECONNRESET` and the RTU records a closed
session while the client is still holding its socket.

The cyclic task sends feeder current as spontaneous data (COT 3) every 2 s
and busbar voltage as cyclic data (COT 1) every 10 s; `PERIODIC_MS=0`
disables both. The control-centre client honours `IEC104_T3`.

## Phase 1 result (2026-10-09, before L1-L4 merge)

Full run against `iec104` with only the contract commit (default 660 s
freshness window): exit 3, 13 passed, 0 failed, 21 gate-failed, 2 not
implemented. The baseline passes: routing through the firewall, NFQUEUE
group 101 bound, CAP_NET_RAW, GI and command confirmations both ways, the
allowed command actuates, no `block_flows` entry, a GI on a reused 5-tuple,
and 365 spontaneous updates over 11 minutes on an unbroken session. Every
enforcement assertion gate-fails because forbidden, split and coalesced
commands reach and actuate the RTU and nothing resets a session. Not
implemented: a stale retransmit after a new handshake (needs a raw old-ISN
replay tool) and a queue-bind failure at start (needs a second binder on
group 101).
