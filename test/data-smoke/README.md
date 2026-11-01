# Smoke-Test Data Directory

This directory is mounted as `/data` inside the smoke-test container
(see `deploy/docker-compose.smoke.yml`).

Runtime keys, certificates and databases are **generated at runtime** by the
containd binary itself. The tracked protocol and HTTP fixture programs in this
directory are separate test inputs.

- `ssh/host_key` -- auto-generated Ed25519 key on first SSH listen
- `tls/server.crt`, `tls/server.key` -- auto-generated ECDSA P-256
  self-signed certificate on first HTTPS listen
- `*.db` -- SQLite databases created with `CREATE TABLE IF NOT EXISTS`

To pre-populate the keys, certificate and service directories before starting
the container, run the helper script. It does not create databases:

```sh
bash test/data-smoke/generate.sh
```

**Do not commit private keys or database files to the repository.**

## Running the smoke scripts beside another smoke stack

`scripts/smoke-forward.sh` and `scripts/smoke-dpi.sh` default to compose
project `deploy`, subnets `172.30.0.0/24` (wan) and `172.31.0.0/24` (lan),
host ports 18080 (HTTP), 18443 (HTTPS) and 12222 (SSH),
the shared `test/data-smoke` data directory, and the
`containd/containd:dev` image. Two runs on one Docker host can collide on
these resources. For an isolated run, write an
override that moves them and point the scripts at it:

| Variable | Meaning |
|---|---|
| `SMOKE_PROJECT` | compose project name (default `deploy`) |
| `COMPOSE_FILE` | colon-separated compose files, base first (as in `docker compose`) |
| `SMOKE_WAN_NET`, `SMOKE_LAN_NET` | first three octets of the moved subnets |
| `BASE` | management URL for the moved host port |
| `TOKEN` | management bearer token (default `devtoken`) |
| `SMOKE_SKIP_UP=1` | use a stack you brought up yourself (to read random ports); without it, `smoke-dpi.sh` recreates the containers, because a reused stack keeps the earlier run's dynamic blocks |

The override replaces the engine image, networks, addresses, ports and the
`/data` bind with `!override` ([Docker Compose 2.24.4 or later](https://github.com/compose-spec/compose-spec/blob/main/13-merge.md#replace-value)), for example
`image: containd/containd:<run-tag>`, `ports: !override ["127.0.0.1::18080"]`,
one `ipv4_address` per service in the new subnets,
and `networks.<name>.ipam: !override` with the new subnet. Replace the
**entire** ports list (the example publishes only HTTP) and set a
non-empty `CONTAIND_JWT_SECRET` in the override's engine environment, for
example a value generated with `openssl rand -hex 32`. With that secret set,
lab mode accepts only bearer tokens signed with it, so set `TOKEN` to an
HS256 JWT signed with the secret and carrying a future `exp`. Use a separate
data directory for the `/data` bind. Bring the stack
up with `docker compose -p "$SMOKE_PROJECT" -f deploy/docker-compose.smoke.yml
-f <override> up -d`, read the port with `docker compose ... port engine
18080`, run the script with `SMOKE_SKIP_UP=1`, then `down --volumes` the
project you created.

The scripts never reach the engine API through a published port. While
enforcing, the engine admits its unauthenticated API only from loopback, so
the scripts call it inside the `engine` container with `docker compose exec`
(`scripts/smoke-engine-api.sh`).

## Forwarding fixtures

`forward/echo.py NAME PORT...` serves HTTP on each port and answers every
request with one line, for example
`server=wan_server port=8080 client=172.30.0.2`, naming the listener, the
accepting port and the client address it observed. `wan_server` listens on
8080 and 8082, `lan_target` on 80 and 22, so every flow the forwarding smoke
expects to be denied has a live listener behind it. `forward/probe.py IP PORT
TIMEOUT` makes one TCP connection and prints its outcome: `open <reply
line>`, `timeout`, `refused` or `unreachable`. It exits 2 when it cannot
probe at all, so a broken probe is never read as a drop. The compose file
mounts the directory at `/opt/forward` in `lan_client`, `lan_target` and
`wan_server`.

The forwarding smoke saves a default-deny base policy, publishes `lan-http`
through `/api/v1/firewall/port-forwards` with `allowRule: true`, and commits
through management. It checks the generated rule's `viaForwards`, DNAT
delivery and counters, and return-path masquerade. It also publishes a second
forward without permission (translation counter increases but the probe times
out), moves a covering DENY from bottom to top and back (delivery changes
with first-match order), verifies that via-rule history preview reports
`unavailable`, and deletes the forward and its generated rule. Each policy
change is committed before a fresh connection probes the engine. If the
packaged CLI is reachable, `show firewall rules` must print order numbers and
the via forward; otherwise the script logs a skip reason.

`scripts/smoke-forward.sh` also reads `DNAT_PORT` (default 8088),
`NO_ALLOW_PORT` (a different listen port, default 8089),
`SMOKE_PROBE_TIMEOUT` (seconds a probe waits for a connection, default 3),
`SMOKE_MUTATION` (`permissive` or
`no-masquerade`, used by `scripts/smoke-forward-mutations.sh`) and
`SMOKE_RESULT_FILE` (a file that receives the IDs of failed checks, one per
line). The log contains every executed check's named PASS/FAIL result.
Unexpected check failures stop the run; expected mutation failures continue
so the mutation driver can compare the complete set. The permissive mutation
must fail the four direct deny checks and `dnat-no-allow`; disabling LAN
masquerade must fail only `lan-wan-snat`.

## Scanning-gate fixtures

`av/server.py NAME PORT...` is the HTTP origin of the scanning-gate smoke
(`scripts/smoke-av-gate.sh`). It answers `GET /` with the same
`server=NAME port=PORT client=IP` line as the forwarding echo listener,
`GET /clean.txt` with that line followed by clean filler, `GET /eicar.txt`
with the 68-byte EICAR test file and `POST /upload` with the line extended
by `method=POST size=N md5=HEX`. It appends every request to
`/tmp/av-requests.jsonl` in its container (client address, method, path,
port, body size and MD5), which the smoke reads to see which address
reached the origin and whether a refused upload ever arrived. `av/eicar.py`
assembles the EICAR string at runtime from pieces, so no file in the
repository carries it. `av/client.py get IP PORT PATH TIMEOUT` and
`av/client.py post IP PORT PATH TIMEOUT eicar|clean` make one HTTP/1.1
request and print one outcome line: `status=CODE bytes=N complete=yes|no
eicar=yes|no line=<first body line>` (the line of an EICAR body is printed
as `(eicar)`), or `timeout`, `refused`, `reset`, `closed` or `unreachable`.
Exit 2 means the client could not run, which the smoke treats as a harness
error. The compose file runs `av_server` (WAN side, ports 8080 and 8082)
and `av_target` (LAN side, port 80) from this directory and mounts it at
`/opt/av` in `lan_client` as well.

`scripts/smoke-av-gate.sh` reads the isolation variables above,
`SMOKE_PROBE_TIMEOUT` (default 10), `SMOKE_AV_READY_TIMEOUT` (seconds to
wait for the gate to reach the state a policy implies, default 180),
`SMOKE_MUTATION=no-gate` (commits every policy with an empty scan selection,
which must fail the refusal checks) and `SMOKE_RESULT_FILE`.

## ICS fixtures and the NFQUEUE variant

`modbus/server.py` appends every decoded request (with its MBAP
`protocol_id`) to `/tmp/modbus-requests.jsonl` and rewrites its register
image to `/tmp/modbus-state.json` (`{"writes": N, "registers": [...]}`)
inside the `modbus_server` container. It answers a request whose protocol
identifier is not 0 like any other, so a test can prove whether the firewall
delivered it. `modbus/client.py` modes: `read`, `write`, `readwrite` (a read,
then a write on one connection), `persistent` (read, write, read on one
connection, stopping at the first failed exchange), `read-split` (one read whose
MBAP header and PDU go out as two TCP segments), `read-coalesced` (two reads in one segment),
`diag` (FC 8), `pid-nonzero` (two reads with protocol identifier 1 on one
connection) and `bad-length` (one MBAP header whose length field is 1,
outside 2..254), with `--source IP` and `--value N`. Exit 3 means the connection was
established but the write, diagnostics, nonzero-PID or bad-length request got
no response; stderr names the cause.

Both capture variants end with the ICS parsing checks
(`scripts/smoke-dpi-lib-parsing.sh`): tolerant parsing, the default, delivers
the `pid-nonzero` reads with one `ics-conformance` alert per connection;
`dataplane.dpiIcsParsing.modbus = "strict"`, pushed through the API, drops
the read and resets the session when inline (`would_drop` in monitor mode); a
`bad-length` read resets in both modes when inline. The checks read the
connection's events by client port, which both modes print first.

`dnp3/dnp3.py` is a minimal DNP3-over-TCP outstation (`server`, port 20000)
and master (`read`, `operate` = FC 5, `operate-nr` = FC 6). The outstation
answers a read with FC 129 and then one FC 130 unsolicited response per
connection, logs every request to `/tmp/dnp3-requests.jsonl` and keeps
`/tmp/dnp3-state.json` (`{"operations": N, "requests": N}`). The compose file
does not mount it; `scripts/smoke-dpi.sh` copies it into the `ot_client` and
`modbus_server` containers with `docker compose cp` and starts the
outstation itself.

`SMOKE_DPI_CAPTURE=nfqueue bash scripts/smoke-dpi.sh` runs the inline
variant (`nfqueueGroup` 101). It adds client addresses `.6`-`.10` on the
`ot_client` container and asserts, from the servers' state files, that the
first Modbus FC 6 write (fresh connection and after a read), the first
Modbus FC 8, and the first complete DNP3 FC 5 and FC 6 never reach the
server. Each probe has its own source address, so the 10-minute dynamic
block from an earlier deny cannot stand in for the inline drop.

The default `afpacket` variant has no inline path. It asserts that saving the
ICS rules in enforce mode is refused, then runs the traffic in monitor mode,
where denied writes reach the server and no dynamic block is installed. Both
variants check the ICS coverage that `/dataplane/ruleset` and `/health` report.
