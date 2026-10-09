# Smoke-Test Data Directory

This directory is mounted as `/data` inside the smoke-test container
(see `deploy/docker-compose.smoke.yml`).

All fixture files (keys, certificates, databases) are **generated at
runtime** by the containd binary itself:

- `ssh/host_key` -- auto-generated Ed25519 key on first SSH listen
- `tls/server.crt`, `tls/server.key` -- auto-generated ECDSA P-256
  self-signed certificate on first HTTPS listen
- `*.db` -- SQLite databases created with `CREATE TABLE IF NOT EXISTS`

If you want to pre-populate the directory before starting the container,
run the helper script:

```sh
./generate.sh
```

**Do not commit private keys or database files to the repository.**

## Running the smoke scripts beside another smoke stack

`scripts/smoke-forward.sh` and `scripts/smoke-dpi.sh` default to compose
project `deploy`, subnets `172.30.0.0/24` (wan) and `172.31.0.0/24` (lan),
host ports 18080/18081 and the shared `containd/containd:dev` image. Two
runs on one Docker host collide on all four. For an isolated run, write an
override that moves them and point the scripts at it:

| Variable | Meaning |
|---|---|
| `SMOKE_PROJECT` | compose project name (default `deploy`) |
| `COMPOSE_FILE` | colon-separated compose files, base first (as in `docker compose`) |
| `SMOKE_WAN_NET`, `SMOKE_LAN_NET` | first three octets of the moved subnets |
| `BASE`, `ENGINE` | management and engine URLs for the moved host ports |
| `SMOKE_SKIP_UP=1` | use a stack you brought up yourself (to read random ports) |

The override replaces the engine image, networks, addresses, ports and the
`/data` bind with `!override` (Docker Compose 2.24 or later), for example
`image: containd/containd:<run-tag>`, `ports: !override ["127.0.0.1::8081",
"127.0.0.1::18080"]`, one `ipv4_address` per service in the new subnets,
and `networks.<name>.ipam: !override` with the new subnet. Bring the stack
up with `docker compose -p "$SMOKE_PROJECT" -f deploy/docker-compose.smoke.yml
-f <override> up -d`, read the ports with `docker compose ... port engine
18080` and `port engine 8081`, run the script with `SMOKE_SKIP_UP=1`, then
`down --volumes` the project you created.

## ICS fixtures and the NFQUEUE variant

`modbus/server.py` appends every decoded request to
`/tmp/modbus-requests.jsonl` and rewrites its register image to
`/tmp/modbus-state.json` (`{"writes": N, "registers": [...]}`) inside the
`modbus_server` container. `modbus/client.py` modes: `read`, `write`,
`readwrite` (a read, then a write on one connection), `read-split` (one read
whose MBAP header and PDU go out as two TCP segments), `read-coalesced` (two
reads in one segment) and `diag` (FC 8), with `--source IP` and `--value N`.
Exit 3 means the connection was established but the write or diagnostics
request got no response.

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
